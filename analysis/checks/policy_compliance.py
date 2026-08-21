"""
Netwise -- policy-compliance check (Shubham's feature).

WHAT THIS CHECK DOES
    It asserts our written security policy against the real config. The policy
    is a list of rules -- "this traffic must be blocked", "this traffic must be
    allowed" -- and each rule is proved or disproved by Batfish.

    The rules, and the reasoning behind every one of them, live in
    docs/policy-rules.md. That document is the source of truth; POLICY_RULES
    below is the same list in code. Change one, change the other.

WHY searchFilters AND NOT reachability
    The obvious question to ask is "can this traffic get through?", which is
    what reachability answers. On our fixtures that question lies.

    rtr-us5 has one interface and no route to 10.20.0.5, so reachability
    reports zero successful flows -- for a ROUTING reason, not a policy one.
    Measured against the INSECURE fixture (the one containing `permit ip any
    any`), reachability(actions="success") returns nothing at all, and
    actions="failure" shows why: NO_ROUTE(Discarded). A check that read "empty
    means the policy holds" would put a green tick on the config that permits
    everything. That is precisely the failure F-4 exists to prevent.

    searchFilters reasons about the FILTER, not the path, so it needs no
    routing and cannot be fooled this way.

HOW A RULE BECOMES A QUERY
    Rules come in two directions, and the direction picks the question:

      prohibition ("must be blocked")  -> searchFilters(action="permit", ...)
                                          a returned flow = something forbidden
                                          is allowed
      requirement ("must be allowed")  -> searchFilters(action="deny", ...)
                                          a returned flow = something required
                                          is blocked

    Either way an EMPTY answer means the rule holds. That is a strong claim:
    searchFilters searches a whole SPACE of flows, so empty means "no packet
    anywhere in this space behaves that way" -- a proof, not a spot check.

WHY AN EMPTY ANSWER IS SAFE TO TRUST
    Empty only means "the rule holds" if it cannot also mean "we asked the
    wrong question". It cannot: a wrong node or filter name makes Batfish raise
    BatfishException rather than return an empty frame (measured). So this
    module never swallows an exception -- a failed query becomes status="error",
    never a quiet pass.

FINDING IDS (agreed -- see docs/policy-rules.md §4)
    policy_compliance owns the PC- prefix outright. It shared it with
    change_impact until amendment A-2 (docs/finding-format.md), which gave
    change_impact its own CH- prefix -- so the two checks can no longer collide
    with each other at all. The banding below is about keeping THIS check's own
    findings apart.

    IDs are pinned to RULES, not to the order violations happen to be found:
    POL-1 is always PC-001, POL-2 always PC-002. So a given id means the same
    thing on every run, which is what will let the dashboard show what changed
    since the previous upload. A retired rule's number is never reused.

    ONE RULE CAN PRODUCE TWO FINDINGS, so it needs two numbers. A rule with
    several query arms can have one arm prove a violation while another fails
    to run -- both facts are true and both are reported (see PARTIAL CHECKS).
    They cannot share an id: `duplicate_id_findings()` in the pipeline would
    correctly flag that as a broken contract. So each rule owns two slots:

        violation   -> PC-00n              (n = rule number)
        check error -> PC-0(n + 50)        ERROR_NUMBER_OFFSET

    POL-2 violated and partly unchecked therefore gives PC-002 and PC-052.
    The offset caps the policy at 49 rules, which is far more than we have.

PARTIAL CHECKS -- why a rule reports a violation AND an error (issue #22)
    The first version wrapped a rule's whole query loop in one try, so if arm A
    proved a violation and arm B then raised, the proven violation was thrown
    away and the user saw only "could not check".

    That is the wrong trade for a security tool. A PROVEN finding outranks the
    fact that a second query failed, and replacing it with "we don't know"
    reads as LESS alarming than the truth -- the same class of mistake as
    confusing `none` with `error`. Each arm is now isolated, so what was proved
    is reported as proved, and what could not be reached is reported separately.
"""

from typing import Any, Dict, List, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings, policy, snapshot

# The name this check is registered under, and the value in every "check" field.
CHECK_NAME = "policy_compliance"

# Which searchFilters action proves which kind of rule. See the module docstring.
ACTION_BY_KIND = {
    "prohibition": "permit",  # find forbidden traffic that IS allowed
    "requirement": "deny",  # find required traffic that IS blocked
}

# A rule that both proves a violation and fails to run one of its query arms
# emits TWO findings, which need two ids. Errors sit in their own band, offset
# from the rule number: POL-2 -> PC-002 for the violation, PC-052 for the error.
# See the FINDING IDS section of the module docstring.
ERROR_NUMBER_OFFSET = 50

# The id for the ONE card reporting rules that do not apply to this snapshot.
#
# access_control numbers its findings sequentially, so it can just take the next
# number. Ours are pinned to rules, so a check-level card needs a slot of its
# own. 50 is that slot, and it is not arbitrary: it is SENTINEL_NUMBER + the
# offset, mirroring PC-000. PC-000 is "the whole check found nothing"; PC-050 is
# "the whole check could not apply". Rules are numbered from 1, so nothing else
# can ever land here.
SKIPPED_NUMBER = ERROR_NUMBER_OFFSET

# --- The policy being asserted ----------------------------------------------
#
# Kept as plain data so the policy can be edited without reading the code below
# it. Every field is explained in docs/policy-rules.md, which also records why
# each rule exists and why it carries the severity it does.
#
# "number" is the pinned rule number: POL-n -> PC-00n. Never reuse one.
# "queries" is a LIST because a rule can need more than one query to express its
# full space -- see POL-2. The rule holds only if every query comes back empty.
POLICY_RULES: List[Dict[str, Any]] = [
    {
        "number": 1,  # POL-1 -> PC-001
        "description": "The LAN may reach only the two approved servers",
        "kind": "prohibition",
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "high",
        "violation_summary": "The internal network can reach servers it should not",
        "queries": [
            {
                "srcIps": "10.10.10.0/24",
                # "\ " is Batfish's set-difference operator: everything except
                # the two approved servers.
                "dstIps": "0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)",
            },
        ],
    },
    {
        "number": 2,  # POL-2 -> PC-002
        "description": "The internal server is reachable only over HTTPS",
        "kind": "prohibition",
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "high",
        "violation_summary": "The internal server accepts traffic other than HTTPS",
        # TWO queries, because "everything except TCP/443" cannot be written as
        # one headerspace. Do NOT try to collapse this using invertSearch: that
        # flag inverts the WHOLE headerspace including dstIps, so the search
        # escapes to other destinations and reports the legitimate DNS traffic
        # on the CLEAN fixture as a violation. Measured. See docs/policy-rules.md §2.
        "queries": [
            # Arm A -- any non-TCP protocol reaching the server (UDP, ICMP, ...)
            {
                "srcIps": "10.10.10.0/24",
                "dstIps": "10.20.0.5",
                "ipProtocols": ["!tcp"],
            },
            # Arm B -- TCP reaching the server on any port except 443
            {
                "srcIps": "10.10.10.0/24",
                "dstIps": "10.20.0.5",
                "ipProtocols": ["tcp"],
                "dstPorts": "0-442,444-65535",
            },
        ],
    },
    {
        "number": 3,  # POL-3 -> PC-003
        "description": "Only LAN addresses may enter the LAN interface",
        "kind": "prohibition",
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "medium",
        "violation_summary": "Traffic with a forged source address is permitted",
        "queries": [
            {"srcIps": "0.0.0.0/0 \\ 10.10.10.0/24"},
        ],
    },
    {
        "number": 4,  # POL-4 -> PC-004
        "description": "DNS to the approved resolver must work",
        "kind": "requirement",
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "medium",
        "violation_summary": "DNS to the approved resolver is blocked, so name lookups fail",
        "queries": [
            # UDP/53 written out rather than applications=["dns"]. Both behave
            # identically here (measured), but the explicit form cannot shift
            # meaning if Batfish's named-application list ever changes.
            {
                "srcIps": "10.10.10.0/24",
                "dstIps": "218.8.104.58",
                "ipProtocols": ["udp"],
                "dstPorts": "53",
            },
        ],
    },
    {
        "number": 5,  # POL-5 -> PC-005
        "description": "HTTPS to the internal server must work",
        "kind": "requirement",
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "medium",
        "violation_summary": "HTTPS to the internal server is blocked, so the service is unreachable",
        "queries": [
            {
                "srcIps": "10.10.10.0/24",
                "dstIps": "10.20.0.5",
                "ipProtocols": ["tcp"],
                "dstPorts": "443",
            },
        ],
    },
]


def _search(
    bf: Session, node: str, filter_name: str, action: str, headers: Dict[str, Any]
) -> List[Any]:
    """Run ONE searchFilters query and return the rows it matched.

    An empty list means nothing in that headerspace behaves the way we searched
    for. Exceptions are deliberately NOT caught here -- run() turns them into a
    status="error" finding, because a query we could not ask is a blind spot,
    not a pass.
    """
    frame = (
        bf.q.searchFilters(
            nodes=node,
            filters=filter_name,
            action=action,
            headers=HeaderConstraints(**headers),
        )
        .answer()
        .frame()
    )
    return [frame.iloc[i] for i in range(len(frame))]


def _describe(rule: Dict[str, Any], hits: List[Any]) -> str:
    """Turn matched rows into the evidence string, in Batfish's own words.

    We quote the flow and the ACL line verbatim and do not paraphrase them --
    the AI layer rephrases this text later, and it can only stay grounded if
    what it receives is the real Batfish result.
    """
    first = hits[0]
    if rule["kind"] == "prohibition":
        wrong = "is permitted but policy forbids it"
    else:
        wrong = "is denied but policy requires it"

    detail = (
        f"Flow {first['Flow']} {wrong}. "
        f"Decided by: {first['Line_Content']}"
    )
    if len(hits) > 1:
        detail += f" ({len(hits)} example flows matched)"
    return detail


def _with_provenance(detail: str, policy_label: str) -> str:
    """Append which policy these rules came from.

    WHY EVERY FINDING CARRIES THIS (#87)
        A finding produced from the USER's policy and one produced from our
        built-in example look identical on screen. That is the whole of #87
        in one sentence: the user believes their rules are enforced when
        ours are. Making the origin part of the evidence means it survives
        into the dashboard and into the AI explanation, because both read
        `evidence.detail`.

    WHY IT IS APPENDED RATHER THAN PREPENDED
        `ai/explain.py::_compute_policy_outcome` (#145) matches
        `_describe()`'s wording with a deliberately narrow regex ending at
        "Decided by:". Appending leaves that match intact; prepending would
        too, but appending also keeps the Batfish quote first, which is the
        part the reader needs and the part the model must not paraphrase.
        Verified against all five policy findings across every fixture
        rather than reasoned about.
    """
    return f"{detail} [Rules checked: {policy_label}.]"


#: Where the rules being checked came from. Attached to the evidence of every
#: finding this check produces, because a finding from the USER's policy and
#: one from our built-in example look identical on screen otherwise -- and a
#: user believing their rules are enforced when ours are is the whole of #87.
BUILTIN_POLICY_LABEL = (
    "Netwise's built-in example policy (analysis/checks/policy_compliance.py) "
    "-- no policy file was supplied"
)
USER_POLICY_LABEL = "the policy file you supplied"


def rules_in_use() -> Tuple[List[Dict[str, Any]], str, bool]:
    """The rules this run should check, where they came from, and whether
    the user supplied them.

    WHY THIS EXISTS (#87)
        `analysis/policy.py` was written, validated, tested and merged in
        #173 -- and read by nothing. Measured before this change: no module
        under analysis/checks/, analysis/pipeline.py, web/ or ai/ imported
        it. This is the function that connects it, for one check, as a
        vertical slice.

    THE THREE STATES, WHICH ARE NOT TWO
        no policy supplied      -> our built-in rules, LABELLED as ours
        policy with entries     -> the user's rules
        policy with NO entries  -> the user's (empty) policy, NOT ours

        The third is the one worth getting right. An empty policy is a valid,
        deliberate state (D4) and means "I assert nothing", which is a
        different claim from "I did not give you a policy". Falling back to
        our rules there would enforce assertions the user explicitly chose
        not to make, and label them as theirs by omission.

        So the fallback is keyed on `active_policy() is None`, never on
        whether the entry list is empty.
    """
    active = policy.active_policy()
    if active is None:
        return POLICY_RULES, BUILTIN_POLICY_LABEL, False
    return active.entries_for(CHECK_NAME), USER_POLICY_LABEL, True


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every policy rule and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only asks questions and shapes the answers.

    Since #87's vertical slice, the RULES may come from a policy file the user
    supplied rather than from POLICY_RULES below -- see rules_in_use(). Every
    finding says which, in its evidence.
    """
    results: List[Dict[str, Any]] = []
    rules, policy_label, user_supplied = rules_in_use()

    # An empty policy is valid and must be LOUD (D4, @shubhamkataria2005 on
    # #159). Returning [] here would be read by the pipeline as the check
    # being broken -- it emits `PC-000 status=error "the policy compliance
    # check returned no findings"`, which is the wrong status AND the wrong
    # message for a check that ran perfectly and had nothing to assert.
    if user_supplied and not rules:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="n/a",
                summary="No policy compliance rules to check",
                detail=(
                    "Your policy file has no policy_compliance entries, so "
                    "nothing was asserted about this configuration and nothing "
                    "was checked. This is not a problem with the config -- it "
                    "means no rules were written for this check."
                ),
                source=policy_label,
            )
        ]

    # Which rules can this snapshot actually answer?
    #
    # Every rule names a device. On a snapshot that does not contain it, each
    # rule reported "could not check" -- correct under F-4, and unusable in
    # volume: measured at 5 of 5 findings on the routing-secure fixture. Report
    # it ONCE instead, using the helper access_control established in #45.
    #
    # Unlike access_control, this check has NO analysis that works without a
    # policy, so when nothing applies there is nothing else to run.
    present = snapshot.device_names(bf)

    if present is None:
        # We could not find out what is in this snapshot. Note what this does
        # NOT say: it does not claim the devices are absent, because we have not
        # observed that. Claiming it would send a reader hunting for a missing
        # device when the real fault was a broken Batfish query.
        return [
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary=(
                    f"{len(rules)} policy rule(s) could not be checked "
                    "against this config"
                ),
                detail=_with_provenance(
                    "The devices present in this snapshot could not be "
                    "determined, so we cannot tell whether these rules apply to "
                    "it. Nothing is claimed about them either way.",
                    policy_label,
                ),
                source="analysis/checks/policy_compliance.py",
                number=SKIPPED_NUMBER,
            )
        ]

    applicable = [r for r in rules if r["node"] in present]
    absent = sorted({r["node"] for r in rules if r["node"] not in present})
    if absent:
        results.append(
            findings.error_finding(
                check=CHECK_NAME,
                # Safe here in a way it is not above: we know what is present,
                # so naming what is missing is an observation, not a guess.
                device=absent[0] if len(absent) == 1 else "unknown",
                summary=(
                    f"{len(rules) - len(applicable)} policy rule(s) could "
                    "not be checked against this config"
                ),
                detail=_with_provenance(
                    "They are written about "
                    + ", ".join(absent)
                    + ", which "
                    + ("is" if len(absent) == 1 else "are")
                    + " not in this snapshot. Nothing is claimed about them "
                    "either way.",
                    policy_label,
                ),
                source="analysis/checks/policy_compliance.py",
                number=SKIPPED_NUMBER,
            )
        )

    for rule in applicable:
        node = rule["node"]
        filter_name = rule["filter"]
        action = ACTION_BY_KIND[rule["kind"]]

        # Each arm is isolated. The arms describe ONE space between them, so a
        # hit in any of them violates the rule -- but a failure in one must not
        # discard what another one proved. See issue #22 and the PARTIAL CHECKS
        # note in the module docstring.
        hits: List[Any] = []
        failures: List[Exception] = []
        for headers in rule["queries"]:
            try:
                hits.extend(_search(bf, node, filter_name, action, headers))
            except Exception as error:
                failures.append(error)

        if hits:
            results.append(
                findings.make_finding(
                    check=CHECK_NAME,
                    severity=rule["violation_severity"],
                    device=node,
                    summary=rule["violation_summary"],
                    detail=_with_provenance(_describe(rule, hits), policy_label),
                    # searchFilters names the matching LINE but not its line
                    # NUMBER, so device:filter is the most precise source it can
                    # give us. (definedStructures does return real file:line
                    # locations; using it would mean a second query per finding,
                    # and was left out to keep this readable.)
                    source=f"{node}:{filter_name}",
                    status="found",
                    number=rule["number"],
                )
            )

        if failures:
            # We could not ask one of the questions -- a renamed ACL, a missing
            # node, a malformed header. We are blind for that part of the rule,
            # so it is an error, NOT a pass, whether or not the arms that DID
            # run found anything.
            #
            # The wording distinguishes the two cases deliberately. "Partly
            # unchecked" alongside a violation is a different claim from "could
            # not check" on its own, and a user who reads only the summary
            # should not have to infer which one they are looking at.
            if hits:
                summary = f"Policy rule only partly checked: {rule['description'].lower()}"
            else:
                summary = f"Could not check policy rule: {rule['description'].lower()}"

            detail = _with_provenance(
            findings.describe_error(failures[0]), policy_label
        )
            if len(rule["queries"]) > 1:
                detail = (
                    f"{len(failures)} of {len(rule['queries'])} queries for this "
                    f"rule could not run. First failure: {detail}"
                )

            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=summary,
                    detail=detail,
                    source=f"{node}:{filter_name}",
                    # Its own id band, so a rule reporting BOTH findings cannot
                    # collide with itself. See ERROR_NUMBER_OFFSET.
                    number=rule["number"] + ERROR_NUMBER_OFFSET,
                )
            )

        # Neither hits nor failures means every arm ran and nothing in the
        # searched space behaves the forbidden way. The rule holds; report
        # nothing, and the all-clear below covers it.

    # Only claim "all clear" if every rule was actually checked and held. If any
    # rule errored, results is non-empty and the error is what the user sees.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=rules[0]["node"] if rules else "unknown",
                summary="No issues found by policy compliance",
                # `applicable`, not POLICY_RULES: only rules that actually ran
                # can be claimed to hold. They are the same list unless some
                # were skipped -- and if any were, the skip card above already
                # made `results` non-empty, so this branch is unreachable. Said
                # accurately anyway, because the day that stops being true this
                # sentence would quietly start overstating what we checked.
                detail=_with_provenance(
                    f"All {len(applicable)} policy rule(s) hold",
                    policy_label,
                ),
                source=", ".join(sorted({r["node"] for r in applicable})) or "unknown",
                # PC-000. Since A-2 (#102) change_impact has its own "CH-"
                # prefix, so there is no cross-check collision to avoid here
                # any more -- this is simply policy_compliance's own clean
                # sentinel.
                number=0,
            )
        ]

    return results
