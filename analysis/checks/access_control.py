"""
Netwise -- access-control check (Arsh's feature).

>>> THIS FILE IS THE TEMPLATE. Ankeet, Shubham, Samika: copy its shape. <<<

    A check is one Python file with one function:

        def run(bf: Session) -> list[dict]

    It receives a live Batfish session with the snapshot already loaded, and
    returns a list of findings built with analysis.findings. That is the whole
    contract. The pipeline handles connecting, loading, and catching your
    mistakes -- you only write the analysis.

WHAT THIS CHECK DOES -- four analyses, one check

    1. POLICY STATEMENTS (testFilters)
       "This exact packet must be allowed / blocked." Spot-checks one flow at a
       time and names the ACL line that decided.

    2. GUARANTEES (searchFilters)   <-- our strongest capability
       "NO packet in this whole space may be permitted." Searches an entire
       space of flows at once, so it PROVES a property instead of sampling it.

    3. DEAD RULES (filterLineReachability)
       Finds ACL lines that can never match because an earlier line shadows
       them. The config looks like it does something; it does nothing.

    4. UNDEFINED REFERENCES (undefinedReferences)
       Finds config pointing at an ACL or object group that was never defined.

    All four are access control, so they are ONE check -- `access_control` --
    producing `AC-` findings. They are not four registry entries: F-1 fixes the
    `check` vocabulary to five values, and adding to it needs all four of us.

HOW IT DECIDES WHAT TO REPORT
    Every analysis reports independently:
      - a real problem            -> status="found"
      - Batfish could not answer  -> status="error", we are blind here
      - nothing wrong anywhere    -> ONE status="none" for the whole check

    Each analysis is wrapped separately, so if filterLineReachability fails we
    still run undefinedReferences. A blind spot in one analysis must not
    silently shrink the others.

    And we only ever say "all clear" if every analysis actually completed. If a
    query failed, the honest answer is "we could not check" -- see F-4 in
    docs/finding-format.md.
"""

from itertools import count
from typing import Any, Dict, Iterator, List, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import policy as policy_module
from analysis import findings, snapshot

# The name this check is registered under, and the value that goes in every
# finding's "check" field.
CHECK_NAME = "access_control"

# --- 1. Policy statements: single flows that must be allowed or blocked -----
#
# OUR EXAMPLE STATEMENTS, USED ONLY WHEN THE USER SUPPLIED NO POLICY (#316).
# They describe the rtr-us5 test fixture. Since #316 a user's own statements
# replace them -- see rules_in_use() below, and note that the fallback is
# keyed on whether a policy was supplied, never on whether it is empty.
#
# This list stopped being a PLACEHOLDER and became a documented default. The
# distinction matters: a placeholder is waiting to be replaced by us, a
# default is what runs when the user chose not to decide.
POLICY: List[Dict[str, Any]] = [
    {
        "description": "DNS lookups to the approved DNS server must be allowed",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {
            "srcIps": "10.10.10.0/24",
            "dstIps": "218.8.104.58",
            "applications": ["dns"],
        },
        "expected": "PERMIT",
        "violation_summary": "DNS to the approved server is blocked, so name lookups will fail",
        "violation_severity": "medium",
    },
    {
        "description": "Plain HTTP to the internal server must be blocked",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {
            "srcIps": "10.10.10.0/24",
            "dstIps": "10.20.0.5",
            "applications": ["http"],
        },
        "expected": "DENY",
        "violation_summary": "Unencrypted web traffic reaches the internal server",
        "violation_severity": "high",
    },
]

# --- 2. Guarantees: whole SPACES of traffic that must never be permitted ----
#
# The difference from POLICY above is the difference between testing and
# proving. A policy statement checks one packet. A guarantee checks every
# packet that fits the description -- every source address in the subnet,
# every source port, all at once. If Batfish returns nothing, no such packet
# exists. That is a proof, not a sample.
GUARANTEES: List[Dict[str, Any]] = [
    {
        "description": "No unencrypted web traffic may be permitted out of the internal subnet",
        "node": "rtr-us5",
        "filter": "acl_in",
        # Deliberately broad: ANY source in the subnet, ANY destination.
        "headers": {"srcIps": "10.10.10.0/24", "applications": ["http"]},
        "violation_summary": "Unencrypted web traffic is allowed out of the internal subnet",
        "violation_severity": "high",
    },
]


# --- Whose statements are we checking? (#87 / #316) -------------------------

BUILTIN_POLICY_LABEL = (
    "Netwise's built-in example policy (analysis/checks/access_control.py) "
    "-- no policy file was supplied"
)
USER_POLICY_LABEL = "the policy file you supplied"


def statements_in_use() -> Tuple[List[Dict[str, Any]], str, bool]:
    """The policy statements this run should check, and where they came from.

    WHY THIS EXISTS (#87)
        `analysis/policy.py` has validated an `access_control` section since
        #173 and no check has ever read it. Measured before this change with
        `python -m tools.stranger_config`: rename the device in a config and
        detection falls from 12 findings to 3, because every statement here
        names `rtr-us5`.

    THE THREE STATES, WHICH ARE NOT TWO
        no policy supplied      -> POLICY below, LABELLED as ours
        policy with entries     -> the user's statements
        policy with NO entries  -> the user's (empty) policy, NOT ours

        Keyed on `active_policy() is None`, exactly as policy_compliance
        does, and never on emptiness. An empty policy is a valid, deliberate
        state meaning "I assert nothing", which is a different claim from
        "I did not give you a policy". Falling back to ours there would
        enforce assertions the user explicitly declined to make, and label
        them as theirs by omission.

    WHAT THIS DOES NOT COVER
        GUARANTEES are unaffected and remain ours. The policy format has no
        way to express a whole flow space, so a user cannot yet state one.
        Their guarantees therefore still report "could not check" on a
        snapshot without our devices -- honest, and not yet useful. Widening
        the schema is a separate change needing the team, not something to
        invent here.
    """
    active = policy_module.active_policy()
    if active is None:
        return POLICY, BUILTIN_POLICY_LABEL, False
    return active.entries_for(CHECK_NAME), USER_POLICY_LABEL, True


def _with_provenance(detail: str, policy_label: str) -> str:
    """Say whose statements produced this finding.

    A finding from the user's rules and one from our example look identical
    on screen otherwise, and "your network violates a policy" means
    something very different depending on whose policy it was.
    """
    return f"{detail} [Statements checked: {policy_label}.]"


def run(bf: Session) -> List[Dict[str, Any]]:
    """Run all four analyses and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    # One shared counter across all four analyses, so every finding gets a
    # unique id (AC-001, AC-002, ...). docs/finding-format.md calls `id` a
    # unique identifier, so anything downstream may rely on it -- duplicates
    # would let a consumer silently drop one of a colliding pair.
    #
    # KNOWN WEAKNESS: these numbers are assigned in discovery order, so a
    # finding's id shifts if an earlier one stops occurring. policy_compliance
    # pins ids to rules instead, which is better and is what would let the
    # dashboard show what changed since the previous run. Worth adopting here.
    numbering = count(1)

    # WHOSE statements? (#316) Resolved once, here, so every branch below
    # agrees. `statements` replaces the module-level POLICY everywhere in
    # this function; POLICY is now only the fallback that statements_in_use()
    # may return, not something run() reads directly.
    statements, policy_label, user_supplied = statements_in_use()

    # An empty policy is valid and must be LOUD -- the same rule
    # policy_compliance follows. Returning nothing here would be read by the
    # pipeline as this check being broken, which is the wrong status and the
    # wrong message for a check that ran perfectly and had nothing to assert.
    #
    # The dead-rule and undefined-reference analyses need no policy at all,
    # so they still run below and this is a note rather than an early return.
    if user_supplied and not statements:
        results_empty_policy = [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="n/a",
                summary="No access-control statements to check",
                detail=(
                    "Your policy file has no access_control entries, so "
                    "nothing was asserted about which flows must be allowed "
                    "or blocked. This is not a problem with the config -- it "
                    "is what an empty section means. The analyses that need "
                    "no policy, dead rules and undefined references, still "
                    "ran."
                ),
                source=policy_label,
                number=next(numbering),
            )
        ]
    else:
        results_empty_policy = []

    # Which of these statements can this snapshot actually answer?
    #
    # POLICY and GUARANTEES name specific devices. On a snapshot that does not
    # contain them, every statement would report "could not check" -- correct
    # under F-4, but measured at 8 of 9 findings on one fixture and 10 of 10 on
    # a converted PF Sense config. Correct and unusable are not the same thing.
    #
    # So the inapplicable ones are reported ONCE, together, instead of one card
    # each. They are still reported: skipping quietly is the silent omission
    # F-4 exists to prevent, and a device may be absent because someone forgot
    # to upload it.
    present = snapshot.device_names(bf)
    total = len(statements) + len(GUARANTEES)
    results: List[Dict[str, Any]] = list(results_empty_policy)

    if present is None:
        # We could not find out what is in this snapshot. Note what this does
        # NOT say: it does not claim the devices are absent, because we have
        # not observed that. Saying so would send a reader looking for a
        # missing device when the real fault was a broken Batfish query -- the
        # same mistake routing.py fixed in 6d7c769, where a hardcoded summary
        # blamed a missing route for what was actually a deny rule.
        policy, guarantees = [], []
        results.append(
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary=(
                    f"{total} access policy statement(s) could not be checked "
                    "against this config"
                ),
                detail=(
                    "The devices present in this snapshot could not be "
                    "determined, so we cannot tell whether these statements "
                    "apply to it. Nothing is claimed about them either way. "
                    "The analyses that need no policy -- dead rules and "
                    "undefined references -- still ran."
                ),
                source="analysis/checks/access_control.py",
                number=next(numbering),
            )
        )
    else:
        policy = [s for s in statements if s["node"] in present]
        guarantees = [g for g in GUARANTEES if g["node"] in present]
        absent = sorted(
            {s["node"] for s in statements if s["node"] not in present}
            | {g["node"] for g in GUARANTEES if g["node"] not in present}
        )
        if absent:
            skipped = ((len(statements) - len(policy))
                       + (len(GUARANTEES) - len(guarantees)))
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    # Safe here in a way it is not above: we know what is
                    # present, so naming the missing device is an observation.
                    device=absent[0] if len(absent) == 1 else "unknown",
                    summary=(
                        f"{skipped} access policy statement(s) could not be checked "
                        "against this config"
                    ),
                    detail=(
                        "They are written about "
                        + ", ".join(absent)
                        + ", which "
                        + ("is" if len(absent) == 1 else "are")
                        + " not in this snapshot. Nothing is claimed about them "
                        "either way. The analyses that need no policy -- dead rules "
                        "and undefined references -- still ran."
                    ),
                    source="analysis/checks/access_control.py",
                    number=next(numbering),
                )
            )

    results.extend(_check_policy_statements(bf, numbering, policy))
    results.extend(_check_guarantees(bf, numbering, guarantees))
    results.extend(_check_dead_rules(bf, numbering))
    results.extend(_check_undefined_references(bf, numbering))

    # THE "WE DID NOT READ YOUR RULES" CARD IS GONE, BECAUSE WE NOW DO.
    #
    # #196 added an error finding here saying "N supplied rule(s) for this
    # check were not read", and its comment said it "goes away when the check
    # learns to read a policy properly". #316 taught it, four hundred lines
    # above, and left the card in place.
    #
    # For one commit, a user supplying access_control rules got their rules
    # checked, their findings produced, AND an amber card saying their rules
    # had been ignored -- two contradictory claims from one run of one check.
    # That is worse than a stale comment: it is a FINDING making a false
    # statement about what Netwise did, next to the findings that disprove it.
    #
    # tests/test_unread_policy_is_reported.py now asserts the card is ABSENT
    # for a check that reads a policy. Nothing asserted that before, which is
    # why the contradiction survived its own commit.

    # BEFORE the clean-sentinel return below, deliberately. Appending after it
    # meant this card was skipped in exactly the case that matters most: the
    # built-in rules find nothing, the user gets a GREEN TICK, and nothing
    # mentions that their own rules were never read. Caught by the test for
    # it, not by reading the code. Making `results` non-empty suppresses the
    # sentinel, which is the same trade PC-049 makes (#229).

    # Only claim "all clear" if every analysis ran AND found nothing. If any
    # produced an error finding, `results` is non-empty and we never get here --
    # which is the point.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=statements[0]["node"] if statements else "unknown",
                summary="No issues found by access control",
                detail=(
                    f"{len(statements)} policy statement(s) hold, {len(GUARANTEES)} "
                    "guarantee(s) proven, no dead rules, no undefined references"
                ),
                source=", ".join(sorted({s["node"] for s in statements})),
            )
        ]

    return results


# ---------------------------------------------------------------------------
# 1. Policy statements -- testFilters
# ---------------------------------------------------------------------------


def _check_policy_statements(
    bf: Session, numbering: Iterator[int], statements: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Check each single-flow policy statement with testFilters.

    `statements` is the subset whose devices are in this snapshot -- run()
    filters them, so anything reaching here is genuinely checkable.
    """
    results: List[Dict[str, Any]] = []

    for statement in statements:
        node = statement["node"]
        filter_name = statement["filter"]

        # testFilters answers: for ONE specific packet, does this filter permit
        # or deny it, and WHICH LINE decided? That line is the evidence -- it
        # is what lets us say "blocked by this rule" instead of just "blocked",
        # and it is what the AI layer expands into plain English.
        try:
            frame = (
                bf.q.testFilters(
                    nodes=node,
                    filters=filter_name,
                    # Where the packet enters the device. A filter's behaviour
                    # can depend on the incoming interface, so this matters.
                    startLocation=node,
                    headers=HeaderConstraints(**statement["headers"]),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {statement['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        if frame.empty:
            # The query ran but matched nothing -- usually the node or filter
            # does not exist in this snapshot. Blind, not clean.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {statement['description'].lower()}",
                    detail=(
                        f"Batfish returned no result for filter {filter_name!r} "
                        f"on device {node!r}. Does it exist in this config?"
                    ),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        row = frame.iloc[0]
        actual = row["Action"]

        if actual == statement["expected"]:
            continue  # config agrees with policy -- nothing to report

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=statement["violation_severity"],
                device=node,
                summary=statement["violation_summary"],
                # The evidence is Batfish's own words -- the exact ACL line that
                # decided. We never paraphrase it here; the AI layer does that,
                # grounded in this string.
                detail=(
                    f"Expected {statement['expected']} but got {actual}, "
                    f"decided by: {row['Line_Content']}"
                ),
                # testFilters names the matching LINE but not its line NUMBER,
                # so the best source we can give is device:filter.
                source=f"{node}:{filter_name}",
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 2. Guarantees -- searchFilters  (the strongest capability)
# ---------------------------------------------------------------------------


def _check_guarantees(
    bf: Session, numbering: Iterator[int], guarantees: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Prove that no packet in a whole space is permitted, using searchFilters.

    WHY THIS IS DIFFERENT FROM testFilters
        testFilters asks about one packet. searchFilters asks about every packet
        matching a description -- every address in the subnet, every source
        port -- and returns one that violates the rule, if any exists.

        So an EMPTY result is the interesting one: it means Batfish searched
        the whole space and found no permitted flow. That is a proof the
        guarantee holds, not a sample that happened to pass.

        A returned row is a counter-example: a specific flow that IS permitted
        when it should not be, plus the ACL line responsible.
    """
    results: List[Dict[str, Any]] = []

    for guarantee in guarantees:
        node = guarantee["node"]
        filter_name = guarantee["filter"]

        try:
            frame = (
                bf.q.searchFilters(
                    nodes=node,
                    filters=filter_name,
                    # action="permit" means "search for flows this filter
                    # PERMITS". We expect none, because the guarantee says this
                    # traffic must never be allowed.
                    action="permit",
                    headers=HeaderConstraints(**guarantee["headers"]),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not prove: {guarantee['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        if frame.empty:
            # Nothing in the whole space is permitted -- the guarantee holds.
            # No finding: this analysis found no problem.
            continue

        # Batfish found at least one violating flow. Report the first as the
        # counter-example -- one concrete packet is far more useful to a human
        # than "the policy is violated somewhere".
        row = frame.iloc[0]
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=guarantee["violation_severity"],
                device=node,
                summary=guarantee["violation_summary"],
                detail=(
                    f"Example permitted flow: {row['Flow']}, "
                    f"allowed by: {row['Line_Content']}"
                ),
                source=f"{node}:{filter_name}",
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 3. Dead rules -- filterLineReachability
# ---------------------------------------------------------------------------


def _check_dead_rules(bf: Session, numbering: Iterator[int]) -> List[Dict[str, Any]]:
    """Find ACL lines that can never match because an earlier line shadows them.

    WHY THIS MATTERS
        A dead rule is dangerous precisely because it looks fine. Someone reads
        the config, sees "permit HTTPS to the finance server", and believes it
        works. It never fires, because a broader line above it already decided.

        Batfish returns ONE ROW PER UNREACHABLE LINE, naming the blocking
        line(s). An empty result means every line in every ACL can fire.
    """
    try:
        frame = bf.q.filterLineReachability().answer().frame()
    except Exception as error:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                summary="Could not check for dead ACL rules",
                detail=findings.describe_error(error),
                source="filterLineReachability",
                number=next(numbering),
            )
        ]

    results: List[Dict[str, Any]] = []
    for _, row in frame.iterrows():
        # `Sources` looks like ["rtr-us5: acl_in"] -- the device and filter the
        # dead line belongs to. Split it back apart for the finding fields.
        source_text = row["Sources"][0] if len(row["Sources"]) else "unknown: unknown"
        device, _, filter_name = source_text.partition(": ")

        # A dead DENY is worse than a dead PERMIT. A permit that never fires
        # blocks traffic someone wanted (an availability problem). A deny that
        # never fires lets through traffic someone meant to block -- a security
        # hole. Batfish tells us which it is, so we grade accordingly rather
        # than guessing.
        dead_action = row["Unreachable_Line_Action"]
        severity = "high" if dead_action == "DENY" else "medium"

        blocking = ", ".join(row["Blocking_Lines"]) or "an earlier line"
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=severity,
                device=device,
                summary=f"ACL rule never takes effect in {filter_name}",
                detail=(
                    f"Unreachable line: {row['Unreachable_Line']} "
                    f"(action {dead_action}). Blocked by: {blocking}. "
                    f"Reason: {row['Reason']}"
                ),
                source=source_text,
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 4. Undefined references -- undefinedReferences
# ---------------------------------------------------------------------------


def _check_undefined_references(
    bf: Session, numbering: Iterator[int]
) -> List[Dict[str, Any]]:
    """Find config that points at a structure which was never defined.

    WHY THIS MATTERS
        `ip access-group acl_guest_in in` on an interface, with no
        `ip access-list acl_guest_in` anywhere, is a silent failure. The author
        believed they had applied a filter. Depending on the platform the
        traffic may be entirely unfiltered.

        An empty result means every referenced structure exists.
    """
    try:
        frame = bf.q.undefinedReferences().answer().frame()
    except Exception as error:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                summary="Could not check for undefined references",
                detail=findings.describe_error(error),
                source="undefinedReferences",
                number=next(numbering),
            )
        ]

    # undefinedReferences reports the FILE, not the device. Rather than guessing
    # a hostname from the filename, ask Batfish which nodes came from which
    # file -- so `device` stays grounded in real output like everything else.
    file_to_node = _map_files_to_nodes(bf)

    results: List[Dict[str, Any]] = []
    for _, row in frame.iterrows():
        file_name = row["File_Name"]
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                # High: an undefined ACL reference means traffic the author
                # believed was filtered may not be filtered at all.
                severity="high",
                device=file_to_node.get(file_name, "unknown"),
                summary=f"Config refers to {row['Struct_Type']} '{row['Ref_Name']}' which is not defined",
                detail=(
                    f"Referenced as: {row['Context']}. "
                    f"The structure {row['Ref_Name']!r} is never defined in this snapshot."
                ),
                # `Lines` is already in filename:[line] form -- exactly the
                # "filename:line" F-1 asks for.
                source=str(row["Lines"]),
                status="found",
                number=next(numbering),
            )
        )

    return results


def _map_files_to_nodes(bf: Session) -> Dict[str, str]:
    """Map each config file to the device defined in it, using fileParseStatus.

    Returns an empty map on failure -- callers fall back to "unknown", which is
    what F-1 says to use when we cannot tell which device a finding belongs to.
    """
    try:
        frame = bf.q.fileParseStatus().answer().frame()
    except Exception:
        return {}

    mapping: Dict[str, str] = {}
    for _, row in frame.iterrows():
        nodes = row["Nodes"]
        if len(nodes):
            mapping[row["File_Name"]] = nodes[0]
    return mapping
