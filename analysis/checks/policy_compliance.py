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
    policy_compliance owns PC-000..PC-099; change_impact owns PC-100..PC-199,
    because findings.py maps BOTH checks to the "PC" prefix.

    IDs are pinned to RULES, not to the order violations happen to be found:
    POL-1 is always PC-001, POL-2 always PC-002. So a given id means the same
    thing on every run, which is what will let the dashboard show what changed
    since the previous upload. A retired rule's number is never reused.
"""

from typing import Any, Dict, List

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings

# The name this check is registered under, and the value in every "check" field.
CHECK_NAME = "policy_compliance"

# Which searchFilters action proves which kind of rule. See the module docstring.
ACTION_BY_KIND = {
    "prohibition": "permit",  # find forbidden traffic that IS allowed
    "requirement": "deny",  # find required traffic that IS blocked
}

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
        "severity": "high",
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
        "severity": "high",
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
        "severity": "medium",
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
        "severity": "medium",
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
        "severity": "medium",
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


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every policy rule and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only asks questions and shapes the answers.
    """
    results: List[Dict[str, Any]] = []

    for rule in POLICY_RULES:
        node = rule["node"]
        filter_name = rule["filter"]
        action = ACTION_BY_KIND[rule["kind"]]

        try:
            # Every query for this rule. They describe one space between them,
            # so their results are pooled: a hit in any arm violates the rule.
            hits: List[Any] = []
            for headers in rule["queries"]:
                hits.extend(_search(bf, node, filter_name, action, headers))
        except Exception as error:
            # We could not ask -- a renamed ACL, a missing node, a malformed
            # header. We are blind for this rule, so it is an error, NOT a pass.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check policy rule: {rule['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{filter_name}",
                    number=rule["number"],
                )
            )
            continue

        if not hits:
            # Nothing anywhere in the searched space behaves the forbidden way.
            # The rule holds. Nothing to report.
            continue

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=rule["severity"],
                device=node,
                summary=rule["violation_summary"],
                detail=_describe(rule, hits),
                # searchFilters names the matching LINE but not its line NUMBER,
                # so device:filter is the most precise source it can give us.
                # (definedStructures does return real file:line locations; using
                # it would mean a second query per finding, and was left out to
                # keep this readable. Noted as a possible improvement.)
                source=f"{node}:{filter_name}",
                status="found",
                number=rule["number"],
            )
        )

    # Only claim "all clear" if every rule was actually checked and held. If any
    # rule errored, results is non-empty and the error is what the user sees.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=POLICY_RULES[0]["node"] if POLICY_RULES else "unknown",
                summary="No issues found by policy compliance",
                detail=f"All {len(POLICY_RULES)} policy rule(s) hold",
                source=", ".join(sorted({r["node"] for r in POLICY_RULES})),
                # PC-000. change_impact uses 100 for its own all-clear, so the
                # two checks cannot collide on the "PC" prefix they share.
                number=0,
            )
        ]

    return results
