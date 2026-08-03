"""
Netwise -- routing check (Ankeet's feature).

WHAT THIS CHECK DOES
    It asserts a reachability policy: a list of "traffic from A must (or must
    not) be able to reach B" statements, each proved or disproved against the
    real config with Batfish's traceroute question. This answers the client's
    core question for this feature: "can host A reach host B?", answered
    purely from the config, with the hop-by-hop path as evidence.

WHY traceroute AND NOT THE routes QUESTION
    Both are listed in CLAUDE.md as tools for this feature. `routes` shows
    the routing table Batfish computed; `traceroute` actually walks the path
    hop by hop and reports the outcome. For "does A reach B", traceroute is
    the direct answer -- it proves the property rather than requiring someone
    to read a routing table and infer whether it would work. `routes` is left
    unused here, the same way policy_compliance.py chose one Batfish question
    over another and documented why rather than using both by default.

WHAT COUNTS AS "REACHABLE" -- and why EXITS_NETWORK is deliberately excluded
    pybatfish's own tooling (pybatfish.datamodel.flow._get_color_for_disposition)
    treats three dispositions as success for colouring a trace diagram green:
    ACCEPTED, DELIVERED_TO_SUBNET, and EXITS_NETWORK. This module uses only
    the first two.

    DELIVERED_TO_SUBNET is included on purpose. Measured directly against a
    real two-router fixture (see tests/fixtures/routing-secure): traceroute
    between two LANs connected over a WAN link reports DELIVERED_TO_SUBNET,
    not ACCEPTED -- ACCEPTED requires the destination IP to be a device's own
    interface address, which a plain host address on a LAN never is. Treating
    DELIVERED_TO_SUBNET as failure would make every ordinary LAN-to-LAN route
    look broken.

    EXITS_NETWORK is excluded on purpose, and this was found by independent
    review, not anticipated up front. It means "forwarded toward a next hop
    Batfish has no model of at all" -- which sounds like a reasonable thing to
    call success for a flow headed to the real internet, but every ROUTES
    statement below names a SPECIFIC destination NODE that is meant to exist
    in this snapshot. Measured: deleting rtr-branch.cfg from routing-secure
    entirely and re-running the HQ -> branch statement reports EXITS_NETWORK,
    not an error. If EXITS_NETWORK counted as success, a whole device missing
    from the upload -- a real, plausible mistake -- would be reported as a
    clean, working route, which is exactly the false "none" F-4 exists to
    prevent. Excluding it means that case instead surfaces as a genuine
    finding (or, if the OTHER statement in ROUTES also references the missing
    node directly, as the status="error" the empty-frame branch below already
    produces).

THE rtr-us5 FIXTURES DO NOT WORK FOR THIS CHECK
    Both existing rtr-us5 fixtures (tests/fixtures/rtr-us5-secure,
    rtr-us5-insecure) have exactly one interface and no route beyond the
    router itself. Measured: traceroute to 10.20.0.5 from either fixture
    reports NO_ROUTE regardless of what the ACL says, because there is
    nothing past the router to route to. A routing check that ran only
    against those fixtures could never demonstrate a genuine successful
    result, so this check uses a dedicated fixture pair instead:
    tests/fixtures/routing-secure (both directions reachable) and
    tests/fixtures/routing-missing-route (one direction broken by a missing
    static route). See those fixtures' own comments for the topology.

HOW IT DECIDES WHAT TO REPORT
    Each statement declares "expected": "REACHABLE" or "UNREACHABLE". Both
    are implemented -- an earlier version of this module documented
    UNREACHABLE as the way to express a deliberately isolated segment but
    never actually handled it, which meant using it silently produced a
    false status="none" instead of evaluating anything. Fixed: see
    _evaluate() below, and tests/test_routing_classification.py, which
    regression-tests both this and the EXITS_NETWORK case directly.

      - "REACHABLE"   holds only if EVERY trace succeeds. A flow can take
                       more than one path (equal-cost routes), and a real
                       packet could take any of them, so one failing path
                       among several is a genuine partial defect.
      - "UNREACHABLE" holds only if EVERY trace fails. Mirrors searchFilters'
                       "no packet in this whole space" reasoning in
                       policy_compliance.py: even one path getting through
                       when none should is a leak, not noise.
      - Batfish could not answer at all -> status="error", we are blind here.

    If every statement was checked and all held -> a single status="none".
    NO_ROUTE is not automatically a finding and an empty query result is not
    automatically "clean" -- see F-4 in docs/finding-format.md.
"""

from typing import Any, Dict, List, Optional, Sequence

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings

# The name this check is registered under, and the value in every "check" field.
CHECK_NAME = "routing"

# See the "WHAT COUNTS AS REACHABLE" section of the module docstring for why
# this is NOT the same set pybatfish's own tooling treats as success.
SUCCESS_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET"}

# --- The reachability policy being asserted ---------------------------------
#
# PLACEHOLDER: these statements describe the routing-secure / routing-missing-
# route test fixtures. The real client topology will replace them -- kept as
# plain data, same as POLICY in access_control.py and POLICY_RULES in
# policy_compliance.py, so editing the intent list doesn't require reading
# the code below it.
#
# "number" is PINNED to the statement, not assigned by discovery order. IDs
# stay stable across runs this way (RT-001 is always this statement), which
# access_control.py's own comments flag as the better approach it doesn't yet
# use itself -- adopted here from the start rather than copied as a known
# weakness.
ROUTES: List[Dict[str, Any]] = [
    {
        "number": 1,  # RT-001
        "description": "The HQ LAN must be able to reach the branch LAN",
        "start_node": "rtr-hq",
        "src_ip": "10.10.10.5",
        "dst_ip": "10.20.20.5",
        "expected": "REACHABLE",
        "violation_summary": "The HQ network cannot reach the branch network; a route appears to be missing",
        "violation_severity": "high",
    },
    {
        "number": 2,  # RT-002
        "description": "The branch LAN must be able to reach the HQ LAN",
        "start_node": "rtr-branch",
        "src_ip": "10.20.20.5",
        "dst_ip": "10.10.10.5",
        "expected": "REACHABLE",
        "violation_summary": "The branch network cannot reach the HQ network; a route appears to be missing",
        "violation_severity": "high",
    },
]


def _evaluate(expected: str, traces: Sequence[Any]) -> Optional[str]:
    """Classify one route statement's traces against what was expected.

    Returns None if the statement holds, or a one-line description of the
    violation if it does not.

    A PURE function on purpose: it takes plain disposition-and-hops objects,
    not a live Batfish session, so it can be unit tested directly without
    Docker or Batfish. See tests/test_routing_classification.py, which
    exercises both branches and specifically regression-tests the
    EXITS_NETWORK case described in the module docstring.
    """
    successes = [t for t in traces if t.disposition in SUCCESS_DISPOSITIONS]
    failures = [t for t in traces if t.disposition not in SUCCESS_DISPOSITIONS]
    multi = len(traces) > 1

    if expected == "REACHABLE":
        if not failures:
            return None
        bad = failures[0]
        hops = " -> ".join(hop.node for hop in bad.hops) or "?"
        detail = f"traceroute ended in {bad.disposition}. Path: {hops}"
        if multi:
            detail += f" ({len(failures)} of {len(traces)} paths failed)"
        return detail

    if expected == "UNREACHABLE":
        if not successes:
            return None
        bad = successes[0]
        hops = " -> ".join(hop.node for hop in bad.hops) or "?"
        detail = f"traceroute unexpectedly succeeded: {bad.disposition}. Path: {hops}"
        if multi:
            detail += f" ({len(successes)} of {len(traces)} paths succeeded)"
        return detail

    # A statement with anything else in "expected" is a bug in ROUTES, not a
    # runtime condition -- raising here means run() surfaces it through the
    # pipeline's own crash-isolation as a status="error" finding (see
    # run_check() in analysis/pipeline.py) rather than silently doing nothing,
    # which is exactly the failure this function exists to replace.
    raise ValueError(f"route 'expected' must be REACHABLE or UNREACHABLE, got {expected!r}")


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every route statement and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    results: List[Dict[str, Any]] = []

    for route in ROUTES:
        node = route["start_node"]

        # traceroute answers: starting from THIS node, with THESE headers,
        # where does the packet end up, hop by hop? Unlike testFilters it
        # does not need a filter name -- it walks the whole path, ACLs
        # included, and reports how the flow was finally disposed of.
        try:
            frame = (
                bf.q.traceroute(
                    startLocation=node,
                    headers=HeaderConstraints(
                        srcIps=route["src_ip"], dstIps=route["dst_ip"]
                    ),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            # Could not ask the question at all -- a bad node name, a
            # malformed header. We are blind for this statement, so it is an
            # error, NOT a clean result.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {route['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{route['dst_ip']}",
                    number=route["number"],
                )
            )
            continue

        if frame.empty:
            # The query ran but matched nothing -- usually the node does not
            # exist in this snapshot. Blind, not clean.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {route['description'].lower()}",
                    detail=(
                        f"Batfish returned no result starting from node "
                        f"{node!r}. Does it exist in this config?"
                    ),
                    source=f"{node}:{route['dst_ip']}",
                    number=route["number"],
                )
            )
            continue

        row = frame.iloc[0]
        violation = _evaluate(route["expected"], row["Traces"])

        if violation is None:
            # The statement holds. Nothing to report.
            continue

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=route["violation_severity"],
                device=node,
                summary=route["violation_summary"],
                # The evidence is Batfish's own words -- the disposition it
                # actually reached and the path it took to get there. We
                # never paraphrase it here; the AI layer does that, grounded
                # in this string.
                detail=(
                    f"Expected {route['expected']} for a flow from "
                    f"{route['src_ip']} to {route['dst_ip']}, but {violation}"
                ),
                source=f"{node}:{route['dst_ip']}",
                status="found",
                number=route["number"],
            )
        )

    # Only claim "all clear" if we actually checked everything successfully.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=ROUTES[0]["start_node"] if ROUTES else "unknown",
                summary="No issues found by routing",
                detail=f"All {len(ROUTES)} route assertion(s) hold",
                source=", ".join(sorted({r["start_node"] for r in ROUTES})),
            )
        ]

    return results
