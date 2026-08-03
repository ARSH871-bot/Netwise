"""
Netwise -- routing check (Ankeet's feature).

WHAT THIS CHECK DOES
    It asserts a reachability policy: a list of "traffic from A must be able
    to reach B" statements, each proved or disproved against the real config
    with Batfish's traceroute question. This answers the client's core
    question for this feature: "can host A reach host B?", answered purely
    from the config, with the hop-by-hop path as evidence.

WHY traceroute AND NOT THE routes QUESTION
    Both are listed in CLAUDE.md as tools for this feature. `routes` shows
    the routing table Batfish computed; `traceroute` actually walks the path
    hop by hop and reports the outcome. For "does A reach B", traceroute is
    the direct answer -- it proves the property rather than requiring someone
    to read a routing table and infer whether it would work. `routes` is left
    unused here, the same way policy_compliance.py chose one Batfish question
    over another and documented why rather than using both by default.

WHAT COUNTS AS "REACHABLE"
    Batfish's own tooling (pybatfish.datamodel.flow._get_color_for_disposition)
    treats three dispositions as success: ACCEPTED, DELIVERED_TO_SUBNET, and
    EXITS_NETWORK. This module uses exactly that set. Measured directly
    against a real two-router fixture (see tests/fixtures/routing-secure):
    traceroute between two LANs connected over a WAN link reports
    DELIVERED_TO_SUBNET, not ACCEPTED -- ACCEPTED requires the destination IP
    to be a device's own interface address, which a plain host address on a
    LAN never is. Treating DELIVERED_TO_SUBNET as failure would make every
    ordinary LAN-to-LAN route look broken.

THE rtr-us5 FIXTURES DO NOT WORK FOR THIS CHECK
    Both existing rtr-us5 fixtures (tests/fixtures/rtr-us5-secure,
    rtr-us5-insecure) have exactly one interface and no route beyond the
    router itself. Measured: traceroute to 10.20.0.5 from either fixture
    reports NO_ROUTE regardless of what the ACL says, because there is
    nothing past the router to route to. A routing check that ran only
    against those fixtures could never demonstrate a genuine ACCEPTED
    result, so this check uses a dedicated fixture pair instead:
    tests/fixtures/routing-secure (both directions reachable) and
    tests/fixtures/routing-missing-route (one direction broken by a missing
    static route). See those fixtures' own comments for the topology.

HOW IT DECIDES WHAT TO REPORT
    For each route statement:
      - every trace disposition is a success disposition -> nothing to report
      - the destination is expected reachable but at least one trace is not
        -> status="found", a real routing defect (missing or wrong route)
      - Batfish could not answer                          -> status="error"
    If every statement was checked and all held -> a single status="none".

    NO_ROUTE is not automatically a finding and an empty query result is not
    automatically "clean" -- see F-4 in docs/finding-format.md. A route that
    is genuinely absent by design (a deliberately isolated segment) would
    need its own statement with "expected": "UNREACHABLE" rather than being
    inferred from silence.
"""

from typing import Any, Dict, List

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings

# The name this check is registered under, and the value in every "check" field.
CHECK_NAME = "routing"

# Batfish's own notion of a successful delivery, taken from
# pybatfish.datamodel.flow._get_color_for_disposition, which pybatfish itself
# uses to decide whether to render a trace green (success) or red (failure).
SUCCESS_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"}

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


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every route statement and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    raise NotImplementedError("query logic lands in the next commit")
