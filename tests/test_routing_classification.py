"""
Netwise -- tests for routing.py's pure trace-classification logic.

WHY THIS FILE EXISTS
    Independent review of analysis/checks/routing.py, before it was ever
    merged, found two real defects in _evaluate() and its supporting
    SUCCESS_DISPOSITIONS set:

    1. A route statement with "expected": "UNREACHABLE" was silently never
       evaluated -- the loop had no branch for it, so it fell through to the
       "everything held" fallback and produced a false status="none" for a
       statement that was never actually checked. Exactly the F-4 failure
       this whole codebase exists to prevent, and the module's own docstring
       had been telling a future author to write that exact statement.
    2. SUCCESS_DISPOSITIONS included EXITS_NETWORK, copied from pybatfish's
       own success set for colouring trace diagrams. Measured: deleting a
       destination device's config file entirely from a snapshot makes
       traceroute report EXITS_NETWORK rather than an error, so a device
       missing from an upload was being reported as a working route.

    Both are fixed in routing.py. These tests exist so neither regresses
    silently -- they exercise _evaluate() directly with fake trace objects,
    so they run in milliseconds and need neither Batfish nor Docker, the
    same reasoning tests/test_finding_ids.py gives for testing the
    duplicate-id guard the same way.

RUN
    pytest tests/ -v
"""

import pytest

from analysis.checks.routing import _evaluate


class FakeHop:
    def __init__(self, node: str):
        self.node = node


class FakeTrace:
    def __init__(self, disposition: str, hops=None):
        self.disposition = disposition
        self.hops = hops or [FakeHop("some-node")]


# --- REACHABLE ---------------------------------------------------------------


def test_reachable_holds_when_the_only_trace_succeeds():
    assert _evaluate("REACHABLE", [FakeTrace("DELIVERED_TO_SUBNET")]) is None


def test_reachable_holds_when_every_trace_succeeds():
    traces = [FakeTrace("ACCEPTED"), FakeTrace("DELIVERED_TO_SUBNET")]
    assert _evaluate("REACHABLE", traces) is None


def test_reachable_violated_when_the_only_trace_fails():
    violation = _evaluate("REACHABLE", [FakeTrace("NO_ROUTE")])
    assert violation is not None
    assert "NO_ROUTE" in violation


def test_reachable_violated_when_one_of_several_paths_fails():
    """Equal-cost paths: a real packet could take any of them, so one
    failing path among several is a genuine partial defect, not something to
    average away."""
    traces = [FakeTrace("DELIVERED_TO_SUBNET"), FakeTrace("NO_ROUTE")]
    violation = _evaluate("REACHABLE", traces)
    assert violation is not None
    assert "1 of 2 paths failed" in violation


# --- UNREACHABLE ---------------------------------------------------------------
# Regression coverage for defect 1: an earlier version of routing.py had no
# branch for this value at all, so a statement using it was silently skipped
# and the check reported a false status="none" instead of ever evaluating it.


def test_unreachable_holds_when_the_only_trace_fails():
    assert _evaluate("UNREACHABLE", [FakeTrace("NO_ROUTE")]) is None


def test_unreachable_holds_when_every_trace_fails():
    traces = [FakeTrace("NO_ROUTE"), FakeTrace("DENIED_IN")]
    assert _evaluate("UNREACHABLE", traces) is None


def test_unreachable_violated_when_the_only_trace_succeeds():
    violation = _evaluate("UNREACHABLE", [FakeTrace("DELIVERED_TO_SUBNET")])
    assert violation is not None
    assert "unexpectedly succeeded" in violation


def test_unreachable_violated_when_any_one_path_gets_through():
    """Mirrors searchFilters' reasoning in policy_compliance.py: even one
    path getting through when none should is a leak, not noise to ignore."""
    traces = [FakeTrace("NO_ROUTE"), FakeTrace("ACCEPTED")]
    violation = _evaluate("UNREACHABLE", traces)
    assert violation is not None
    assert "1 of 2 paths succeeded" in violation


# --- EXITS_NETWORK -------------------------------------------------------------
# Regression coverage for defect 2.


def test_exits_network_is_not_treated_as_success():
    """pybatfish's own tooling counts EXITS_NETWORK as success for colouring
    a trace diagram green. This module must not: every ROUTES statement
    names a specific destination node meant to exist in the snapshot, and
    EXITS_NETWORK means Batfish forwarded the packet toward a next hop it has
    no model of at all -- which includes the destination device's own config
    file simply being missing from the upload. Measured directly: deleting
    tests/fixtures/routing-secure/configs/rtr-branch.cfg and re-running the
    HQ -> branch statement reports EXITS_NETWORK, not an error."""
    violation = _evaluate("REACHABLE", [FakeTrace("EXITS_NETWORK")])
    assert violation is not None
    assert "EXITS_NETWORK" in violation


def test_exits_network_does_not_satisfy_unreachable_either():
    """Consistency check: if EXITS_NETWORK is not success, it must not
    silently count as failure-for-the-wrong-reason either -- an UNREACHABLE
    statement should hold when the only trace is EXITS_NETWORK, the same as
    any other non-success disposition."""
    assert _evaluate("UNREACHABLE", [FakeTrace("EXITS_NETWORK")]) is None


# --- Unknown expected value ----------------------------------------------------


def test_unknown_expected_value_raises_rather_than_silently_passing():
    """A statement with anything other than REACHABLE/UNREACHABLE in
    "expected" is a bug in ROUTES, not a runtime condition. It must raise
    loudly -- run()'s caller (pipeline.run_check) converts that into a
    status="error" finding, not a crash -- rather than falling through to a
    false "all clear" the way the original UNREACHABLE gap did."""
    with pytest.raises(ValueError):
        _evaluate("SOMETHING_ELSE", [FakeTrace("ACCEPTED")])
