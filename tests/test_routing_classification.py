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

from analysis.checks.routing import _evaluate, _violation_detail


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


# --- _violation_detail (#439) ---------------------------------------------------
# run() builds a finding's evidence.detail by calling this function with
# _evaluate()'s own output. Tested directly so tests/test_explain_safety_
# net.py's routing fixtures, which call this same function to build a
# realistic detail string, fail loudly if this format ever changes --
# rather than silently testing a hand-typed copy that no longer matches
# what run() actually emits.


def test_violation_detail_matches_what_run_actually_builds():
    violation = _evaluate("REACHABLE", [FakeTrace("NO_ROUTE")])
    detail = _violation_detail("REACHABLE", "10.10.10.5", "10.20.20.5", violation)
    assert detail == (
        "Expected REACHABLE for a flow from 10.10.10.5 to 10.20.20.5, "
        f"but {violation}"
    )


# --- Unknown expected value ----------------------------------------------------


def test_unknown_expected_value_raises_rather_than_silently_passing():
    """A statement with anything other than REACHABLE/UNREACHABLE in
    "expected" is a bug in ROUTES, not a runtime condition. It must raise
    loudly -- run()'s caller (pipeline.run_check) converts that into a
    status="error" finding, not a crash -- rather than falling through to a
    false "all clear" the way the original UNREACHABLE gap did."""
    with pytest.raises(ValueError):
        _evaluate("SOMETHING_ELSE", [FakeTrace("ACCEPTED")])


# --- No traces at all ----------------------------------------------------------


@pytest.mark.parametrize("expected", ["REACHABLE", "UNREACHABLE"])
def test_no_traces_raises_rather_than_silently_passing(expected):
    """Zero traces is zero evidence, for either expectation.

    With an empty list there are no failures (so REACHABLE "held") and no
    successes (so UNREACHABLE "held"). Measured on main dc93ccb, both
    returned None, and routing.run() said "All 1 route assertion(s) ...
    hold", status none, for a path nobody traced.
    """
    with pytest.raises(ValueError):
        _evaluate(expected, [])


def test_no_traces_reaches_the_user_as_could_not_check(monkeypatch):
    """It reaches the user as an error, not a tick."""
    import pandas as pd

    from analysis import pipeline
    from analysis.checks import routing

    class _Answer:
        def answer(self): return self
        def frame(self): return pd.DataFrame([{"Traces": []}])

    class _Session:
        class q:  # noqa: N801 -- mirrors pybatfish's bf.q
            @staticmethod
            def traceroute(**_kwargs): return _Answer()

    route = {
        "description": "hq must reach branch", "node": "rtr-hq",
        "src_ip": "10.1.1.1", "dst_ip": "10.2.2.2", "expected": "REACHABLE",
        "violation_summary": "hq cannot reach branch",
        "violation_severity": "high", "number": 1,
    }
    monkeypatch.setattr(routing, "ROUTES", [route])
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-hq"})
    monkeypatch.setattr(routing, "_routing_hygiene", lambda bf: [])

    results = pipeline.run_check(_Session(), "routing")

    assert [f["status"] for f in results] == ["error"], results


# --- One route that cannot be judged must not take the others with it -----------
#
# Found by Ankeet reviewing #442. _evaluate() now raises for zero traces, and its
# call site in run() was the one place in the loop with no handling of its own.
# So one such route ended the whole check: the routes after it were never asked,
# the policy-free analyses never ran, and the user saw one "failed to run" card.


def _routes_and_session(monkeypatch, answers):
    """Three routes on three devices. `answers` maps a device to its traces."""
    import pandas as pd

    from analysis.checks import routing

    asked = []

    class _Answer:
        def __init__(self, traces): self.traces = traces
        def answer(self): return self
        def frame(self): return pd.DataFrame([{"Traces": self.traces}])

    class _Session:
        class q:  # noqa: N801 -- mirrors pybatfish's bf.q
            @staticmethod
            def traceroute(startLocation=None, **_kwargs):  # noqa: N803 -- pybatfish's name
                asked.append(startLocation)
                return _Answer(answers[startLocation])

    def route(number, node, expected="REACHABLE"):
        return {"description": f"route {number}", "node": node, "src_ip": "10.1.1.1",
                "dst_ip": "10.2.2.2", "expected": expected,
                "violation_summary": f"route {number} is broken",
                "violation_severity": "high", "number": number}

    monkeypatch.setattr(routing, "ROUTES", [route(1, "rtr-a"), route(2, "rtr-b"), route(3, "rtr-c")])
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-a", "rtr-b", "rtr-c"})
    hygiene = []
    monkeypatch.setattr(routing, "_routing_hygiene", lambda bf: (hygiene.append(True), [])[1])
    return _Session(), asked, hygiene


def test_a_route_with_no_traces_does_not_stop_the_other_routes(monkeypatch):
    from analysis import pipeline

    session, asked, hygiene = _routes_and_session(monkeypatch, {
        "rtr-a": [],  # nothing traced: cannot be judged
        "rtr-b": [FakeTrace("NO_ROUTE")],  # a real violation, and it must still be reported
        "rtr-c": [FakeTrace("ACCEPTED")],  # holds
    })

    results = pipeline.run_check(session, "routing")
    by_device = {f["device"]: f for f in results}

    assert asked == ["rtr-a", "rtr-b", "rtr-c"], "every route must still be asked"
    assert hygiene, "the policy-free analyses must still run"
    assert by_device["rtr-a"]["status"] == "error"
    assert by_device["rtr-a"]["id"] == "RT-001", "the error belongs to that route, not to the check"
    assert "route 1" in by_device["rtr-a"]["summary"]
    assert "no traces" in by_device["rtr-a"]["evidence"]["detail"]
    assert by_device["rtr-b"]["status"] == "found"


def test_the_route_that_could_not_be_judged_is_never_vouched_for(monkeypatch):
    """The all-clear covers rtr-c, which held. It must not include rtr-a, which
    nobody checked: this PR exists to stop exactly that sentence being printed."""
    from analysis import pipeline

    session, _asked, _hygiene = _routes_and_session(monkeypatch, {
        "rtr-a": [], "rtr-b": [FakeTrace("ACCEPTED")], "rtr-c": [FakeTrace("ACCEPTED")],
    })

    results = pipeline.run_check(session, "routing")
    clean = [f for f in results if f["status"] == "none"]

    assert len(clean) == 1, results
    assert "rtr-a" not in clean[0]["evidence"]["source"]
    assert "rtr-b" in clean[0]["evidence"]["source"] and "rtr-c" in clean[0]["evidence"]["source"]


def test_a_bad_expected_value_is_reported_on_that_route_alone(monkeypatch):
    """_evaluate() raises the same way for a bad "expected", so it gets the same
    treatment: that route says it could not be checked, and the rest still run."""
    from analysis import pipeline
    from analysis.checks import routing

    session, asked, hygiene = _routes_and_session(monkeypatch, {
        "rtr-a": [FakeTrace("ACCEPTED")], "rtr-b": [FakeTrace("ACCEPTED")], "rtr-c": [FakeTrace("ACCEPTED")],
    })
    routing.ROUTES[0]["expected"] = "SOMETIMES"

    results = pipeline.run_check(session, "routing")
    by_device = {f["device"]: f for f in results}

    assert asked == ["rtr-a", "rtr-b", "rtr-c"] and hygiene
    assert by_device["rtr-a"]["status"] == "error"
    assert "SOMETIMES" in by_device["rtr-a"]["evidence"]["detail"]
