"""A check that COULD NOT RUN must say `status="error"` -- never go quiet.

WHY THIS FILE EXISTS
    tests/test_found_status_is_reported.py pins one half of F-4: a problem a
    check finds is reported as `found`. This pins the other half: a Batfish
    question that fails is reported as `error`, and is never allowed to
    become silence that the all-clear then reads as "checked, nothing wrong".

    Measured by mutation on main dc93ccb. Each line below replaced one guard
    with `continue` or `return []`, so the failure was swallowed instead of
    reported, and the whole suite still passed with Batfish stopped, as on
    CI. The first four were also run with Batfish up: still nothing failed.

        access_control  testFilters raises      -> swallowed   SURVIVED
        access_control  testFilters empty       -> swallowed   SURVIVED
        access_control  searchFilters raises    -> swallowed   SURVIVED
        access_control  dead-rule query raises  -> swallowed   SURVIVED
        access_control  undefined-refs raises   -> swallowed   SURVIVED
        routing         traceroute raises       -> swallowed   SURVIVED
        routing         traceroute empty        -> swallowed   SURVIVED
        explain         an error card's text claims a result   SURVIVED

    Every swallowed failure ends the same way: the check's all-clear names
    the device -- "1 guarantee(s) proven" after searchFilters raised -- a
    green tick about a question Batfish never answered.

NO BATFISH, NO OLLAMA
    Each test drives a whole check's run() with a fake session. A control
    test proves the fake reaches the all-clear when nothing fails, so the
    tests below it cannot pass by never getting that far.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ai import explain as explain_module
from analysis.checks import access_control, routing

_EMPTY = pd.DataFrame()


class _Question:
    def __init__(self, outcome): self._outcome = outcome

    def answer(self, **_kwargs): return self

    def frame(self):
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


class _Q:
    """One preset outcome per question: a frame, or an exception to raise.

    An unprepared question fails the test, so a check asking something new
    cannot get an empty frame by accident and read it as "nothing found".
    """

    def __init__(self, outcomes): self._outcomes = outcomes

    def __getattr__(self, name):
        if name not in self._outcomes:
            raise AssertionError(f"the check asked an unprepared question: {name}()")
        return lambda *args, **kwargs: _Question(self._outcomes[name])


class _FakeSession:
    def __init__(self, outcomes): self.q = _Q(outcomes)


def _batfish_failed():
    return RuntimeError("BatfishException: Work terminated abnormally")


def _statuses(results):
    return [f["status"] for f in results]


# ---------------------------------------------------------------------------
# access_control
# ---------------------------------------------------------------------------

_STATEMENT = {
    "description": "DNS must be allowed",
    "node": "rtr-us5",
    "filter": "acl_in",
    "headers": {"dstIps": "10.10.10.5"},
    "expected": "PERMIT",
    "violation_summary": "DNS is blocked",
    "violation_severity": "medium",
}
_GUARANTEE = {
    "description": "No plaintext web out of the subnet",
    "node": "rtr-us5",
    "filter": "acl_in",
    "headers": {"srcIps": "10.10.10.0/24", "applications": ["http"]},
    "violation_summary": "Plaintext web is allowed out",
    "violation_severity": "high",
}


def _access_control_outcomes(**overrides):
    """Every question access_control asks, answered as a clean rtr-us5."""
    outcomes = {
        "fileParseStatus": pd.DataFrame([{
            "File_Name": "configs/rtr-us5.cfg", "Status": "PASSED",
            "Nodes": ["rtr-us5"]}]),
        "testFilters": pd.DataFrame([{"Action": "PERMIT",
                                      "Line_Content": "permit udp any any eq 53"}]),
        "searchFilters": _EMPTY,              # empty = the guarantee is proven
        "filterLineReachability": _EMPTY,
        "undefinedReferences": _EMPTY,
        "unusedStructures": _EMPTY,
    }
    outcomes.update(overrides)
    return outcomes


@pytest.fixture
def _one_statement_one_guarantee(monkeypatch):
    monkeypatch.setattr(access_control, "POLICY", [_STATEMENT])
    monkeypatch.setattr(access_control, "GUARANTEES", [_GUARANTEE])


def test_control_a_clean_access_control_run_reaches_the_all_clear(
        _one_statement_one_guarantee):
    results = access_control.run(_FakeSession(_access_control_outcomes()))
    assert _statuses(results) == ["none"], results


@pytest.mark.parametrize("question", [
    "testFilters", "searchFilters", "filterLineReachability",
    "undefinedReferences", "unusedStructures",
])
def test_an_access_control_question_that_fails_is_an_error_not_an_all_clear(
        question, _one_statement_one_guarantee):
    bf = _FakeSession(_access_control_outcomes(**{question: _batfish_failed()}))

    results = access_control.run(bf)

    assert "error" in _statuses(results), (
        f"{question}() failed and access_control reported no error: {results}")
    assert "none" not in _statuses(results), (
        f"{question}() failed and access_control still gave an all-clear -- "
        "a green tick about a question Batfish never answered")


def test_an_empty_test_filters_answer_is_an_error_not_an_all_clear(
        _one_statement_one_guarantee):
    """No row for the filter means it was not found, not that it agreed."""
    bf = _FakeSession(_access_control_outcomes(testFilters=_EMPTY))

    results = access_control.run(bf)

    assert "error" in _statuses(results), results
    assert "none" not in _statuses(results), results


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------

_ROUTE = {
    "description": "hq must reach branch",
    "node": "rtr-hq",
    "src_ip": "10.1.1.1",
    "dst_ip": "10.2.2.2",
    "expected": "REACHABLE",
    "violation_summary": "hq cannot reach branch",
    "violation_severity": "high",
    "number": 1,
}


class _Trace:
    def __init__(self, disposition):
        self.disposition = disposition
        self.hops = []


def _routing_outcomes(**overrides):
    outcomes = {
        "fileParseStatus": pd.DataFrame([{
            "File_Name": "configs/rtr-hq.cfg", "Status": "PASSED",
            "Nodes": ["rtr-hq"]}]),
        "traceroute": pd.DataFrame([{"Traces": [_Trace("ACCEPTED")]}]),
        "ipOwners": _EMPTY,
        "detectLoops": _EMPTY,
        "bgpSessionCompatibility": _EMPTY,
        "ospfSessionCompatibility": _EMPTY,
    }
    outcomes.update(overrides)
    return outcomes


def test_control_a_clean_routing_run_reaches_the_all_clear(monkeypatch):
    monkeypatch.setattr(routing, "ROUTES", [_ROUTE])
    results = routing.run(_FakeSession(_routing_outcomes()))
    assert _statuses(results) == ["none"], results


@pytest.mark.parametrize("outcome", [_batfish_failed(), _EMPTY],
                         ids=["traceroute raises", "traceroute empty"])
def test_a_traceroute_that_fails_is_an_error_not_an_all_clear(outcome, monkeypatch):
    monkeypatch.setattr(routing, "ROUTES", [_ROUTE])
    bf = _FakeSession(_routing_outcomes(traceroute=outcome))

    results = routing.run(bf)

    assert "error" in _statuses(results), results
    assert "none" not in _statuses(results), (
        "the route was never traced and routing still said every assertion holds")


# ---------------------------------------------------------------------------
# explain -- an error card's prose must not claim a result
# ---------------------------------------------------------------------------


def test_a_model_claiming_a_result_for_an_error_card_is_not_shown(monkeypatch):
    """_looks_like_a_result_claim() is unit-tested; this pins that it is USED.

    A confident sentence about the network, written for a check that never
    ran, is the F-4 failure arriving through prose instead of status.
    """
    monkeypatch.setattr(explain_module, "_ollama_is_reachable", lambda: True)
    monkeypatch.setattr(explain_module, "_generate",
                        lambda finding: "The HQ LAN cannot reach the branch LAN.")
    finding = {
        "id": "RT-000", "check": "routing", "severity": "high",
        "device": "unknown", "status": "error",
        "summary": "Could not check: hq must reach branch",
        "evidence": {"detail": "BatfishException: Work terminated abnormally",
                     "source": "traceroute"},
    }

    text, source = explain_module.explain_with_source(finding)

    assert source == "fallback", text
    assert "nothing is confirmed" in text
