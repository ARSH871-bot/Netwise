"""
Netwise -- tests for change-impact analysis (US-18, #30).

WHY THIS FILE EXISTS
    The feature's whole job is to answer "is this change safe?" before it
    reaches a real device, so the ways it can be wrong are the ways that
    matter most:

      - saying nothing changed when something did
      - saying a change is safe when we could not compare
      - rating a tightening as a new exposure, or the reverse

    The third is not hypothetical. The first version of this module assumed
    every differentialReachability row was traffic newly getting through, and
    rated all of them `high`. The question is SYMMETRIC -- it returns flows
    whose fate differs EITHER way -- so a change that locked the network down
    was reported as a new exposure. It was caught by running the reverse
    direction against live Batfish, and these tests exist so it cannot come
    back quietly.

HOW THESE RUN WITHOUT BATFISH
    They exercise `_flow_direction()` with fake trace objects, exactly as
    tests/test_routing_classification.py exercises `_evaluate()`, and drive
    `analyse_change()` with the Batfish calls stubbed. The logic under test is
    direction, id allocation and the F-4 distinction -- not Batfish's query
    engine, which a live session would prove nothing extra about.

RUN
    pytest tests/ -v
"""

from types import SimpleNamespace

import pytest

from analysis import change_impact


def _trace(disposition):
    """Enough of a pybatfish Trace for _any_success(): it reads .disposition."""
    return SimpleNamespace(disposition=disposition)


# --- direction: the bug this file exists for --------------------------------


def test_a_flow_that_newly_gets_through_is_opened():
    assert change_impact._flow_direction([_trace("ACCEPTED")], [_trace("DENIED_IN")]) == "opened"


def test_a_flow_that_stops_getting_through_is_closed():
    """THE REGRESSION. Assuming every row was an opening rated this `high`."""
    assert change_impact._flow_direction([_trace("DENIED_IN")], [_trace("ACCEPTED")]) == "closed"


def test_exits_network_counts_as_success_here_unlike_in_routing():
    """Measured on the fixtures: the real opening case reports EXITS_NETWORK.

    routing.py deliberately excludes EXITS_NETWORK, because a destination
    device missing from a snapshot reports it and that would read an absent
    device as a working route. That is the right call for asserting a route
    WORKS. It is the wrong call here: differentialReachability has already
    used its own success set -- which includes EXITS_NETWORK -- to select the
    flow, so this must agree with it or lose the direction entirely.
    """
    assert change_impact._flow_direction([_trace("EXITS_NETWORK")], [_trace("DENIED_IN")]) == "opened"


@pytest.mark.parametrize(
    "after, before",
    [
        ("ACCEPTED", "ACCEPTED"),   # both succeeded
        ("DENIED_IN", "NO_ROUTE"),  # neither did
    ],
)
def test_an_unclassifiable_pair_is_not_guessed(after, before):
    """Say "changed" rather than pick a direction we cannot see."""
    assert change_impact._flow_direction([_trace(after)], [_trace(before)]) == "changed"


def test_malformed_traces_do_not_raise():
    """A shape we did not expect must not take down the comparison."""
    assert change_impact._flow_direction(None, None) == "changed"


# --- the F-4 distinction ----------------------------------------------------


class _FakeFrame:
    def __init__(self, rows):
        self._rows = rows

    def __len__(self):
        return len(self._rows)

    @property
    def iloc(self):
        return self._rows


def _stub(monkeypatch, *, filters=None, flows=None, filters_raises=False, flows_raises=False):
    """Drive analyse_change() with both Batfish questions faked."""
    monkeypatch.setattr(change_impact, "connect", lambda host="localhost": SimpleNamespace(
        set_network=lambda *a, **k: None, set_snapshot=lambda *a, **k: None))
    monkeypatch.setattr(change_impact, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(change_impact, "find_parse_problems", lambda bf: [])

    def fake_filters(bf, number):
        if filters_raises:
            raise RuntimeError("compareFilters exploded")
        return (list(filters or []), number + len(filters or []))

    def fake_flows(bf, number):
        if flows_raises:
            raise RuntimeError("differentialReachability exploded")
        return (list(flows or []), number + len(flows or []))

    monkeypatch.setattr(change_impact, "_filter_change_findings", fake_filters)
    monkeypatch.setattr(change_impact, "_reachability_change_findings", fake_flows)


def _a_change(number=1):
    from analysis import findings
    return findings.make_finding(
        check="change_impact", severity="high", device="rtr-us5",
        summary="A rule change opens traffic", detail="d", source="s",
        status="found", number=number,
    )


def test_no_change_is_none_not_silence(monkeypatch):
    _stub(monkeypatch)
    results = change_impact.analyse_change("before", "after")
    assert [f["status"] for f in results] == ["none"]
    assert results[0]["id"] == "CH-000"


def test_a_config_that_will_not_parse_is_error_never_none(monkeypatch):
    """The dangerous claim. "Nothing changed" and "we could not compare" are
    different, and only one of them tells a user it is safe to proceed."""
    _stub(monkeypatch)
    monkeypatch.setattr(change_impact, "find_parse_problems",
                        lambda bf: ["rtr-broken.cfg (PARTIALLY_UNRECOGNIZED)"])
    results = change_impact.analyse_change("before", "after")
    assert [f["status"] for f in results] == ["error"]
    assert results[0]["id"] == "CH-050"
    assert not any(f["status"] == "none" for f in results)


def test_unreachable_batfish_is_error_never_none(monkeypatch):
    def refuse(host="localhost"):
        raise ConnectionError("nothing is listening")
    monkeypatch.setattr(change_impact, "connect", refuse)
    results = change_impact.analyse_change("before", "after")
    assert [f["status"] for f in results] == ["error"]
    assert "docker start batfish" in results[0]["evidence"]["detail"]


def test_a_proven_change_survives_the_second_query_failing(monkeypatch):
    """Issue #22's lesson, applied here before it could be repeated.

    compareFilters proved a change; differentialReachability then failed.
    Reporting only the error would replace a proven finding with "we don't
    know", which reads as LESS alarming than the truth.
    """
    _stub(monkeypatch, filters=[_a_change()], flows_raises=True)
    results = change_impact.analyse_change("before", "after")

    statuses = sorted(f["status"] for f in results)
    assert statuses == ["error", "found"], f"both, not just the error: {statuses}"
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_ids_stay_inside_the_ch_prefix(monkeypatch):
    _stub(monkeypatch, filters=[_a_change(1)], flows=[_a_change(2)])
    results = change_impact.analyse_change("before", "after")
    assert all(f["id"].startswith("CH-") for f in results)
    assert all(f["check"] == "change_impact" for f in results)


def test_the_error_sentinel_cannot_collide_with_a_real_finding():
    """CH-050 mirrors PC-050 -- SENTINEL_NUMBER + ERROR_NUMBER_OFFSET (#101).

    Changes are numbered from 1, so the only way to reach 50 is 50 changes in
    one comparison. Asserted rather than assumed, because the offset is what
    keeps them apart.
    """
    assert change_impact.SKIPPED_NUMBER == change_impact.ERROR_NUMBER_OFFSET
    assert change_impact.SKIPPED_NUMBER != 0, "must differ from the clean sentinel"


# --- the wiring, not just the predicate -------------------------------------
#
# The tests above prove _flow_direction() classifies correctly, and the ones
# below prove _reachability_change_findings() ACTUALLY CALLS IT.
#
# That distinction is not pedantry. Mutating the direction back to the original
# hardcoded "opened" left every test above green, because the analyse_change
# tests stub this function out entirely and the direction tests call the
# predicate directly. Neither touched the line where the two meet -- exactly
# the shape of #84, where a guard's self-test verified a copy of the logic
# while the real path could break independently.


class _FakeQuestion:
    def __init__(self, rows):
        self._rows = rows

    def answer(self, **kwargs):
        return self

    def frame(self):
        return _FakeFrame(self._rows)


class _FakeSessionWithFlows:
    def __init__(self, rows):
        self.q = SimpleNamespace(differentialReachability=lambda **kw: _FakeQuestion(rows))


def _flow_row(after_disposition, before_disposition):
    return {
        "Flow": "start=rtr-us5 interface=GigabitEthernet0/0 [10.10.10.2->10.20.0.5 TCP]",
        "Snapshot_Traces": [_trace(after_disposition)],
        "Reference_Traces": [_trace(before_disposition)],
    }


def test_reachability_findings_rate_an_opening_high():
    bf = _FakeSessionWithFlows([_flow_row("ACCEPTED", "DENIED_IN")])
    results, _ = change_impact._reachability_change_findings(bf, 1)

    assert len(results) == 1
    assert results[0]["severity"] == "high"
    assert "could not reach before" in results[0]["summary"]


def test_reachability_findings_rate_a_tightening_medium():
    """The mutation guard. Hardcoding the direction fails HERE, not above."""
    bf = _FakeSessionWithFlows([_flow_row("DENIED_IN", "ACCEPTED")])
    results, _ = change_impact._reachability_change_findings(bf, 1)

    assert len(results) == 1
    assert results[0]["severity"] == "medium", (
        "a change that blocks traffic is not a new exposure"
    )
    assert "no longer reaches" in results[0]["summary"]


def test_reachability_findings_number_sequentially_and_report_the_next():
    bf = _FakeSessionWithFlows([
        _flow_row("ACCEPTED", "DENIED_IN"),
        _flow_row("DENIED_IN", "ACCEPTED"),
    ])
    results, next_number = change_impact._reachability_change_findings(bf, 3)

    assert [f["id"] for f in results] == ["CH-003", "CH-004"]
    assert next_number == 5, "the caller needs the next free number"


# --- THE TRAP, defended at the boundary -------------------------------------
#
# The module's longest docstring section is about differentialReachability
# seeing nothing unless the start location is one traffic ENTERS. Every test
# above monkeypatches the session, so none of them observe what is actually
# SENT to Batfish -- and @ARSH871-bot demonstrated on #140 that reintroducing
# a `PathConstraints(startLocation="rtr-us5")` leaves all fifteen green while
# silently dropping a real finding live.
#
# Worse than a normal regression, because compareFilters covers for it on our
# fixtures: the run still reports the ACL change, so the output looks healthy.
# What disappears is the case the second question exists for -- changed traffic
# with no changed line. Invisible on exactly the configs we test with.
#
# Same shape as tests/test_query_translation.py's
# test_reachability_starts_from_the_entry_point_not_the_bare_device: assert on
# the argument, because the argument is what the module controls.


class _RecordingQuestion:
    def __init__(self, recorder, rows):
        self._recorder = recorder
        self._rows = rows

    def answer(self, **kwargs):
        self._recorder["answer_kwargs"] = kwargs
        return self

    def frame(self):
        return _FakeFrame(self._rows)


class _RecordingSession:
    """Records the keyword arguments each differential question was built with."""

    def __init__(self, rows=()):
        self.calls = {}
        self.q = SimpleNamespace(
            differentialReachability=lambda **kw: self._record("differentialReachability", kw, rows),
            compareFilters=lambda **kw: self._record("compareFilters", kw, ()),
        )

    def _record(self, name, kwargs, rows):
        entry = self.calls.setdefault(name, {})
        entry["build_kwargs"] = kwargs
        return _RecordingQuestion(entry, list(rows))


def test_differential_reachability_is_asked_with_no_path_constraint():
    """THE TRAP. A start location that is not an entry point sees no ACL at all.

    Measured on the fixtures, secure -> insecure, varying only this:

        startLocation = the node                  rows=0
        startLocation = the node's interface      rows=0
        startLocation = @enter(the interface)     rows=1
        no path constraint                        rows=1

    Unconstrained covers every entry point. Anything narrower has to be
    deliberately correct, and the tidy-looking version is the wrong one.
    """
    session = _RecordingSession()
    change_impact._reachability_change_findings(session, 1)

    build_kwargs = session.calls["differentialReachability"]["build_kwargs"]
    assert "pathConstraints" not in build_kwargs, (
        "a path constraint here silently excludes traffic ENTERING an "
        f"interface, which is the only traffic an inbound ACL sees: {build_kwargs}"
    )


def test_both_differential_questions_compare_after_against_before():
    """Direction of comparison is as load-bearing as the constraint.

    Swapping snapshot and reference_snapshot inverts every finding this module
    produces -- an opening would be reported as a tightening and rated medium
    instead of high. Nothing else in the file would notice.
    """
    session = _RecordingSession()
    change_impact._reachability_change_findings(session, 1)
    change_impact._filter_change_findings(session, 1)

    for question in ("differentialReachability", "compareFilters"):
        answer_kwargs = session.calls[question]["answer_kwargs"]
        assert answer_kwargs["snapshot"] == change_impact.AFTER_SNAPSHOT, question
        assert answer_kwargs["reference_snapshot"] == change_impact.BEFORE_SNAPSHOT, question
