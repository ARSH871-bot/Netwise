"""A partly-read config gets its analysis AND its caveat (#217).

THE DECISION THIS IMPLEMENTS
    `find_parse_problems()` treated every non-PASSED status as fatal,
    including `PARTIALLY_UNRECOGNIZED`, and its own docstring named that as a
    decision waiting to be revisited:

        "Real-world configs often have a few unrecognised lines, and refusing
         to analyse them at all may prove too strict. When we hit that, the
         fix is to let the checks run but attach a loud 'results may be
         incomplete' finding -- NOT to quietly ignore it."

    We hit it. Measured on a hand-written Cisco ASA -- a firewall, the device
    class this product is most about:

        cisco_asa.cfg    PARTIALLY_UNRECOGNIZED   ['fw-asa']

    Batfish built the node and read the interfaces and the access-list. We
    threw the entire analysis away and told the user we could check nothing.

BOTH WRONG ANSWERS, NAMED
    Refusing the whole file loses real findings about the part we CAN read.
    Ignoring the status entirely reports a clean result for a config we only
    partly read -- the exact lie F-4 exists to prevent.

    So: run the checks, and attach a `status="error"` finding naming the
    files. The user gets the analysis and the caveat. Neither alone is honest.

NO BATFISH
    Every test here drives the real functions with a crafted frame or a
    stubbed classifier.
"""

from __future__ import annotations

import pandas as pd
import pytest

from analysis import pipeline


class _Answer:
    def __init__(self, frame): self._frame = frame

    def frame(self): return self._frame


class _Question:
    def __init__(self, frame): self._frame = frame

    def answer(self): return _Answer(self._frame)


class _Q:
    def __init__(self, frame): self._frame = frame

    def fileParseStatus(self, *a, **k): return _Question(self._frame)


class _FakeSession:
    def __init__(self, rows):
        self.q = _Q(pd.DataFrame(rows))


def _status(file_name, status):
    return {"File_Name": file_name, "Status": status}


# ---------------------------------------------------------------------------
# classify_parse_status -- the split itself
# ---------------------------------------------------------------------------


def test_a_clean_parse_has_neither_fatal_nor_partial():
    bf = _FakeSession([_status("a.cfg", "PASSED"), _status("b.cfg", "PASSED")])

    assert pipeline.classify_parse_status(bf) == ([], [])


def test_partially_unrecognized_is_partial_not_fatal():
    """The whole point of #217. If this flips back, the ASA is refused again."""
    bf = _FakeSession([_status("fw-asa.cfg", "PARTIALLY_UNRECOGNIZED")])

    fatal, partial = pipeline.classify_parse_status(bf)

    assert fatal == [], (
        "PARTIALLY_UNRECOGNIZED means Batfish built a node -- refusing the "
        "whole analysis throws away real findings about the part it read"
    )
    assert len(partial) == 1
    assert "fw-asa.cfg" in partial[0], "the file must be named"


@pytest.mark.parametrize("status", ["FAILED", "EMPTY", "UNKNOWN"])
def test_every_other_status_is_still_fatal(status):
    """The relaxation is ONE status wide, deliberately.

    Without this, "be less strict" quietly becomes "accept anything", which
    is the failure mode the old docstring warned about.
    """
    bf = _FakeSession([_status("broken.cfg", status)])

    fatal, partial = pipeline.classify_parse_status(bf)

    assert partial == []
    assert len(fatal) == 1 and status in fatal[0]


def test_one_file_can_be_fatal_while_another_is_partial():
    bf = _FakeSession([
        _status("good.cfg", "PASSED"),
        _status("partial.cfg", "PARTIALLY_UNRECOGNIZED"),
        _status("broken.cfg", "FAILED"),
    ])

    fatal, partial = pipeline.classify_parse_status(bf)

    assert len(fatal) == 1 and "broken.cfg" in fatal[0]
    assert len(partial) == 1 and "partial.cfg" in partial[0]


def test_no_files_at_all_is_fatal():
    """An empty snapshot must never analyse. It would report clean."""
    bf = _FakeSession([])

    fatal, partial = pipeline.classify_parse_status(bf)

    assert fatal and not partial


# ---------------------------------------------------------------------------
# find_parse_problems -- deliberately UNCHANGED, because change_impact uses it
# ---------------------------------------------------------------------------


def test_find_parse_problems_still_treats_partial_as_a_problem():
    """`analysis/change_impact.py` calls this and must stay strict.

    It compares two snapshots and reports what moved between them, so an
    unrecognised line on one side and not the other would surface as a change
    in the NETWORK rather than a change in what we could read.

    The point of #217 was to split the two callers, not to loosen one
    function for everybody.
    """
    bf = _FakeSession([_status("fw-asa.cfg", "PARTIALLY_UNRECOGNIZED")])

    assert pipeline.find_parse_problems(bf), (
        "change_impact relies on this staying strict"
    )


# ---------------------------------------------------------------------------
# analyse() -- the behaviour a user actually sees
# ---------------------------------------------------------------------------


@pytest.fixture
def _stubbed_run(monkeypatch):
    """Let analyse() reach the parse-status branch without Batfish.

    Everything before it is stubbed; the checks return one clean finding each
    so the result is realistic rather than empty.
    """
    # `analyse()` calls connect(host) POSITIONALLY -- a keyword-only stub
    # raises TypeError, which analyse catches and reports as "Batfish is not
    # reachable", so the test fails for a reason that has nothing to do with
    # what it is testing. Found by running it outside pytest.
    monkeypatch.setattr(pipeline, "connect", lambda *a, **k: _FakeSession([]))
    monkeypatch.setattr(pipeline, "load_snapshot",
                        lambda bf, d, network_name, snapshot_name: None)
    monkeypatch.setattr(pipeline, "run_check", lambda bf, name: [
        pipeline.findings.no_issues_finding(
            check=name, summary=f"{name} found nothing",
            detail="stub", source="test", device="rtr-us5")
    ])


def _analyse_with(monkeypatch, fatal, partial):
    monkeypatch.setattr(pipeline, "classify_parse_status",
                        lambda bf: (fatal, partial))
    return pipeline.analyse("tests/fixtures/rtr-us5-secure")


def test_a_partial_parse_still_produces_the_findings(monkeypatch, _stubbed_run):
    """The analysis runs. That is the change."""
    results = _analyse_with(monkeypatch, [], ["fw-asa.cfg (PARTIALLY_UNRECOGNIZED)"])

    clean = [f for f in results if f["status"] == "none"]
    assert clean, (
        "the checks must actually run on a partly-read config -- refusing "
        "the whole file is what #217 changed"
    )


def test_a_partial_parse_attaches_a_loud_incomplete_finding(monkeypatch,
                                                            _stubbed_run):
    """And the caveat. Without it this change would be the OTHER wrong answer."""
    results = _analyse_with(monkeypatch, [], ["fw-asa.cfg (PARTIALLY_UNRECOGNIZED)"])

    caveat = [f for f in results if "may be incomplete" in f["summary"]]

    assert len(caveat) == 1, "exactly one caveat, naming the problem once"
    assert caveat[0]["status"] == "error", (
        "this is a genuine 'we could not check' claim about part of the "
        "user's config -- a warning or a note would let it be skimmed past"
    )
    assert "fw-asa.cfg" in caveat[0]["evidence"]["detail"], (
        "the caveat must name the file, or the user cannot act on it"
    )


def test_a_clean_parse_attaches_no_caveat(monkeypatch, _stubbed_run):
    """The control case.

    Without this, a caveat attached unconditionally would pass the test above
    while telling every user their results might be incomplete.
    """
    results = _analyse_with(monkeypatch, [], [])

    assert not [f for f in results if "may be incomplete" in f["summary"]]


def test_a_fatal_parse_still_refuses_to_analyse(monkeypatch, _stubbed_run):
    """Unchanged, and it must stay unchanged.

    A file Batfish could not read at all produces no findings worth having,
    and running the checks would report an empty model as clean.
    """
    results = _analyse_with(monkeypatch, ["broken.cfg (FAILED)"], [])

    assert results, "F-4: a refusal is still findings, never an empty list"
    assert all(f["status"] == "error" for f in results), (
        "nothing may be reported as checked when the config did not parse"
    )
    assert not [f for f in results if f["status"] == "none"]
