"""Tests for scoping policy statements to the devices actually in a snapshot.

THE PROBLEM THESE COVER
    Every check states its policy against named devices. On a snapshot that
    does not contain them, each statement reported "could not check" -- correct
    under F-4, and unusable in volume. Measured on `main` before this change:

        routing-secure snapshot      8 of 9 findings were "could not check"
        converted PF Sense config   10 of 10

    The fix reports it ONCE per check instead of once per statement. The danger
    in that fix is obvious: one wrong step and it becomes "skip quietly", which
    is the silent omission F-4 exists to prevent. So these tests care much more
    about what must STILL be reported than about the tidier output.

These need neither Batfish nor Docker.
"""

import pytest

from analysis import findings, snapshot
from analysis.checks import access_control


class _FakeAnswer:
    """The real call is fileParseStatus().answer().frame() -- three steps.

    Worth spelling out: the first version of this double had .frame() but no
    .answer(), so device_names() raised AttributeError and returned an empty
    set. The tests failed for the right reason on wrong grounds, and would have
    passed the fail-closed test while proving nothing about the happy path.
    """

    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _FakeQuestions:
    def __init__(self, frame=None, raises=False):
        self._frame, self._raises = frame, raises

    def fileParseStatus(self):
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._frame)


class _FakeSession:
    def __init__(self, frame=None, raises=False):
        self.q = _FakeQuestions(frame, raises)


class _FakeFrame:
    """Just enough of a pandas frame for device_names to iterate it."""

    def __init__(self, rows):
        self._rows = rows

    def iterrows(self):
        return enumerate(self._rows)


# --- snapshot.device_names ---------------------------------------------------


def test_device_names_reads_every_node_in_the_snapshot():
    bf = _FakeSession(_FakeFrame([{"Nodes": ["rtr-hq", "rtr-branch"]},
                                  {"Nodes": ["firewall"]}]))
    assert snapshot.device_names(bf) == {"rtr-hq", "rtr-branch", "firewall"}


def test_device_names_handles_a_file_that_defined_no_nodes():
    bf = _FakeSession(_FakeFrame([{"Nodes": []}, {"Nodes": ["rtr-us5"]}]))
    assert snapshot.device_names(bf) == {"rtr-us5"}


def test_device_names_fails_closed_when_batfish_cannot_answer():
    """An empty set means every statement is treated as unanswerable.

    That is the safe direction. Guessing the other way -- assuming the device
    is present because we could not find out -- would let a real blind spot
    pass as a checked result.
    """
    assert snapshot.device_names(_FakeSession(raises=True)) == set()


# --- access_control's use of it ----------------------------------------------


def _run_with_devices(monkeypatch, present):
    """Run the check with a known device set and the Batfish analyses stubbed."""
    monkeypatch.setattr(snapshot, "device_names", lambda bf: present)
    monkeypatch.setattr(access_control.snapshot, "device_names", lambda bf: present)
    for fn in ("_check_policy_statements", "_check_guarantees"):
        monkeypatch.setattr(access_control, fn, lambda bf, n, items: [])
    for fn in ("_check_dead_rules", "_check_undefined_references"):
        monkeypatch.setattr(access_control, fn, lambda bf, n: [])
    return access_control.run(_FakeSession())


def test_absent_devices_are_reported_once_not_once_per_statement(monkeypatch):
    results = _run_with_devices(monkeypatch, {"rtr-hq", "rtr-branch"})

    skipped = [f for f in results if "could not be checked" in f["summary"]]
    assert len(skipped) == 1, "one summary finding, not one per statement"
    assert skipped[0]["status"] == "error", "still an error -- we did not check"


def test_the_summary_names_the_missing_device_and_the_count(monkeypatch):
    """A user must be able to tell WHY nothing was checked, and what."""
    results = _run_with_devices(monkeypatch, {"rtr-hq"})
    summary = next(f for f in results if "could not be checked" in f["summary"])

    total = len(access_control.POLICY) + len(access_control.GUARANTEES)
    assert str(total) in summary["summary"]
    assert "rtr-us5" in summary["evidence"]["detail"]
    assert "not in this snapshot" in summary["evidence"]["detail"]


def test_nothing_is_reported_when_every_device_is_present(monkeypatch):
    """The normal case must be untouched -- no extra card on a good run."""
    results = _run_with_devices(monkeypatch, {"rtr-us5"})
    assert not any("could not be checked" in f["summary"] for f in results)


def test_a_missing_device_never_becomes_a_clean_result(monkeypatch):
    """The failure mode this whole change could have introduced.

    Reporting once instead of N times is one careless step from reporting zero
    times. If that happened, a snapshot missing every device we name would come
    back status="none" -- a clean bill of health for a config nobody checked.
    """
    results = _run_with_devices(monkeypatch, set())

    assert results, "something must be reported"
    assert not any(f["status"] == "none" for f in results), (
        "a snapshot we could not check must never report 'no issues found'"
    )
    assert any(f["status"] == "error" for f in results)
