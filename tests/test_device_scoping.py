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


def test_device_names_returns_none_when_batfish_cannot_answer():
    """None, not an empty set -- the two are different facts.

        set()   we know what is here, and it is nothing
        None    we could not find out what is here

    Both must lead to reporting that the check could not run, so the safety
    outcome is the same. What differs is what a caller may then SAY. An earlier
    version returned set() for both and produced a message asserting the
    devices were absent -- a claim about a snapshot nobody had managed to read.
    """
    assert snapshot.device_names(_FakeSession(raises=True)) is None


def test_an_empty_snapshot_is_not_the_same_as_an_unreadable_one():
    """The distinction, asserted directly so it cannot be collapsed later."""
    empty = snapshot.device_names(_FakeSession(_FakeFrame([])))
    unknown = snapshot.device_names(_FakeSession(raises=True))
    assert empty == set() and unknown is None
    assert empty is not unknown


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


def test_unknown_devices_do_not_claim_the_devices_are_absent(monkeypatch):
    """The message must not assert something we did not observe.

    Caught in review by @shubhamkataria2005 and @patelankeet2 independently:
    when device_names() failed, the card still said the devices were "not in
    this snapshot" -- false on a snapshot that does contain them, and it sends
    a reader hunting a missing device when Batfish was the problem.
    """
    results = _run_with_devices(monkeypatch, None)
    card = next(f for f in results if "could not be checked" in f["summary"])

    detail = card["evidence"]["detail"]
    assert "could not be determined" in detail
    assert "not in this snapshot" not in detail, "must not assert absence"
    assert card["device"] == "unknown", (
        "with nothing observed, the finding cannot be attributed to a device"
    )
    assert card["status"] == "error"


def test_unknown_devices_still_never_become_a_clean_result(monkeypatch):
    results = _run_with_devices(monkeypatch, None)
    assert results and not any(f["status"] == "none" for f in results)


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
