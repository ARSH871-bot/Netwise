"""Netwise -- the multi-device fixture behaves as #218 measured.

WHY THIS FILE EXISTS
    Every other fixture is one or two devices. tests/fixtures/multi-device-10
    is the first with enough devices for coverage to be a question, and #218
    asked for one because nothing was known about behaviour at that size.

    These tests do NOT re-measure runtime -- a timing assertion in a suite
    that must pass on any machine is a flaky test wearing a useful hat. The
    figures live in docs/scale.md, taken by hand against live Batfish, and
    tools/make_scale_fixture.py is committed so anyone can retake them.

    What they DO pin is the shape the fixture exists to demonstrate: some
    devices covered by policy, most not, and the check saying so.

HOW THESE RUN WITHOUT BATFISH
    They read the fixture off disk and drive policy_compliance with
    snapshot.device_names stubbed, the same approach as
    tests/test_device_scoping.py. Loading ten configs into Batfish to
    re-derive names already on disk would add minutes and prove nothing.

RUN
    pytest tests/ -v
"""

from pathlib import Path

import pytest

from analysis.checks import policy_compliance

FIXTURE = Path(__file__).parent / "fixtures" / "multi-device-10"
CONFIGS = FIXTURE / "configs"


def _device_names_on_disk():
    """Hostnames as the fixture actually declares them, not as we assume."""
    names = set()
    for cfg in CONFIGS.glob("*.cfg"):
        for line in cfg.read_text().splitlines():
            if line.startswith("hostname "):
                names.add(line.split(None, 1)[1].strip())
                break
    return names


class _FakeSession:
    """policy_compliance never reaches Batfish in these tests."""


def test_the_fixture_exists_and_has_more_than_two_devices():
    """The point of the fixture. Everything else here assumes it."""
    assert FIXTURE.is_dir(), (
        "multi-device-10 is missing. Rebuild it: python -m tools.make_scale_fixture"
    )
    names = _device_names_on_disk()
    assert len(names) == 10, f"expected 10 devices, found {len(names)}: {sorted(names)}"


def test_exactly_one_device_is_covered_by_the_built_in_policy():
    """The fixture's whole purpose is the PARTIALLY covered case.

    A snapshot where nothing is covered only reaches the PC-050 path, which
    the single-device fixtures already test. A snapshot where everything is
    covered only reaches the clean sentinel. The interesting state -- and the
    one that used to produce a green tick over unexamined devices (#228) --
    needs both at once.
    """
    names = _device_names_on_disk()
    covered = {r["node"] for r in policy_compliance.POLICY_RULES}

    assert covered & names, "no device in the fixture is named by any rule"
    assert names - covered, "every device is covered; the uncovered case is untested"
    assert len(covered & names) == 1


def test_the_uncovered_devices_are_reported_not_silently_skipped(monkeypatch):
    """THE #228 REGRESSION, at the scale it was found.

    Nine of ten devices are outside every rule. The check must say so, and
    must not report a clean result for the whole snapshot.
    """
    names = _device_names_on_disk()
    monkeypatch.setattr(policy_compliance.snapshot, "device_names", lambda bf: names)
    monkeypatch.setattr(policy_compliance, "_search", lambda *a, **k: [])

    results = policy_compliance.run(_FakeSession())

    assert not any(f["status"] == "none" for f in results), (
        "nine of ten devices were never examined; this must not be a green tick"
    )
    card = next(f for f in results if f["id"] == "PC-049")
    assert "9 of 10" in card["summary"], card["summary"]


@pytest.mark.parametrize("name", sorted(_device_names_on_disk() - {"rtr-us5"})[:3])
def test_each_uncovered_device_is_named_or_counted(monkeypatch, name):
    """A card saying "9 devices" without saying WHICH is not actionable.

    The detail names the first few and counts the rest, so a reader can tell
    whether the omission is the one they care about. Checking a sample rather
    than all nine, because the card deliberately truncates.
    """
    names = _device_names_on_disk()
    monkeypatch.setattr(policy_compliance.snapshot, "device_names", lambda bf: names)
    monkeypatch.setattr(policy_compliance, "_search", lambda *a, **k: [])

    card = next(f for f in policy_compliance.run(_FakeSession()) if f["id"] == "PC-049")
    detail = card["evidence"]["detail"]

    assert name in detail or "more" in detail, (
        f"{name} is neither named nor covered by a 'and N more': {detail}"
    )
