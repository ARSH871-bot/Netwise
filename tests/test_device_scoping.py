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
from analysis.checks import access_control, policy_compliance, routing


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


# --- policy_compliance's use of it -------------------------------------------
#
# Same behaviour, one structural difference worth testing separately: this check
# has NO analysis that works without a policy. access_control still runs dead
# rules and undefined references when its statements do not apply; here, if
# nothing applies, nothing runs. That makes "skip quietly" a more attractive
# shortcut and a worse mistake, because there is no other output left to notice
# its absence.


def _run_policy_with_devices(monkeypatch, present):
    """Run policy_compliance with a known device set and Batfish stubbed out."""
    monkeypatch.setattr(policy_compliance.snapshot, "device_names", lambda bf: present)
    # No rule may actually reach Batfish: every one that runs returns "holds".
    monkeypatch.setattr(policy_compliance, "_search", lambda *a, **k: [])
    return policy_compliance.run(_FakeSession())


def test_policy_absent_devices_reported_once_not_once_per_rule(monkeypatch):
    results = _run_policy_with_devices(monkeypatch, {"rtr-hq", "rtr-branch"})

    assert len(results) == 1, f"one card, not one per rule: {[f['id'] for f in results]}"
    assert results[0]["status"] == "error", "still an error -- we did not check"
    assert "rtr-us5" in results[0]["evidence"]["detail"]
    assert "not in this snapshot" in results[0]["evidence"]["detail"]


def test_policy_skip_card_has_its_own_reserved_id(monkeypatch):
    """PC-050 mirrors PC-000: 'the whole check could not apply'.

    It cannot borrow a rule's number -- those are pinned, and reusing one would
    make PC-002 mean two different things depending on the snapshot.
    """
    results = _run_policy_with_devices(monkeypatch, {"rtr-hq"})
    assert results[0]["id"] == "PC-050"

    rule_ids = {f"PC-{r['number']:03d}" for r in policy_compliance.POLICY_RULES}
    error_ids = {
        f"PC-{r['number'] + policy_compliance.ERROR_NUMBER_OFFSET:03d}"
        for r in policy_compliance.POLICY_RULES
    }
    assert "PC-050" not in rule_ids | error_ids, "the skip id must not collide"


def test_policy_unknown_devices_do_not_claim_the_devices_are_absent(monkeypatch):
    """The #45 lesson, applied here: do not assert a cause we did not observe."""
    results = _run_policy_with_devices(monkeypatch, None)

    assert len(results) == 1 and results[0]["status"] == "error"
    detail = results[0]["evidence"]["detail"]
    assert "could not be determined" in detail
    assert "not in this snapshot" not in detail, (
        "we did not observe that -- fileParseStatus failed, which is a "
        "different fact from the device being absent"
    )
    assert results[0]["device"] == "unknown"


def test_policy_missing_devices_never_become_a_clean_result(monkeypatch):
    """The failure this whole change is one careless step away from.

    If the skip card were ever dropped instead of reported, a snapshot naming
    none of our devices would come back status="none" -- a clean bill of health
    for a config nothing was checked against. That is the F-4 lie.
    """
    for present in ({"rtr-hq"}, set(), None):
        results = _run_policy_with_devices(monkeypatch, present)
        assert results, "never return nothing"
        assert not any(f["status"] == "none" for f in results), (
            f"a config we could not check must never read as clean (present={present!r})"
        )


def test_policy_says_nothing_when_every_device_is_present(monkeypatch):
    """The normal case must not gain a spurious card."""
    results = _run_policy_with_devices(monkeypatch, {"rtr-us5"})

    assert [f["status"] for f in results] == ["none"]
    assert results[0]["id"] == "PC-000"
# --- routing's use of it -----------------------------------------------------
#
# The last check to adopt this. Until #29 it was the only remaining source of
# "could not check" cards on an ordinary upload: measured on `main`, a full
# pipeline run over rtr-us5-secure returned two clean checks and two amber
# routing cards, both about routers that config never mentioned.


class _EmptyTraceFrame:
    """A traceroute answer that matched nothing.

    Enough for these tests: they care which statements are ASKED about, not
    what the answers say. An empty frame makes every applicable statement
    report its own "Could not check: ..." card, which is deliberately worded
    differently from the single scoping card so the two cannot be confused.
    """

    empty = True


class _RoutingQuestions:
    def traceroute(self, **_kwargs):
        return _FakeAnswer(_EmptyTraceFrame())


class _RoutingSession:
    def __init__(self):
        self.q = _RoutingQuestions()


def _run_routing_with_devices(monkeypatch, present):
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: present)
    return routing.run(_RoutingSession())


def _scoping_card(results):
    """The single card reported when statements do not apply to this snapshot.

    Matched on the scoping wording specifically, NOT on "could not" -- a
    per-statement error says "Could not check: the hq lan must...", and a test
    that accepted either would pass while the fix did nothing.
    """
    cards = [f for f in results if "route assertion(s) could not be checked" in f["summary"]]
    assert len(cards) == 1, f"expected exactly one scoping card, got {len(cards)}"
    return cards[0]


def test_routing_absent_devices_are_reported_once_not_once_per_statement(monkeypatch):
    results = _run_routing_with_devices(monkeypatch, {"rtr-us5"})

    card = _scoping_card(results)
    assert card["status"] == "error", "still an error -- we did not check"
    assert len(results) == 1, "the statements must not also report individually"


def test_routing_summary_names_the_missing_devices_and_the_count(monkeypatch):
    results = _run_routing_with_devices(monkeypatch, {"rtr-us5"})
    card = _scoping_card(results)

    assert str(len(routing.ROUTES)) in card["summary"]
    detail = card["evidence"]["detail"]
    assert "rtr-hq" in detail and "rtr-branch" in detail
    assert "not in this snapshot" in detail


def test_routing_reports_nothing_extra_when_every_device_is_present(monkeypatch):
    """The normal case must be untouched -- no scoping card on a good run."""
    results = _run_routing_with_devices(monkeypatch, {"rtr-hq", "rtr-branch"})

    assert not any(
        "route assertion(s) could not be checked" in f["summary"] for f in results
    )


def test_routing_unknown_devices_do_not_claim_the_devices_are_absent(monkeypatch):
    """Same distinction #45 was corrected on, kept here rather than re-learned.

    device_names() returning None means we could not find out what is in the
    snapshot. Saying "rtr-hq is not in this snapshot" would assert something
    never observed, and would be false on a snapshot that does contain it.
    """
    results = _run_routing_with_devices(monkeypatch, None)
    card = _scoping_card(results)

    detail = card["evidence"]["detail"]
    assert "could not be determined" in detail
    assert "not in this snapshot" not in detail, "must not assert absence"
    assert card["device"] == "unknown"
    assert card["status"] == "error"


@pytest.mark.parametrize("present", [{"rtr-us5"}, set(), None])
def test_routing_inapplicable_statements_never_become_a_clean_result(present, monkeypatch):
    """The one that matters most.

    Like policy_compliance and unlike access_control, this check has no
    analysis that runs without a statement -- if nothing applies, nothing
    runs. So "skip quietly" would leave an empty result list, and an empty
    list is one line away from the all-clear at the end of run().
    """
    results = _run_routing_with_devices(monkeypatch, present)

    assert results, "something must be reported"
    assert not any(f["status"] == "none" for f in results), (
        "a snapshot whose devices we never checked must never report 'no issues found'"
    )


def test_routing_scoping_card_id_cannot_collide_with_a_statement(monkeypatch):
    """RT-050 is reserved. ROUTES numbers are pinned, so a borrowed id would
    mean different things on different snapshots."""
    card = _scoping_card(_run_routing_with_devices(monkeypatch, set()))

    assert card["id"] == f"RT-{routing.SKIPPED_NUMBER:03d}"
    assert routing.SKIPPED_NUMBER not in {r["number"] for r in routing.ROUTES}
