"""Netwise -- a check that ignores your policy must say so (#196).

WHY THIS FILE EXISTS
    `policy_compliance` reads a supplied policy since #181. `access_control`
    and `routing` do not. Measured on `main` before this change, with a user
    policy naming their own device in all three sections:

        access_control   said NOTHING -- the entry was silently discarded
        routing          RT-050 "written about rtr-branch, rtr-hq, which are
                         not in this snapshot"

    Every device and every count in that routing message is OURS. The user
    wrote about `rtr-acme`.

    F-4 holds narrowly either way -- both report `error`, never `none`, so
    nobody is told they are safe. But "we could not check YOUR rules" and
    "we never read your rules" are different claims, and the product was
    making the wrong one.

WHAT THIS DOES NOT TEST
    That either check READS a supplied policy. Neither does, deliberately --
    that is the capability half of #196 and needs the seam #181 built plus a
    decision per check about what a supplied rule even means for it. This is
    the honesty half.

RUN
    pytest tests/ -v
"""

import pytest

from analysis import policy as policy_module
from analysis.checks import access_control, routing


class _Policy:
    """Enough of a Policy for entries_supplied_for(): it only counts."""

    def __init__(self, sections):
        self.sections = sections

    def entries_for(self, check_name):
        return self.sections.get(check_name, [])


@pytest.fixture
def supplied(monkeypatch):
    """Install a policy holding entries for both checks that ignore one."""
    pol = _Policy({
        "access_control": [{"description": "Guests must not reach finance",
                            "node": "rtr-acme"}],
        "routing": [{"description": "HQ must reach branch", "node": "rtr-acme"},
                    {"description": "Branch must reach HQ", "node": "rtr-acme"}],
    })
    monkeypatch.setattr(policy_module, "active_policy", lambda: pol)
    return pol


def test_no_policy_supplied_means_no_extra_card(monkeypatch):
    """The card must not appear for the overwhelmingly common case.

    A user who supplied nothing has nothing to be told about, and an amber
    card on every clean run is how people learn to ignore amber.
    """
    monkeypatch.setattr(policy_module, "active_policy", lambda: None)
    assert policy_module.entries_supplied_for("access_control") == 0
    assert policy_module.entries_supplied_for("routing") == 0


def test_the_count_is_the_users_not_ours(supplied):
    """THE #196 REGRESSION.

    The old routing message said "2 route assertion(s)" -- OUR two, about OUR
    devices -- to a user who supplied their own. The number must come from
    their policy.
    """
    assert policy_module.entries_supplied_for("routing") == 2
    assert policy_module.entries_supplied_for("access_control") == 1


def test_a_check_with_no_entries_in_a_supplied_policy_is_not_told_off(supplied):
    """A policy that says nothing about a check is not the same as an ignored one.

    `policy_compliance` has no section in this fixture. It must not acquire a
    "your rules were not read" card, because there were none to read.
    """
    assert policy_module.entries_supplied_for("policy_compliance") == 0


def test_access_control_says_the_rules_were_not_read(supplied, monkeypatch):
    """It used to say nothing at all."""
    monkeypatch.setattr(access_control.snapshot, "device_names", lambda bf: {"rtr-us5"})
    monkeypatch.setattr(access_control, "_check_policy_statements", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_guarantees", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_dead_rules", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_undefined_references", lambda *a, **k: [])

    results = access_control.run(bf=None)
    card = next((f for f in results if "not read" in f["summary"]), None)

    assert card is not None, "a supplied access-control rule was silently discarded"
    assert card["status"] == "error", "not read is a could-not-check, never a clean result"
    assert "1 rule(s) for access control" in card["evidence"]["detail"]
    assert "#196" in card["evidence"]["detail"]


def test_routing_says_the_assertions_were_not_read(supplied, monkeypatch):
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-hq", "rtr-branch"})
    monkeypatch.setattr(routing, "_evaluate", lambda *a, **k: [])

    results = routing.run(bf=None)
    card = next((f for f in results if "not read" in f["summary"]), None)

    assert card is not None
    assert card["status"] == "error"
    assert card["id"] == "RT-051", f"pinned id, got {card['id']}"
    assert "2 supplied route assertion(s)" in card["summary"]


def test_the_routing_id_cannot_collide_with_its_other_bands():
    """RT-051 must stay clear of the route numbers and of SKIPPED_NUMBER.

    Same discipline as PC-049 (#229): a sentinel that quietly reuses a number
    produces a duplicate id, which is what A-2 made structurally impossible
    ACROSS checks and is still only discipline WITHIN one.
    """
    numbers = {r["number"] for r in routing.ROUTES}
    assert routing.UNREAD_POLICY_NUMBER not in numbers
    assert routing.UNREAD_POLICY_NUMBER != routing.SKIPPED_NUMBER
    assert routing.UNREAD_POLICY_NUMBER != 0, "must not collide with the clean sentinel"
