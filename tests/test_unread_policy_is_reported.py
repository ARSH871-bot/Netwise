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
    """Install a policy holding entries for both checks.

    THE ENTRIES ARE COMPLETE, AND THEY HAVE TO BE (#316, #319).
        `_Policy` above is a double that bypasses `load_policy()`, so
        `_SECTION_REQUIRED` never runs against it. That was harmless while
        neither check dereferenced these keys: the entries carried a
        description and a node because that was all anyone read.

        Both checks now read them, and the double happily held entries the
        real loader would refuse -- which surfaced as `KeyError: 'dst_ip'`
        from inside `routing.run()`, exactly the failure `_SECTION_REQUIRED`
        exists to move forward to load time.

        A double that can express states the real thing rejects will
        eventually pin behaviour that cannot happen. Keeping these entries
        loader-valid is what stops that.
    """
    pol = _Policy({
        "access_control": [{"description": "Guests must not reach finance",
                            "node": "rtr-acme", "filter": "acl_in",
                            "headers": {"srcIps": "10.30.30.0/24"},
                            "expected": "DENY",
                            "violation_severity": "high",
                            "violation_summary": "guests reach finance"}],
        "routing": [{"description": "HQ must reach branch", "node": "rtr-acme",
                     "number": 1, "src_ip": "10.10.10.5",
                     "dst_ip": "10.20.20.5", "expected": "REACHABLE",
                     "violation_severity": "high",
                     "violation_summary": "HQ cannot reach branch"},
                    {"description": "Branch must reach HQ", "node": "rtr-acme",
                     "number": 2, "src_ip": "10.20.20.5",
                     "dst_ip": "10.10.10.5", "expected": "REACHABLE",
                     "violation_severity": "high",
                     "violation_summary": "branch cannot reach HQ"}],
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


def test_access_control_no_longer_says_the_rules_were_not_read(
        supplied, monkeypatch):
    """INVERTED ON #316, and the inversion is the point.

    This used to assert the card was PRESENT -- correct while the check
    ignored a supplied policy, which was the whole subject of #196.

    #316 taught `access_control` to read one, and left the card in place.
    For one commit a user supplying access-control rules got their rules
    checked, their findings produced, AND an amber card saying their rules
    had been ignored: two contradictory claims from a single run of a single
    check. Worse than a stale comment -- a FINDING stating something false
    about what Netwise did, printed beside the findings that disprove it.

    Nothing caught it, because this file only ever asserted the card was
    there. A test that pins a true statement becomes a test that pins a
    false one the day the code catches up, and the pinning is invisible
    either way.

    So the assertion is now the opposite one, and it is the assertion that
    would have failed on #316 the moment it was written.
    """
    monkeypatch.setattr(access_control.snapshot, "device_names", lambda bf: {"rtr-us5"})
    monkeypatch.setattr(access_control, "_check_policy_statements", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_guarantees", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_dead_rules", lambda *a, **k: [])
    monkeypatch.setattr(access_control, "_check_undefined_references", lambda *a, **k: [])

    results = access_control.run(bf=None)
    card = next((f for f in results if "not read" in f["summary"]), None)

    assert card is None, (
        "access_control reads a supplied policy since #316, and still told "
        f"the user it had not: {card['summary'] if card else ''}"
    )


def test_access_control_actually_uses_the_supplied_rules(supplied):
    """The positive half, so absence of the card is not the whole claim.

    Deleting the card would satisfy the test above on its own. It would not
    mean the rules were read. This asserts the resolver returns the USER's
    entry rather than our two built-in statements.
    """
    statements, label, user_supplied = access_control.statements_in_use()

    assert user_supplied is True
    assert label == access_control.USER_POLICY_LABEL
    assert len(statements) == 1, (
        "expected the one supplied access_control entry, got "
        f"{len(statements)} -- our built-in list has two"
    )
    assert statements[0]["description"] == "Guests must not reach finance"


def test_routing_no_longer_says_the_assertions_were_not_read(
        supplied, monkeypatch):
    """INVERTED ON #319, for the reason the access_control one was on #316.

    #196 gave this check a card saying "N supplied route assertion(s) were
    not read". That was true, and this test pinned it. #319 made it false by
    teaching the check to read them, so the assertion is now the opposite.

    With #316 and #319 together, every section `analysis/policy.py`
    validates is read by the check that owns it. #196's cards have no
    remaining subject, and `entries_supplied_for()` -- the helper that
    counted rules nobody read -- has no remaining caller. Both are removed
    here rather than left as machinery for a problem that no longer exists.
    """
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-acme"})

    results = routing.run(bf=None)
    card = next((f for f in results if "not read" in f["summary"]), None)

    assert card is None, (
        "routing reads a supplied policy since #319, and still told the user "
        f"it had not: {card['summary'] if card else ''}"
    )


def test_routing_actually_uses_the_supplied_assertions(supplied):
    """The positive half. Deleting the card alone would pass the test above
    without a single user assertion ever being read."""
    routes, label, user_supplied = routing.routes_in_use()

    assert user_supplied is True
    assert label == routing.USER_POLICY_LABEL
    assert len(routes) == 2, (
        f"expected the two supplied routing entries, got {len(routes)}"
    )
    assert all(r["node"] == "rtr-acme" for r in routes), (
        "the user's assertions name rtr-acme; ours name rtr-hq and rtr-branch"
    )


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
