"""#266 -- "nothing was checked" must not read as "checked, nothing found".

A policy with no `policy_compliance` entries produces a `status="none"`
finding whose own detail says *"nothing was asserted about this
configuration and nothing was checked"* -- and both renderers counted it
under **checked, nothing found**, next to a green tick.

That is F-4's own confusion arriving one level down. `none` and `error` were
separated so "we looked and it was fine" could not be mistaken for "nobody
looked"; this is a third sentence hiding inside the first.

WHAT IS FIXED, AND WHAT DELIBERATELY IS NOT
    The CARD is distinguished, in both renderers, in words and not only in
    colour. The TILE TOTAL is unchanged -- see `report.is_nothing_to_check()`
    for why a fourth number would trade one confusion for another.

THE JOIN IS THE POINT OF THIS FILE
    The predicate keys on `device == "n/a"`, which no part of F-1 promises.
    A producer renaming it would silently return this card to looking like a
    clean pass, with every other test still green. So the first test here
    runs the REAL check and asserts the sentinel it emits still satisfies the
    predicate -- the same gap the PF Sense/policy join had, where both halves
    were tested and the join between them was not.
"""

import csv
import io
import re

import pytest

from analysis import policy as policy_module
from analysis import report
from analysis.checks import policy_compliance


# --- the fixtures ------------------------------------------------------------

#: The sentinel, copied from what the real check emits. Pinned against the
#: producer by the first test below, so this stays a copy rather than a guess.
NOTHING = {
    "id": "PC-000",
    "check": "policy_compliance",
    "severity": "low",
    "device": "n/a",
    "summary": "No policy compliance rules to check",
    "evidence": {
        "detail": (
            "Your policy file has no policy_compliance entries, so nothing "
            "was asserted about this configuration and nothing was checked."
        ),
        "source": "the policy file you supplied",
    },
    "status": "none",
}

#: A GENUINE clean result. Same status, real device, and it must keep behaving
#: exactly as it did before #266 -- that is the regression this file guards.
GENUINE_CLEAN = {
    "id": "AC-000",
    "check": "access_control",
    "severity": "low",
    "device": "rtr-us5",
    "summary": "No issues found by access control",
    "evidence": {"detail": "3 policy statement(s) hold", "source": "rtr-us5"},
    "status": "none",
}

PROBLEM = {
    "id": "AC-001",
    "check": "access_control",
    "severity": "high",
    "device": "rtr-us5",
    "summary": "Unencrypted web traffic reaches the server",
    "evidence": {"detail": "Expected DENY but got PERMIT", "source": "acl_in"},
    "status": "found",
}

BLIND = {
    "id": "RT-050",
    "check": "routing",
    "severity": "high",
    "device": "unknown",
    "summary": "2 route assertion(s) could not be checked",
    "evidence": {"detail": "rtr-hq is not in this snapshot", "source": "n/a"},
    "status": "error",
}


# --- 1. the join: does the real producer still emit what we key on? ----------


def test_the_real_check_still_emits_the_sentinel_the_renderers_key_on():
    """THE JOIN. Everything else in this file tests one half or the other.

    `is_nothing_to_check()` keys on `device == "n/a"`, and nothing in F-1
    promises a check will keep writing that. If `policy_compliance` renamed
    it, both renderers would quietly go back to showing a green tick over
    zero assertions -- with every other test in this file still passing,
    because they all use the fixture above rather than the real thing.

    So this asserts the fixture is still a faithful copy: the real check,
    given a policy with no rules of its own, produces a finding the predicate
    recognises. Needs no Batfish -- the empty-policy branch returns before any
    session is touched, which is why `run(None)` is safe here.

    THE POLICY MUST BE INSTALLED, not merely absent. The branch is
    `if user_supplied and not rules` -- with no active policy the check falls
    back to our BUILT-IN rules and never reaches it. The first version of this
    test called `run(None)` with nothing installed, got the built-in path, and
    failed; the failure was correct and is worth recording, because a test
    that had instead been written to pass against the built-in path would have
    pinned nothing at all.
    """
    empty_for_this_check = policy_module.load_policy(
        {"device": "rtr-us5",
         "access_control": [{"description": "x", "filter": "acl_in",
                             "expected": "PERMIT"}]}
    )
    policy_module.set_active_policy(empty_for_this_check)
    try:
        produced = policy_compliance.run(None)
    finally:
        policy_module.clear_active_policy()

    sentinels = [f for f in produced if f.get("status") == "none"]
    assert sentinels, (
        "policy_compliance no longer emits a status='none' finding for a "
        "policy with no rules -- #266's whole premise has moved"
    )

    assert any(report.is_nothing_to_check(f) for f in sentinels), (
        "the real check's 'nothing to check' sentinel is no longer recognised "
        "by is_nothing_to_check(). Got devices: "
        f"{[f.get('device') for f in sentinels]!r}. If the producer changed "
        "deliberately, update NOTHING_TO_CHECK_DEVICE -- do NOT delete this "
        "test, it is the only thing joining the two halves."
    )


# --- 2. the predicate itself -------------------------------------------------


def test_the_sentinel_is_recognised():
    assert report.is_nothing_to_check(NOTHING)


def test_a_genuine_clean_result_is_not():
    """The regression guard. A real clean result must be untouched by #266."""
    assert not report.is_nothing_to_check(GENUINE_CLEAN)


@pytest.mark.parametrize("finding", [PROBLEM, BLIND])
def test_only_status_none_can_ever_be_nothing_to_check(finding):
    """`device` alone must not be enough.

    BLIND carries `source: "n/a"` and a problem could name a device oddly;
    neither is a "nothing to check". Both halves of the predicate are load-
    bearing, and a mutation dropping the status half is caught here.
    """
    assert not report.is_nothing_to_check(finding)


def test_a_none_finding_on_a_real_device_is_not_nothing_to_check():
    """The other half: `status` alone must not be enough either."""
    assert not report.is_nothing_to_check(dict(NOTHING, device="rtr-us5"))


# --- 3. the tile totals do not move -----------------------------------------


def test_the_clean_tile_still_counts_it():
    """DELIBERATE. The card is distinguished; the count is not split.

    If this ever fails, someone has decided to add a fourth number -- which
    is a product decision, not a refactor, and #266 explicitly did not make
    it.
    """
    sections = report._sections([PROBLEM, GENUINE_CLEAN, NOTHING, BLIND])

    assert len(sections["clean"]) == 2, "the sentinel left the clean section"
    assert len(sections["problems"]) == 1
    assert len(sections["blind"]) == 1


def test_the_html_counts_are_unchanged_by_the_distinction():
    html_out = report.render_html([PROBLEM, GENUINE_CLEAN, NOTHING, BLIND])

    counts = re.search(r'<div class="counts">.*?</div></div>', html_out, re.S)
    assert counts, "the counts block is gone"
    numbers = re.findall(r'<span class="n">(\d+)</span>', counts.group(0))

    assert numbers == ["1", "2", "1"], (
        f"tile totals moved: {numbers} -- expected 1 problem, 2 clean "
        "(the genuine one AND the sentinel), 1 could-not-check"
    )


# --- 4. the HTML card is distinguished, in words ----------------------------


def test_the_html_card_gets_its_own_class():
    html_out = report.render_html([NOTHING])
    assert 'class="f nothing"' in html_out


def test_the_genuine_clean_html_card_is_untouched():
    """The regression guard, on the renderer this time."""
    html_out = report.render_html([GENUINE_CLEAN])
    assert 'class="f clean"' in html_out
    assert 'class="f nothing"' not in html_out
    assert "nothing was checked" not in html_out.lower()


def test_the_html_card_says_it_in_words_not_only_colour():
    """A class is a colour. The claim has to survive greyscale and a reader.

    Same discipline as the blind cards' "this is not a clean result" line and
    the summary tiles' captions.
    """
    html_out = report.render_html([NOTHING])

    claim = re.search(r'<div class="claim">(.*?)</div>', html_out, re.S)
    assert claim, "the nothing-to-check card carries no sentence at all"

    text = claim.group(1).lower()
    assert "not a clean result" in text
    assert "nothing was checked" in text


def test_the_distinction_does_not_need_the_stylesheet_to_be_read():
    """Strip every style rule and the claim must still be there."""
    html_out = report.render_html([NOTHING])
    without_style = re.sub(r"<style>.*?</style>", "", html_out, flags=re.S)

    assert "not a clean result" in without_style.lower()


# --- 5. the CSV agrees with the HTML ----------------------------------------


def _rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_the_csv_has_the_column():
    assert "nothing_to_check" in report.CSV_COLUMNS


def test_the_csv_marks_the_sentinel_and_nothing_else():
    rows = {
        r["id"]: r
        for r in _rows(report.render_csv([PROBLEM, GENUINE_CLEAN, NOTHING, BLIND]))
    }

    assert rows["PC-000"]["nothing_to_check"] == "yes"
    assert rows["AC-000"]["nothing_to_check"] == ""
    assert rows["AC-001"]["nothing_to_check"] == ""
    assert rows["RT-050"]["nothing_to_check"] == ""


def test_the_csv_still_carries_every_row():
    """Adding a column must not drop or reorder anything."""
    rows = _rows(report.render_csv([PROBLEM, GENUINE_CLEAN, NOTHING, BLIND]))

    assert [r["id"] for r in rows] == ["RT-050", "AC-001", "AC-000", "PC-000"]


def test_both_renderers_agree_about_which_finding_it_is():
    """The two predicates are duplicated across two languages; these two
    renderers at least must not disagree with each other."""
    findings = [PROBLEM, GENUINE_CLEAN, NOTHING, BLIND]

    csv_marked = {
        r["id"]
        for r in _rows(report.render_csv(findings))
        if r["nothing_to_check"] == "yes"
    }
    html_marked = {
        f["id"]
        for f in findings
        if 'class="f nothing"' in report.render_html([f])
    }

    assert csv_marked == html_marked == {"PC-000"}
