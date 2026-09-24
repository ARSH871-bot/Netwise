"""#266 on screen: the third claim is visible in the DOM, not just in CSS.

Drives `tests/js/nothing_to_check_harness.js`, which loads the REAL
`web/static/app.js` and renders three findings that differ only in the way
that matters -- a genuine clean result, the "nothing to check" sentinel, and
a could-not-check.

WHY A DOM HARNESS AND NOT A SOURCE ASSERTION
    The whole risk in #266 is a distinction that exists in the stylesheet and
    nowhere else. The harness has no CSS at all, so anything asserted here is
    carried by markup and words -- which is the property that has to hold for
    a greyscale screenshot, a printed page and a screen reader.

Skips when node is unavailable, like every other JS harness test here.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "nothing_to_check_harness.js"


@pytest.fixture(scope="module")
def rendered():
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    result = subprocess.run(
        ["node", str(HARNESS)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == 0, f"harness failed:\n{result.stderr}"
    return json.loads(result.stdout)


def _card(rendered, finding_id):
    for card in rendered["cards"]:
        if finding_id in card["text"]:
            return card
    raise AssertionError(f"no card rendered for {finding_id}")


# --- the predicate on its own ------------------------------------------------


def test_the_predicate_recognises_the_sentinel_and_nothing_else(rendered):
    """BOTH HALVES OF THE PREDICATE ARE LOAD-BEARING, and a mutation proved
    the second one was not tested until this existed.

    Deleting `status === "none"` -- leaving it keyed on `device` alone --
    passed the entire suite. It is equivalent at the single place the
    function is called today, because `clean` has already been filtered to
    `status="none"` before the renderer asks, so the status half can never
    decide anything there.

    That makes it an equivalent mutant *for now*, which is not the same as a
    harmless one: a second caller keyed on `device` alone would call any
    could-not-check finding carrying "n/a" a "nothing to check". The Python
    twin was already tested this way; this is the JS side of the same guard,
    written down rather than left as a known survivor.
    """
    p = rendered["predicate"]

    assert p["sentinel"] is True
    assert p["genuineClean"] is False
    assert p["blindOnNaDevice"] is False, (
        "a status='error' finding with device 'n/a' is being called a "
        "'nothing to check' -- the status half of the predicate is gone"
    )
    assert p["foundOnNaDevice"] is False


# --- the distinction ---------------------------------------------------------


def test_the_sentinel_card_has_its_own_variant(rendered):
    assert _card(rendered, "PC-000")["className"] == "finding nothing"


def test_a_genuine_clean_card_is_unchanged(rendered):
    """THE REGRESSION GUARD. #266 must not touch a real clean result."""
    card = _card(rendered, "AC-000")
    assert card["className"] == "finding clean"
    assert "✓" in card["text"]
    assert "checked" in card["text"]


def test_the_three_claims_are_three_different_cards(rendered):
    """Neither green nor amber. A third claim needs a third look."""
    variants = {
        "PC-000": _card(rendered, "PC-000")["className"],
        "AC-000": _card(rendered, "AC-000")["className"],
        "RT-050": _card(rendered, "RT-050")["className"],
    }
    assert len(set(variants.values())) == 3, (
        f"two claims share a card treatment: {variants}"
    )


def test_the_sentinel_does_not_get_a_tick(rendered):
    """A checkmark is the clean result's mark and must not appear here."""
    assert "✓" not in _card(rendered, "PC-000")["text"]


def test_the_badge_says_what_happened(rendered):
    assert "nothing to check" in _card(rendered, "PC-000")["text"]


# --- the words, which are the claim -----------------------------------------


def test_the_sentinel_says_it_is_not_a_clean_result_in_words(rendered):
    """The harness renders no CSS, so this can only be markup and text.

    Same discipline as the blind card's own sentence: colour is the signal,
    the words are the claim.
    """
    text = _card(rendered, "PC-000")["text"].lower()
    assert "not a clean result" in text
    assert "nothing was checked" in text


def test_the_sentence_has_its_own_class_so_it_can_be_styled_apart(rendered):
    assert "nothing-warning" in _card(rendered, "PC-000")["classes"]


def test_the_genuine_clean_card_makes_no_such_claim(rendered):
    assert "not a clean result" not in _card(rendered, "AC-000")["text"].lower()


def test_the_sentinel_is_not_told_an_explanation_was_missing(rendered):
    """A bug this change introduced and this test now pins.

    The explanation/remediation notices were guarded by a LIST of variants
    (`!== "blind" && !== "clean"`), so the new fourth variant fell through and
    the card acquired "No explanation was generated for this finding" --
    implying one was expected, on the one card whose entire point is that
    there was nothing to check. The guard now keys on `status === "found"`,
    which is what web/main.py actually does when attaching them.
    """
    text = _card(rendered, "PC-000")["text"].lower()
    assert "no explanation was generated" not in text
    assert "no mechanical remediation" not in text


# --- the counts do not move --------------------------------------------------


def test_it_still_counts_toward_the_clean_tile(rendered):
    """DELIBERATE, and the same assertion the report renderer carries.

    Two `status="none"` findings went in -- one genuine, one the sentinel --
    and the clean tile must read 2. Splitting the tile into four numbers is a
    product decision #266 did not make.
    """
    tiles = {t["className"]: t["text"] for t in rendered["summaryTiles"]}

    assert tiles["tile clean"].startswith("2"), (
        f"the clean tile no longer counts the sentinel: {tiles['tile clean']!r}"
    )
    assert tiles["tile problems"].startswith("0")
    assert tiles["tile blind"].startswith("1")


def test_it_stays_in_the_checked_nothing_found_section(rendered):
    """The card is distinguished WITHIN the section, not moved out of it.

    Moving it would make the section heading disagree with the tile above,
    which is the confusion this issue is about, relocated rather than fixed.
    """
    assert _card(rendered, "PC-000")["section"] == "Checked — nothing found"
    assert _card(rendered, "AC-000")["section"] == "Checked — nothing found"
