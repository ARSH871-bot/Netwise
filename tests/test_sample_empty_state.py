"""The first screen tells the truth and tells you what to do (#347, US-56).

Drives `tests/js/sample_empty_state_harness.js`, which loads the REAL
`web/static/app.js` with no stylesheet at all, so every claim asserted here is
carried by markup and words rather than by a shade of amber.

TWO FAILURES THIS FILE EXISTS TO CATCH, AND THEY PULL IN OPPOSITE DIRECTIONS

    1. Making the empty screen friendly by making it vaguer. #352 removed six
       fabricated findings that greeted a visitor before any upload; the
       sentence it left behind -- "this is not a clean result" -- is the whole
       reason that fix worked. Adding next steps around it is #347's job.
       Softening it is #352 arriving again through a usability improvement.

    2. Letting the sample pass as the user's own network. The findings a
       sample scan produces are genuine Batfish output, so nothing about
       reading them raises a doubt. The label is the only thing that does.

Skips when node is unavailable, like every other JS harness test here.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "sample_empty_state_harness.js"
INDEX = Path(__file__).parent.parent / "web" / "static" / "index.html"


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


# --- the empty state still refuses to look clean ------------------------------


def test_the_empty_state_still_says_it_is_not_a_clean_result(rendered):
    """THE #352 REGRESSION TEST, and the reason this file leads with it.

    Everything else here is about adding helpfulness to this screen. This is
    the assertion that stops the helpfulness being bought with honesty.
    """
    text = rendered["emptyState"]["text"]
    assert "nothing has been checked" in text
    assert "not a clean result" in text


def test_the_empty_state_says_what_to_do_next(rendered):
    """The half #347 adds. An honest blank screen is still a blank screen."""
    text = rendered["emptyState"]["text"].lower()
    assert "scan now" in text
    assert "config file" in text


def test_nothing_is_offered_for_export_from_an_empty_screen(rendered):
    """Nothing analysed means nothing to download, and the hint says which.

    Carried over unchanged from the pre-#347 behaviour and asserted here
    because this branch was rewritten -- a rewrite is exactly when a line
    like this gets dropped without anyone noticing.
    """
    assert "Nothing to export" in rendered["reportHintWhenEmpty"]


# --- the sample is offered, not imposed ---------------------------------------


def test_the_empty_state_offers_the_sample_as_a_real_button(rendered):
    """A BUTTON, AND ONLY ON THE EMPTY SCREEN.

    `type="button"` is asserted because the control sits inside a page with
    forms on it; without it a click would submit. The wording is asserted
    because "try" has to read as an offer -- the first screen must not fill
    itself with data nobody asked for, which is the habit #352 corrected.
    """
    buttons = rendered["emptyStateButtons"]
    assert len(buttons) == 1, f"expected one sample offer, got {buttons}"
    assert buttons[0]["type"] == "button"
    assert "sample" in buttons[0]["text"].lower()


def test_the_offer_beside_the_file_picker_is_wired_too(rendered):
    """Two controls, one handler. The second is easy to add and forget."""
    assert rendered["pickerButtonWired"] == 1


def test_clicking_it_asks_the_server_and_does_not_invent_anything(rendered):
    """It calls POST /api/sample. The findings come from a real scan of a
    real file, which is the only thing that makes a bundled sample honest."""
    assert rendered["fetched"]["url"] == "/api/sample"
    assert rendered["fetched"]["options"]["method"] == "POST"


def test_loading_the_sample_stages_without_scanning(rendered):
    """#82's rule, unchanged: staging and analysing are two deliberate acts.

    So Scan Now becomes available and the results pane says a config is
    staged and nothing has been analysed -- never a loading state, because
    nothing is running.
    """
    assert rendered["scanDisabled"] is False
    text = rendered["findingsAfterLoad"]["text"].lower()
    assert "nothing analysed yet" in text
    assert "scan now" in text


def test_the_message_says_invented_data_and_a_real_scan(rendered):
    """Either half alone misleads, and the message asserted is the SERVER'S.

    The harness extracts this sentence from web/main.py rather than carrying
    a copy. The first draft carried a copy, and it was a plausible invention
    that did not match the real one -- so this test passed while asserting
    two words the server has never sent. A harness compared to its own
    fixture is the failure this project keeps finding in other people's
    tests; it is worth recording that it also happened in mine.

    "Invented" alone undersells it: a visitor could assume the findings are
    canned too, which is the opposite of the truth. "Real scan" alone is
    the #352 problem.
    """
    message = rendered["uploadMessage"]["text"].lower()
    assert "invented" in message
    assert "not a real device" in message
    assert "the scan is real" in message


# --- the label ----------------------------------------------------------------


def test_the_banner_is_hidden_until_the_sample_is_loaded(rendered):
    """It must not label a screen that is not showing the sample."""
    assert rendered["bannerBefore"]["hidden"] is True


def test_loading_the_sample_reveals_the_banner(rendered):
    assert rendered["bannerAfter"]["hidden"] is False


def test_the_banner_comes_back_down(rendered):
    """A MISLABEL IN THE REASSURING DIRECTION IS STILL A MISLABEL.

    Leaving "this is not your data" over somebody's real network invites them
    to disregard true findings about it. Same reasoning as the server
    clearing its marker on a real upload, pinned in test_sample_endpoint.py.
    """
    assert rendered["bannerCleared"]["hidden"] is True


def test_the_banner_says_in_WORDS_what_it_means(rendered):
    """Read from the markup, because the harness DOM carries no page text.

    The harness can prove the banner is revealed and hidden; it cannot prove
    it says anything, since its nodes are built empty. That half is asserted
    against index.html directly -- otherwise a banner emptied of its sentence
    would pass every test above while labelling nothing.
    """
    markup = INDEX.read_text(encoding="utf-8")
    banner = markup[markup.index('id="sample-banner"'):]
    banner = banner[: banner.index("</p>")].lower()

    assert "sample network" in banner
    assert "not your data" in banner
    assert "invented" in banner
