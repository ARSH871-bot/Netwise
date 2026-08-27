"""The dashboard must not show a silent success for an unusable entry (#87).

THE ONE PROPERTY THIS FILE EXISTS FOR
    `POST /api/business-context` returns 200 with `accepted: true` even when
    some entries cannot affect anything -- a subnet entry matches no device
    name, because deciding whether 10.10.10.0/24 IS rtr-us5 needs interface
    enumeration this project does not have.

    The server already refuses to be silent about that: `unusable_entries()`
    names each one, and the endpoint returns them. All of that honesty is
    thrown away if the pane renders a plain green "accepted", because the
    user then reads success, sees no severity move, and concludes their
    context was applied. That is the exact silent failure the whole feature
    was built to avoid, re-created one layer up.

    So an accepted context with unusable entries is AMBER and names them.
    Amber is what a "could not check" finding already wears, for the same
    reason: nothing failed, and you still need to know.

WHY PYTHON CANNOT CATCH THIS
    The endpoint's JSON is correct in every case. Only `app.js` decides what
    colour it wears and whether the notes are rendered at all, so every
    server-side test passes while the dashboard misleads.

HOW
    A Node harness loads the REAL web/static/app.js into a small DOM shim and
    drives the change handler against a scripted server. No jsdom, no npm, no
    browser -- see tests/js/business_context_upload_harness.js. Skips if Node
    is genuinely absent rather than failing.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "business_context_upload_harness.js"

STAGED_NOTICE = "notice staged"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the business-context harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    """Drive every case through the real handler once, and share it."""
    result = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"harness failed (exit {result.returncode}):\n{result.stderr}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# THE SAFETY PROPERTY: an unusable entry is never a silent success
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize("case", ["oneUnusable", "twoUnusable", "allUnusable"])
def test_an_accepted_context_with_unusable_entries_is_amber_not_green(
    rendered, case
):
    """The single most important assertion in this file.

    `ok` here would be a green banner over a live gap. The response was a
    200 and `accepted: true`, so nothing but this decision separates "your
    whole file is working" from "part of your file does nothing".
    """
    result = rendered[case]

    assert "warn" in result["messageClass"], result["messageClass"]
    assert "ok" not in result["messageClass"], (
        "an accepted context with entries that cannot apply must not wear "
        "the same green as one where everything applied"
    )


@needs_node
@pytest.mark.parametrize(
    "case, expected_notes",
    [("oneUnusable", 1), ("twoUnusable", 2), ("allUnusable", 1)],
)
def test_every_unusable_entry_is_named_on_screen(rendered, case, expected_notes):
    """Not a count, not a summary -- each entry, in the server's own words.

    "2 entries did not apply" sends the user hunting through their file.
    The server's note already says which entry and why; summarising it here
    would discard the part that makes it fixable.
    """
    notes = [c for c in rendered[case]["noteClasses"] if c == "unusable-note"]

    assert len(notes) == expected_notes


@needs_node
def test_the_notes_carry_a_heading_saying_what_they_collectively_mean(rendered):
    """Without it, three notes read as three separate oddities rather than
    as "part of your file did nothing"."""
    result = rendered["twoUnusable"]

    assert result["noteClasses"][0] == "unusable-heading"
    assert "did not apply" in result["noteTexts"][0]
    assert "2 entries" in result["noteTexts"][0]


@needs_node
def test_the_heading_is_singular_for_one_entry(rendered):
    assert "1 entry was accepted" in rendered["oneUnusable"]["noteTexts"][0]


@needs_node
def test_the_note_text_is_the_servers_own_words(rendered):
    """Rewording here would let the API and the dashboard start disagreeing
    about why an entry did nothing."""
    note = rendered["oneUnusable"]["noteTexts"][1]

    assert "Finance VLAN" in note
    assert "device name only" in note


@needs_node
def test_a_context_where_every_entry_applies_is_green_with_no_notes(rendered):
    """The other direction. Amber on a fully-working file would train the
    user to ignore amber, which costs exactly the case above."""
    result = rendered["allUsable"]

    assert "ok" in result["messageClass"]
    assert "warn" not in result["messageClass"]
    assert result["noteClasses"] == []


@needs_node
def test_an_empty_context_is_green_rather_than_a_warning(rendered):
    """Saying nothing about any asset is a valid choice, not a problem --
    the loader treats it that way and so must the pane."""
    result = rendered["emptyContext"]

    assert "ok" in result["messageClass"]
    assert result["noteClasses"] == []


# ---------------------------------------------------------------------------
# Rejection
# ---------------------------------------------------------------------------


@needs_node
def test_a_rejected_context_is_red_and_shows_the_loaders_message(rendered):
    result = rendered["rejected"]

    assert "bad" in result["messageClass"]
    assert "did you mean 'critical'" in result["message"]


@needs_node
def test_a_rejected_context_does_not_clear_the_findings(rendered):
    """Nothing changed, so nothing on screen became stale. Throwing away a
    working analysis because a new file failed to parse would punish the
    user for the error they were just told about."""
    result = rendered["rejected"]

    assert result["findingsCount"] == 2
    assert result["summaryCount"] == 1
    assert result["noticeClass"] != STAGED_NOTICE


@needs_node
def test_a_non_json_file_never_reaches_the_server(rendered):
    """A courtesy check, but it must not post: the server would reject it
    anyway, and a round trip to be told what the browser already knew is a
    worse experience for no gain."""
    result = rendered["wrongExtension"]

    assert result["postCount"] == 0
    assert "bad" in result["messageClass"]
    assert result["findingsCount"] == 2, "nothing was staged, nothing is stale"


@needs_node
def test_a_rejected_context_clears_the_picker(rendered):
    """So the control does not still name a file the server refused."""
    assert rendered["rejected"]["contextInputValue"] == ""
    assert rendered["wrongExtension"]["contextInputValue"] == ""


# ---------------------------------------------------------------------------
# Stale findings, in both directions
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize("case", ["allUsable", "oneUnusable", "emptyContext"])
def test_an_accepted_context_clears_the_previous_findings(rendered, case):
    """Whatever was on screen was scored WITHOUT this context, so it is
    exactly as stale as it would be after a new policy."""
    result = rendered[case]

    assert result["findingsCount"] == 1
    assert result["summaryCount"] == 0
    assert result["noticeClass"] == STAGED_NOTICE
    assert "scored without it" in result["noticeText"]


@needs_node
def test_the_replacement_is_a_notice_not_a_loading_state(rendered):
    """Nothing is running. Saying otherwise is the same false claim in the
    other direction -- #82's argument."""
    assert "Scan Now" in rendered["allUsable"]["noticeText"]


# ---------------------------------------------------------------------------
# Bidirectional clearing: a config upload clears the context, visibly
# ---------------------------------------------------------------------------


@needs_node
def test_a_config_upload_says_the_context_was_cleared(rendered):
    """Silence here is worse than for the policy. A cleared policy makes
    checks report "could not check"; a cleared context makes a severity
    quietly drop back one level with nothing on screen to explain it."""
    result = rendered["configClears"]

    assert "warn" in result["messageClass"]
    assert "cleared" in result["message"]
    assert "previous config" in result["message"]


@needs_node
def test_the_clearing_message_is_amber_not_red(rendered):
    """Nothing failed. Red would report a failure that did not happen, and
    green would invite the user past a file of theirs being discarded."""
    result = rendered["configClears"]

    assert "warn" in result["messageClass"]
    assert "bad" not in result["messageClass"]
    assert "ok" not in result["messageClass"]


@needs_node
def test_the_config_upload_resets_the_context_picker(rendered):
    """So the control does not still name a file the server has discarded.

    The harness seeds the picker before every case, and that is what makes
    this test mean anything: a mutation removing the reset survived until it
    did, because the input was already "" from an earlier case and "was it
    cleared" gave the same answer as "was it ever set".
    """
    assert rendered["configClears"]["contextInputValue"] == ""


@needs_node
def test_a_config_upload_that_cleared_nothing_leaves_the_picker_alone(rendered):
    """The other half of the pair. Blanking the picker unconditionally would
    discard the user's own selection on every config upload, and would make
    the test above pass for a reason unrelated to clearing."""
    assert rendered["configNothingStaged"]["contextInputValue"] == "seeded.json"


@needs_node
def test_a_config_upload_with_no_staged_context_says_nothing(rendered):
    """An unconditional message would report a clearing that never happened,
    and train the user to ignore the one that matters."""
    result = rendered["configNothingStaged"]

    assert result["message"] == ""
    assert result["messageClass"] == ""


# ---------------------------------------------------------------------------
# The notes quote the user's own file, which is untrusted input
# ---------------------------------------------------------------------------


@needs_node
def test_a_note_containing_markup_is_rendered_as_text(rendered):
    """These strings quote the user's own file back at them, arriving by a
    path that looks like our own text. textContent, never innerHTML -- the
    same rule the findings list already holds."""
    result = rendered["scriptedNote"]

    assert result["noteClasses"] == ["unusable-heading", "unusable-note"]
    # Present as literal text in the node, never parsed into an element.
    assert "<img src=x onerror=alert(1)>" in result["noteTexts"][1]


# ---------------------------------------------------------------------------
# The markup the handler depends on actually exists
# ---------------------------------------------------------------------------


def test_the_picker_and_message_element_exist_in_the_page():
    """The harness invents any element it is asked for, so it cannot notice
    a missing one -- exactly the gap that would ship a handler wired to
    nothing. Read the real HTML instead."""
    html = (
        Path(__file__).parent.parent / "web" / "static" / "index.html"
    ).read_text(encoding="utf-8")

    assert 'id="business-context-input"' in html
    assert 'id="business-context-message"' in html
    assert 'accept=".json"' in html


@pytest.mark.parametrize("selector", [".unusable-heading", ".unusable-note"])
def test_the_unusable_styles_exist_as_real_rules(selector):
    """A class the CSS does not define renders as ordinary text, so the
    warning would be invisible while every DOM assertion above still passed.

    MATCHES THE SELECTOR AND ITS BRACE, NOT A SUBSTRING.
        Written first as `".unusable-heading" in css`, and a mutation
        renaming the rule to `.unusable-heading-REMOVED` survived it -- the
        renamed selector still CONTAINS the original. The test would have
        passed against a stylesheet where the class did not exist at all,
        which is precisely the invisible-warning case it was written for.
    """
    css = (
        Path(__file__).parent.parent / "web" / "static" / "style.css"
    ).read_text(encoding="utf-8")

    assert re.search(rf"^{re.escape(selector)}\s*\{{", css, re.MULTILINE), (
        f"{selector} is not defined as a rule in style.css"
    )


def test_the_unusable_styles_use_the_amber_family():
    """The same tokens a "could not check" finding wears. Soft grey would
    file a live gap under the same heading as a spelling correction."""
    css = (
        Path(__file__).parent.parent / "web" / "static" / "style.css"
    ).read_text(encoding="utf-8")

    block = re.search(
        r"^\.unusable-note\s*\{(.*?)\}", css, re.MULTILINE | re.DOTALL
    )
    assert block, ".unusable-note rule not found"
    assert "--blind" in block.group(1)
