"""The propose pane must not misrepresent a generated change (US-13/US-14).

WHAT THIS PROTECTS
    This pane shows a CONFIG LINE that Netwise generated, beside a verdict
    about what applying it would do. Three properties matter more here than
    anywhere else in the dashboard, because the output is something a person
    might paste into a real device:

    1. A REFUSAL MUST NEVER RENDER AS A LESSER SUCCESS.
       `grounded=false` means nothing ran. Styled like an answer it becomes
       "here is a fact about your network" -- F-4 arriving in this pane.

    2. A PROVED OPENING MUST BE IMPOSSIBLE TO MISS, AND MUST SURVIVE AN
       UNRELATED ERROR IN THE SAME DIFF.
       #183 made `verified` and `warning` separate booleans after review
       found a proved high-severity opening being suppressed by an unrelated
       "could not check" in the same impact list. ANDing them in the UI would
       re-create that bug one layer later, after the backend was fixed for
       it.

    3. THE GENERATED LINE MUST NEVER READ AS APPLIED.
       ai/propose.py holds the real constraint structurally -- it writes only
       to a throwaway copy that is deleted before it returns. This pane holds
       the user's belief about it.

WHY PYTHON CANNOT CATCH ANY OF IT
    /api/propose's JSON is correct in every case. Only `web/static/app.js`
    decides what it looks like, so every server-side test passes while the
    pane misleads.

HOW
    A Node harness loads the REAL web/static/app.js into a small DOM shim and
    drives addProposeResponse() against scripted responses. No jsdom, no npm,
    no browser -- see tests/js/propose_render_harness.js. Skips if Node is
    genuinely absent rather than failing.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "propose_render_harness.js"
STATIC = Path(__file__).parent.parent / "web" / "static"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the propose render harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    """Render every case through the real app.js once, and share it."""
    # encoding="utf-8" explicitly, unlike the harness fixtures beside this
    # one. Those decode with the platform default, which on Windows is
    # cp1252 -- fine while a harness happens to emit only Latin-1 text, and
    # a UnicodeDecodeError the moment it does not. This harness renders real
    # finding cards, so its output carries renderFinding()'s "⚠" icon and an
    # em dash, and it failed on exactly that before this argument existed.
    # The other harnesses are one non-ASCII character away from the same
    # break; worth fixing, but not by widening this branch.
    result = subprocess.run(
        ["node", str(HARNESS)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, (
        f"harness failed (exit {result.returncode}):\n{result.stderr}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# 1. A refusal is a refusal
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize("case", ["refused", "noUpload"])
def test_a_refusal_renders_as_a_refusal(rendered, case):
    """The same rule /api/ask already holds. `grounded=false` means nothing
    ran, which is the same claim as an amber "could not check" card."""
    result = rendered[case]

    assert result["answerClass"] == "message system refusal"


@needs_node
@pytest.mark.parametrize("case", ["refused", "noUpload"])
def test_a_refusal_shows_no_generated_line_and_no_impact(rendered, case):
    """There is nothing to show. A placeholder card would be displaying a
    change that does not exist, and an empty impact heading would imply a
    simulation ran."""
    result = rendered[case]

    assert result["proposedPresent"] == 0
    assert result["impactPresent"] == 0
    assert result["understood"] is None


@needs_node
@pytest.mark.parametrize("case", ["clean", "narrows", "warning"])
def test_a_grounded_answer_is_not_styled_as_a_refusal(rendered, case):
    """The other direction. If everything rendered as a refusal the pane
    would be useless rather than merely cautious, and the test above would
    still pass."""
    assert rendered[case]["answerClass"] == "message system"


@needs_node
@pytest.mark.parametrize("case", ["missingKeys", "junkKeys"])
def test_a_missing_or_junk_grounded_key_renders_cautiously(rendered, case):
    """`grounded !== true`, not `=== false`.

    A backend that stops sending the key, or sends "yes", must quietly stop
    claiming things -- never quietly start. Same cautious default as the
    chat pane and the explanation byline.
    """
    assert rendered[case]["answerClass"] == "message system refusal"


@needs_node
@pytest.mark.parametrize("case", ["missingKeys", "junkKeys"])
def test_a_malformed_response_still_shows_what_the_server_sent(rendered, case):
    """Under-claim on the verdict, do not hide the data.

    A real refusal carries `proposed_change: null`, so this only arises when
    a grounded response lost its key. The answer is styled cautiously AND the
    generated line is shown with its "not applied" reminder -- suppressing
    the line would be inventing a different response rather than being
    careful about this one.
    """
    assert rendered[case]["proposedPresent"] == 1
    assert "Not applied" in rendered[case]["notAppliedText"]


# ---------------------------------------------------------------------------
# 2. The warning -- the safety-critical case
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize("case", ["warning", "warningAndUnverified", "mixedImpact"])
def test_a_proved_opening_renders_a_warning(rendered, case):
    assert rendered[case]["warningPresent"] == 1
    assert "opens access" in rendered[case]["warningText"]


@needs_node
def test_the_warning_appears_before_the_answer(rendered):
    """Order is a safety property, not layout taste. "This change opens
    access" is a proved fact from the diff and belongs before the prose; a
    reader who stops after the first line must have read it."""
    order = rendered["warning"]["order"]

    assert order.index("propose-warning") < order.index("message system")


@needs_node
def test_a_proved_opening_survives_an_unrelated_error_in_the_same_diff(rendered):
    """#183's property, asserted in the UI.

    Review found a proved high-severity opening being suppressed by an
    unrelated "could not check" in the same impact list, and the fix was to
    keep `verified` and `warning` as separate booleans. ANDing them here
    would re-create that bug one layer later -- the same fact, lost in a
    different file.
    """
    result = rendered["warningAndUnverified"]

    assert result["warningPresent"] == 1, (
        "an unrelated error must never suppress a proved opening"
    )
    assert result["unverifiedPresent"] == 1, (
        "and the incompleteness must not be hidden by the warning either"
    )


@needs_node
@pytest.mark.parametrize("case", ["clean", "narrows", "unverifiedOnly"])
def test_no_warning_when_nothing_was_proved_to_open(rendered, case):
    """Crying wolf costs exactly the case above: a warning on every response
    trains the reader to skip it."""
    assert rendered[case]["warningPresent"] == 0


@needs_node
def test_an_unverified_result_says_so_after_the_answer(rendered):
    """A different claim from the warning. "Some of the analysis could not
    run" qualifies what precedes it, so it follows the answer."""
    order = rendered["unverifiedOnly"]["order"]

    assert order.index("propose-unverified") > order.index("message system")


@needs_node
def test_a_refusal_carries_no_unverified_note(rendered):
    """Nothing ran at all, and the answer says so. A second "could not
    verify" line would imply a partial result existed."""
    assert rendered["refused"]["unverifiedPresent"] == 0


@needs_node
def test_a_fully_verified_result_carries_no_unverified_note(rendered):
    assert rendered["clean"]["unverifiedPresent"] == 0
    assert rendered["warning"]["unverifiedPresent"] == 0


# ---------------------------------------------------------------------------
# 3. The generated line is generated, never applied
# ---------------------------------------------------------------------------


@needs_node
def test_the_request_understood_is_shown_first(rendered):
    """CLAUDE.md section 7c's control, and it matters more here than in the
    chat pane: a mistranslated question produces a wrong answer, while a
    mistranslated request produces a config line somebody might paste."""
    result = rendered["clean"]

    assert result["understood"].startswith("On rtr-us5, add to 'acl_in'")
    assert result["order"][0] == "understood"


@needs_node
def test_the_generated_line_shows_device_filter_and_line(rendered):
    result = rendered["clean"]

    assert result["proposedDevice"] == "rtr-us5"
    assert result["proposedFilter"] == "acl_in"
    assert result["proposedLine"] == (
        "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443"
    )


@needs_node
@pytest.mark.parametrize(
    "case", ["clean", "narrows", "warning", "warningAndUnverified", "unverifiedOnly"]
)
def test_every_generated_line_carries_the_not_applied_reminder(rendered, case):
    """Permanent and per-card, not a one-off notice at the top of the pane.

    A log with five proposals carries five reminders rather than one the
    reader passed twenty minutes ago, and the reminder cannot scroll away
    from the line it is about.
    """
    text = rendered[case]["notAppliedText"]

    assert text is not None, "a generated line with no reminder"
    assert "Not applied" in text
    assert "nothing has been written" in text.lower()


@needs_node
def test_the_reminder_names_both_things_that_were_not_written(rendered):
    """"Not applied to a device" alone would leave the user wondering
    whether their uploaded config was edited. ai/propose.py writes only to a
    throwaway copy and never to before_dir; the sentence says both."""
    text = rendered["clean"]["notAppliedText"].lower()

    assert "device" in text
    assert "config you uploaded" in text


@needs_node
def test_the_line_is_rendered_in_a_code_element(rendered):
    """It is a config line. Rendering it as prose invites a transcription
    error on the one string in this pane that must be copied exactly."""
    assert rendered["clean"]["proposedLineTag"] == "code"


# ---------------------------------------------------------------------------
# 4. The impact list reuses renderFinding()
# ---------------------------------------------------------------------------


@needs_node
def test_the_impact_list_is_built_with_the_dashboard_finding_renderer(rendered):
    """These classes are renderFinding()'s. If the impact list ever stopped
    reusing it, they would vanish -- which is the whole assertion.

    A second card builder would be two places deciding what an amber "could
    not check" card looks like, and the moment they drift one of them shows
    a blind spot as something else.
    """
    classes = rendered["mixedImpact"]["findingClasses"]

    assert classes, "no finding cards were rendered at all"
    assert all(c.startswith("finding ") for c in classes)


@needs_node
def test_the_impact_list_orders_errors_first_then_worst_first(rendered):
    """The dashboard's order, for the dashboard's reason: a check that did
    not run is the thing most likely to mislead someone reading quickly, so
    sorting by severity alone would bury it under three medium diffs."""
    assert rendered["mixedImpact"]["findingClasses"] == [
        "finding blind",
        "finding high",
        "finding medium",
        "finding clean",
    ]


@needs_node
def test_a_blind_impact_card_keeps_its_not_a_clean_result_sentence(rendered):
    """The clearest evidence that renderFinding() is genuinely being reused.

    A hand-rolled impact renderer would almost certainly have omitted this
    sentence -- it is the part of the blind card that says in words what the
    colour says in amber.
    """
    assert rendered["mixedImpact"]["blindNoteCount"] >= 1
    assert rendered["warningAndUnverified"]["blindNoteCount"] >= 1


@needs_node
def test_the_impact_section_is_headed_so_it_is_not_read_as_current_state(rendered):
    """These findings describe a SIMULATED config, not the network as it is.
    Unheaded, they would read as more dashboard findings."""
    heading = rendered["mixedImpact"]["impactHeading"]

    assert "Simulated impact" in heading
    assert "copy" in heading


@needs_node
@pytest.mark.parametrize("case", ["clean", "refused"])
def test_an_empty_impact_list_renders_no_section(rendered, case):
    """Empty happens two ways -- a refusal, and a change with no detected
    effect -- and the answer already says which. An empty headed section
    would imply a third thing happened."""
    assert rendered[case]["impactPresent"] == 0


# ---------------------------------------------------------------------------
# 5. Untrusted text
# ---------------------------------------------------------------------------


@needs_node
def test_a_device_name_containing_markup_is_rendered_as_text(rendered):
    """A device name comes from the user's own config. Every node here is
    el()-built, so textContent, never innerHTML."""
    result = rendered["scripted"]

    assert result["proposedDevice"] == "<img src=x onerror=alert(1)>"
    assert "<img src=x onerror=alert(1)>" in result["understood"]


# ---------------------------------------------------------------------------
# 6. The stub is gone, and the styles the renderer needs exist
# ---------------------------------------------------------------------------


def test_the_dead_404_stub_is_gone():
    """#183/#184 merged, so /api/propose exists and the 404 fallback is
    unreachable. Unreachable code that fabricates a plausible response is
    exactly what survives into a demo."""
    app = (STATIC / "app.js").read_text(encoding="utf-8")
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    assert "stubbedProposeResponse" not in app
    assert "system stubbed" not in app
    assert "stubbed" not in css
    assert "NOT A REAL RESULT" not in css.upper()


@pytest.mark.parametrize(
    "selector",
    [
        ".propose-warning",
        ".propose-unverified",
        ".proposed-change",
        ".proposed-line",
        ".proposed-not-applied",
        ".impact-heading",
    ],
)
def test_every_class_the_renderer_emits_is_a_real_css_rule(selector):
    """A class the stylesheet does not define renders as ordinary text, so
    the warning would be invisible while every DOM assertion above passed.

    Matches the selector AND its brace: `".propose-warning" in css` would
    also be satisfied by `.propose-warning-REMOVED`, which is how an
    equivalent test elsewhere in this suite was caught being fooled.
    """
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    assert re.search(rf"^{re.escape(selector)}\s*[,{{]", css, re.MULTILINE), (
        f"{selector} is not defined as a rule in style.css"
    )


def test_the_warning_uses_the_amber_could_not_check_family():
    """Not `.rename-note`'s soft grey. This project already made that choice
    once and got it wrong: soft italic grey is right for something we FIXED
    for the user, and files a live gap under the same heading as a spelling
    correction. A proved opening is stronger still."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    block = re.search(
        r"^\.propose-warning\s*\{(.*?)\}", css, re.MULTILINE | re.DOTALL
    )
    assert block, ".propose-warning rule not found"
    assert "--blind" in block.group(1)
    assert "rename-note" not in block.group(1)
