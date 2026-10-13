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
@pytest.mark.parametrize("case", ["warning", "warningAndUnverified", "mixedImpact"])
def test_a_warned_response_scrolls_its_own_start_into_view(rendered, case):
    """Being FIRST in the DOM is not the same as being visible.

    `.propose-log` is capped at 18rem and scrolls, and the pane used to
    scroll to the newest content like every other log here. That puts the
    END of the exchange in view -- the impact list -- while the warning,
    which is at the top, sits above the fold. On the response that most
    needs reading, the warning was the one thing off screen.

    The DOM shim has no geometry, so every "the warning comes first"
    assertion passed while this was true. It was found by rendering the
    pane in a real browser, and this test exists so it cannot come back.
    """
    assert rendered[case]["scrolledTo"] == "start"


@needs_node
@pytest.mark.parametrize("case", ["clean", "narrows", "refused"])
def test_an_unwarned_response_keeps_the_usual_scroll_to_newest(rendered, case):
    """The other direction. Hijacking the scroll on every response would be
    its own bug -- the reader loses their place for no reason."""
    result = rendered[case]

    assert result["scrolledTo"] is None
    assert result["logScrolledToBottom"] is True


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
@pytest.mark.parametrize("case", ["groundedJunkFlags", "groundedJunkWarningOnly"])
def test_a_malformed_flag_on_a_grounded_response_is_neither_warned_nor_ignored(
    rendered, case
):
    """The combination no test covered until a mutation survived.

    Both malformed cases above also had a malformed `grounded`, so they
    rendered as refusals and never reached the warning logic at all -- which
    meant mutations to BOTH flag defaults were invisible.

    With `grounded` exactly true and a flag that is not a boolean, neither
    obvious lean is right. Silence implicitly claims "this does not open
    access", which is F-4 in a boolean: "could not determine" is not
    "determined to be fine". Warning on anything non-false fires on every
    malformed response, and a warning that always appears is one the reader
    learns to skip.

    So it is reported as what it is: a result that could not be fully
    verified.
    """
    result = rendered[case]

    assert result["warningPresent"] == 0, "a junk flag must not cry wolf"
    assert result["unverifiedPresent"] == 1, (
        "and must not be read as a clean result either"
    )


@needs_node
def test_a_junk_warning_alone_still_reports_the_result_as_unverified(rendered):
    """`verified` is exactly true here and only `warning` is junk.

    Without the flags-usable term this renders as a fully verified result
    while having no idea whether the change opens access -- the more
    dangerous of the two, and the one that distinguishes the guard from a
    simple `verified !== true`.
    """
    assert rendered["groundedJunkWarningOnly"]["unverifiedPresent"] == 1


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
# 5a. The before/after diff and the download form (strengthening propose)
# ---------------------------------------------------------------------------


def test_the_diff_shows_every_line_with_the_new_one_marked(rendered):
    result = rendered["cleanWithDownload"]

    assert result["aclDiffPresent"] == 1
    assert result["aclDiffAddedLines"] == [
        "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443"
    ]
    # Both original lines still shown -- a diff that only shows the new line
    # is the single-line view this feature exists to replace.
    assert "permit udp any any eq domain" in result["aclDiffAllLines"]
    assert "permit tcp any host 10.20.0.5 eq 443" in result["aclDiffAllLines"]


def test_the_diff_appears_even_with_no_request_text_to_resubmit(rendered):
    """before_lines/after_lines and the download form are two independent
    pieces of data -- a caller that has one is not guaranteed the other, and
    the diff must not silently depend on the download form's presence."""
    result = rendered["cleanNoRequestText"]
    assert result["aclDiffPresent"] == 1


def test_a_refusal_shows_no_diff_at_all(rendered):
    """proposed_change is null on a refusal, so there is nothing to diff --
    confirmed rather than assumed, the same discipline the rest of this file
    applies to every other element."""
    for case in ("refused", "noUpload"):
        assert rendered[case]["aclDiffPresent"] == 0


def test_the_download_form_appears_only_when_a_request_was_given(rendered):
    assert rendered["cleanWithDownload"]["downloadFormPresent"] == 1
    assert rendered["cleanNoRequestText"]["downloadFormPresent"] == 0


def test_the_download_form_carries_the_exact_request_that_was_asked(rendered):
    result = rendered["cleanWithDownload"]
    assert (
        result["downloadFormRequestValue"]
        == "block 10.10.10.5 to 10.20.0.5 on tcp/443 on rtr-us5"
    )


def test_a_refusal_never_grows_a_download_form_even_with_request_text(rendered):
    """The caller could pass requestText on every response, refusal or not
    -- this pins that the renderer itself is the guard, not caller
    discipline. proposed_change is null on a refusal regardless of what
    requestText holds."""
    result = rendered["refusedWithRequestText"]
    assert result["downloadFormPresent"] == 0


def test_the_full_scan_button_appears_alongside_the_download_form(rendered):
    """Tied to the same requestText guard as the download form -- there is
    nothing to resubmit to either endpoint without it."""
    assert rendered["cleanWithDownload"]["fullScanButtonPresent"] == 1
    assert rendered["cleanNoRequestText"]["fullScanButtonPresent"] == 0
    assert (
        rendered["cleanWithDownload"]["fullScanButtonText"]
        == "Run a full scan against this proposed config"
    )


def test_a_refusal_never_grows_a_full_scan_button(rendered):
    assert rendered["refusedWithRequestText"]["fullScanButtonPresent"] == 0


def test_hostile_request_text_reaches_the_hidden_field_as_literal_text(rendered):
    """The hidden input's `.value` is a DOM property assignment, not markup
    built by string concatenation -- so it cannot inject, and this proves it
    by checking the hostile string comes back byte-for-byte rather than
    executed or stripped."""
    result = rendered["scriptedDownload"]
    assert (
        result["downloadFormRequestValue"]
        == "<img src=x onerror=alert(1)> to 10.20.0.5 on tcp/443"
    )


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
        ".acl-diff",
        ".acl-diff-label",
        ".acl-diff-line",
        ".propose-download-form",
        ".propose-download-button",
        ".full-scan-button",
        ".full-scan-results",
        ".full-scan-refusal",
        ".full-scan-clean",
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


# ---------------------------------------------------------------------------
# Impact evidence ids (#255 review, Arsh + Samika)
#
# renderImpact() reuses renderFinding(), and #236 gave renderFinding() a 5th
# parameter -- evidenceId -- so an explanation can link to its own evidence
# block. renderImpact() was not updated for it when this was first written,
# so every impact card's evidence.id was `undefined`, and two impact cards on
# screen at once shared one id with two links both resolving to the same
# (wrong, for one of them) card. Fixed with a module-level, never-reset
# counter and a prefix ("impact-evidence-") distinct from the dashboard's
# ("evidence-"), specifically because the propose log accumulates exchanges
# rather than replacing them -- see the long comment on `_impactEvidenceCounter`
# in app.js for why a per-call reset would only move the collision from
# "two panes" to "two turns of the same pane".
# ---------------------------------------------------------------------------


@needs_node
def test_an_impact_evidence_block_never_gets_an_undefined_id(rendered):
    ids = rendered["turnOne"]["evidenceIds"]
    assert ids, "expected at least one evidence block in the impact list"
    assert "undefined" not in ids
    assert all(i.startswith("impact-evidence-") for i in ids)


@needs_node
def test_an_impact_evidence_link_points_at_its_own_card(rendered):
    ids = rendered["turnOne"]["evidenceIds"]
    hrefs = rendered["turnOne"]["evidenceLinkHrefs"]
    assert hrefs, "an explained impact finding must get a link"
    assert hrefs == [f"#{i}" for i in ids]


@needs_node
def test_two_propose_turns_in_one_session_never_collide(rendered):
    """The regression this design exists to prevent.

    addProposeResponse() never clears #propose-log, so a second proposal's
    cards render beside the first's, still on screen. A counter that reset
    per call -- the more obvious implementation, and what renderFindings()
    itself does -- would hand this second response's evidence block the same
    id as the first's, and a `getElementById` lookup (or a `:target` jump)
    would then land on turn one's card from turn two's link.
    """
    ids_one = rendered["turnOne"]["evidenceIds"]
    ids_two = rendered["turnTwo"]["evidenceIds"]

    assert ids_one and ids_two
    assert set(ids_one).isdisjoint(ids_two), (
        f"turn one and turn two share an evidence id: {ids_one} / {ids_two}"
    )

    # Each turn's link must still resolve to THAT turn's own card, not just
    # be non-colliding by accident.
    assert rendered["turnOne"]["evidenceLinkHrefs"] == [f"#{i}" for i in ids_one]
    assert rendered["turnTwo"]["evidenceLinkHrefs"] == [f"#{i}" for i in ids_two]


@needs_node
def test_impact_evidence_ids_cannot_collide_with_the_dashboards(rendered):
    """Distinct prefixes, not a shared counter -- so the propose pane and
    the findings pane can both be on screen without coordinating."""
    ids = rendered["turnOne"]["evidenceIds"] + rendered["turnTwo"]["evidenceIds"]
    assert all(i.startswith("impact-evidence-") for i in ids)
    assert not any(i.startswith("evidence-") and not i.startswith("impact-evidence-") for i in ids)
