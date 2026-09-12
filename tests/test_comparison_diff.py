"""The propose-a-change comparison view must never conflate a status
TRANSITION with a problem appearing or disappearing (#298 review).

WHAT THIS PROTECTS
    `diffFindings()` in web/static/app.js used to split before/after findings
    into introduced/resolved/unchanged by set membership alone, with no
    regard for `status`. Two reviewers (@shubhamkataria2005, @ARSH871-bot)
    independently reproduced two concrete failures by loading the real
    app.js into a Node vm context and calling `diffFindings()` directly:

      1. A check going from clean/found to error rendered under "problems
         this change FIXES" -- going blind shown as good news.
      2. A check going from error to clean rendered under "a new problem
         this change INTRODUCES" -- a green tick shown as a new problem.

    Both are F-4 failures (found/none/error conflated) in the one view whose
    entire job is to answer "is this change safe". Every existing test for
    this feature used status="found" findings exclusively -- zero none/error
    cases across tests/test_comparison_report.py, tests/test_propose_
    rendering.py and tests/test_web_comparison_report.py combined -- so
    nothing caught it. Same shape as the PF Sense/policy join CLAUDE.md
    section 11 already names: both halves tested, the join between them not.

WHY PYTHON CANNOT CATCH ANY OF IT DIRECTLY
    /api/propose/full-scan's JSON is correct in every case. Only
    web/static/app.js's diffFindings() and detectBlindTransitions() decide
    what the comparison view shows, so this has to run the real JS.

HOW
    A Node harness loads the REAL web/static/app.js into a small DOM shim
    and calls diffFindings()/detectBlindTransitions()/showComparison()
    directly against scripted before/after finding lists -- see
    tests/js/comparison_diff_harness.js. Skips if Node is genuinely absent.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "comparison_diff_harness.js"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the comparison diff harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
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
# 1. @shubhamkataria2005's case: a proposed change makes a check go blind
# ---------------------------------------------------------------------------


@needs_node
def test_a_check_going_blind_is_not_reported_as_resolved(rendered):
    case = rendered["case1GoesBlind"]
    assert case["resolvedIds"] == [], (
        "a check going from none/found to error must never appear under "
        "'resolved' -- going blind is not a fix"
    )
    assert case["introducedIds"] == [], (
        "an error sentinel must never appear under 'introduced' either -- "
        "it is not a found problem"
    )


@needs_node
def test_a_check_going_blind_is_reported_as_newly_blind(rendered):
    case = rendered["case1GoesBlind"]
    assert case["newlyBlindIds"] == ["PC-000"]
    assert case["newlySightedIds"] == []


# ---------------------------------------------------------------------------
# 2. @ARSH871-bot's case: the reverse -- a blind check becomes clean
# ---------------------------------------------------------------------------


@needs_node
def test_a_blind_check_becoming_clean_is_not_reported_as_introduced(rendered):
    case = rendered["case2BecomesClean"]
    assert case["introducedIds"] == [], (
        "a check going from error to none must never appear under "
        "'introduced' -- a green tick is not a new problem"
    )
    assert case["resolvedIds"] == []


@needs_node
def test_a_blind_check_becoming_clean_is_reported_as_newly_sighted(rendered):
    case = rendered["case2BecomesClean"]
    assert case["newlySightedIds"] == ["RT-000"]
    assert case["newlyBlindIds"] == []


# ---------------------------------------------------------------------------
# 3. Ordinary cases must still work after the fix
# ---------------------------------------------------------------------------


@needs_node
def test_a_genuinely_new_found_problem_is_still_introduced(rendered):
    case = rendered["case3NewProblem"]
    assert case["introducedIds"] == ["AC-002"]
    assert case["introducedStatuses"] == ["found"]
    assert case["newlyBlindIds"] == []
    assert case["newlySightedIds"] == []


@needs_node
def test_a_genuinely_fixed_found_problem_is_still_resolved(rendered):
    case = rendered["case4FixedProblem"]
    assert case["resolvedIds"] == ["AC-003"]
    assert case["resolvedStatuses"] == ["found"]


@needs_node
def test_an_identical_found_finding_on_both_sides_is_unchanged(rendered):
    case = rendered["noChange"]
    assert case["unchangedIds"] == ["AC-001"]
    assert case["introducedIds"] == []
    assert case["resolvedIds"] == []


@needs_node
def test_two_empty_scans_produce_no_transitions(rendered):
    case = rendered["bothEmpty"]
    assert case["introducedIds"] == []
    assert case["resolvedIds"] == []
    assert case["unchangedIds"] == []
    assert case["newlyBlindIds"] == []
    assert case["newlySightedIds"] == []


@needs_node
def test_error_becoming_found_is_not_double_reported(rendered):
    """error -> found for the SAME (check, device) is already correctly
    surfaced as 'introduced'. detectBlindTransitions() must not ALSO list it
    under newlySighted -- that would disclose the same fact twice under two
    different, differently-worded framings."""
    case = rendered["case5ErrorBecomesFound"]
    assert case["introducedIds"] == ["PC-001"]
    assert case["newlySightedIds"] == [], (
        "an error->found transition is already reported via 'introduced'; "
        "it must not also appear as 'newly sighted'"
    )
    assert case["newlyBlindIds"] == []


# ---------------------------------------------------------------------------
# 4. Rendered end to end through showComparison() -- not just the pure
#    functions in isolation. A fix that never got wired into the renderer
#    would still be caught here.
# ---------------------------------------------------------------------------


@needs_node
def test_rendered_blind_transition_shows_only_the_transition_card(rendered):
    case = rendered["renderedGoesBlind"]
    assert case["findingCards"] == ["finding blind"], (
        "only the newly-blind card should render; the unchanged found "
        "finding must not appear as a card"
    )
    assert case["blindTransitionsPresent"] == 1


@needs_node
def test_rendered_blind_transitions_block_comes_before_the_sections(rendered):
    """Shubham's review asked for this disclosure ABOVE both sections --
    pinned as an order property, not just a presence check."""
    case = rendered["renderedGoesBlind"]
    assert case["topLevelOrder"][0] == "comparison-blind-transitions"


@needs_node
def test_rendered_newly_sighted_shows_a_clean_card_not_a_found_one(rendered):
    case = rendered["renderedBecomesClean"]
    assert case["findingCards"] == ["finding clean"]
    assert "New problems this change introduces" not in case["allText"]


@needs_node
def test_rendered_ordinary_new_problem_has_no_blind_transitions_block(rendered):
    case = rendered["renderedNoTransition"]
    assert case["blindTransitionsPresent"] == 0
    assert case["findingCards"] == ["finding high"]


# ---------------------------------------------------------------------------
# 5. The disclosure must survive into the download payload itself, not just
#    the DOM (#298 review, round two, @shubhamkataria2005). The on-screen
#    fix above was necessary but not sufficient: renderComparisonDownload()
#    built its POST payload from only introduced/resolved/unchanged_count,
#    so a downloaded report of a blinding proposal read "0 new problems, 0
#    fixed" -- correct about the two buckets it knew, silent about the one
#    that matters most to a reader deciding whether to apply the change.
# ---------------------------------------------------------------------------


@needs_node
def test_download_payload_carries_the_newly_blind_transition(rendered):
    case = rendered["renderedGoesBlind"]
    assert case["downloadPayloadIds"] is not None, (
        "no findings_json input found in the rendered comparison -- the "
        "download form must exist even when the change blinds a check"
    )
    assert case["downloadPayloadIds"]["newlyBlindIds"] == ["PC-000"]
    assert case["downloadPayloadIds"]["newlySightedIds"] == []


@needs_node
def test_download_payload_carries_the_newly_sighted_transition(rendered):
    case = rendered["renderedBecomesClean"]
    assert case["downloadPayloadIds"]["newlySightedIds"] == ["RT-000"]
    assert case["downloadPayloadIds"]["newlyBlindIds"] == []


@needs_node
def test_download_payload_has_empty_transition_lists_when_there_are_none(rendered):
    case = rendered["renderedNoTransition"]
    assert case["downloadPayloadIds"]["newlyBlindIds"] == []
    assert case["downloadPayloadIds"]["newlySightedIds"] == []
