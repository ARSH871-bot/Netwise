"""Which heading each saved-scan difference goes under (#223).

Runs tests/js/history_render_harness.js, which loads the real web/static/app.js
into a DOM shim and calls the real renderComparison(). See that file for why
this is the one place the headings are enforced.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "history_render_harness.js"
FIXED = "Fixed: checked again and no longer found"
UNCONFIRMED = "Gone, but not confirmed fixed"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the history-rendering harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    # encoding explicitly: the page's text contains curly quotes, and text=True
    # alone decodes with the Windows codepage, which fails on them.
    result = subprocess.run(["node", str(HARNESS)], capture_output=True,
                            encoding="utf-8", timeout=60)
    assert result.returncode == 0, f"harness failed (exit {result.returncode}):\n{result.stderr}"
    return json.loads(result.stdout)


def _texts(case, title):
    return [row["text"] for row in case["sections"].get(title, [])]


@needs_node
def test_only_resolved_problems_are_called_fixed(rendered):
    case = rendered["every_category"]
    assert _texts(case, FIXED) == ["RESOLVED ONE (rtr-us5)"]
    assert _texts(case, UNCONFIRMED) == ["UNVERIFIED ONE (rtr-us5)"]


@needs_node
def test_an_unconfirmed_problem_says_why(rendered):
    (row,) = rendered["every_category"]["sections"][UNCONFIRMED]
    assert "could not check this" in row["reason"]


@needs_node
def test_with_nothing_resolved_there_is_no_fixed_heading_at_all(rendered):
    """The Batfish-down comparison: no 'Fixed (0)', no 'Fixed' at all."""
    case = rendered["nothing_resolved"]
    assert FIXED not in case["sections"]
    assert _texts(case, UNCONFIRMED) == ["UNVERIFIED ONE (rtr-us5)"]


@needs_node
def test_every_other_category_has_its_own_heading(rendered):
    sections = rendered["every_category"]["sections"]
    assert _texts({"sections": sections}, "New problems") == ["NEW ONE (rtr-us5)"]
    assert _texts({"sections": sections}, "Seen for the first time, but not new") == ["VISIBLE ONE (rtr-us5)"]
    assert _texts({"sections": sections}, "Checks that could not run this time") == ["routing on rtr-hq"]


@needs_node
def test_caveats_and_the_unchanged_count_are_shown(rendered):
    notes = [n["text"] for n in rendered["every_category"]["notes"]]
    assert "The policy changed between these scans." in notes
    assert "Unchanged: 2 problem(s) reported in both scans." in notes


@needs_node
def test_staging_a_new_config_clears_the_comparison(rendered):
    """It described the previous config; left on screen it would describe
    the wrong one."""
    assert rendered["after_new_config"]["comparison_children"] == 0


@needs_node
def test_a_comparison_involving_the_sample_says_so(rendered):
    notes = rendered["sample_involved"]["notes"]
    assert any(n["className"] == "history-sample" for n in notes)
    assert not any(n["className"] == "history-sample" for n in rendered["every_category"]["notes"])
