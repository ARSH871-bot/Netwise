"""The device filter must not hide a blind spot silently (#219).

WHAT THIS PROTECTS
    Filtering is a view control, and the risk it carries is not a rendering
    bug -- it is F-4. Filtering to one device hides findings about the
    others, INCLUDING `status="error"` ones. A reader who filters to
    rtr-us5, sees a green summary and forgets the selector is set has been
    shown "all clear" for a network where a check never ran.

    The summary tiles are honest about what they count. They cannot be
    honest about what is not in front of them, so the pane has to say it.

WHY PYTHON ALONE CANNOT CATCH IT
    `/api/findings` returns every finding with its `device` field, correctly,
    whatever the browser then shows. Only `web/static/app.js` decides what
    the reader sees, so the server suite passes either way.

HOW
    A Node harness loads the REAL web/static/app.js into a DOM shim and
    drives renderFindings() and the change handler. Skips if Node is absent.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "device_filter_harness.js"
STATIC = Path(__file__).parent.parent / "web" / "static"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the device filter harness needs it",
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
# THE SAFETY PROPERTY: a filter never hides a blind spot silently
# ---------------------------------------------------------------------------


@needs_node
def test_filtering_says_how_many_findings_are_hidden(rendered):
    result = rendered["filteredToUs5"]

    assert result["noticeHidden"] is False
    assert "3 finding(s) about other devices are hidden" in result["noticeText"]


@needs_node
def test_a_hidden_could_not_check_is_called_out_separately(rendered):
    """"Hidden" and "hidden and unknown" are the two claims F-4 exists to
    keep apart. A single total would let a blind spot hide inside a count of
    ordinary findings."""
    result = rendered["filteredToUs5"]

    assert "including 1 that could not be checked" in result["noticeText"]


@needs_node
def test_the_notice_is_amber_only_when_a_blind_spot_is_hidden(rendered):
    """If it were always amber the colour would come to mean "a filter is
    on" rather than "something is not known" -- the meaning it carries
    everywhere else in this stylesheet."""
    assert "blind" in rendered["filteredToUs5"]["noticeClass"]
    assert "blind" not in rendered["noBlindHidden"]["noticeClass"]
    assert "blind" not in rendered["filteredToHq"]["noticeClass"]


@needs_node
def test_a_filter_that_hides_no_blind_spot_still_says_what_it_hides(rendered):
    """Quieter, but not silent -- the reader still needs to know the list is
    not everything."""
    result = rendered["noBlindHidden"]

    assert result["noticeHidden"] is False
    assert "1 finding(s) about other devices are hidden" in result["noticeText"]
    assert "could not be checked" not in result["noticeText"]


@needs_node
def test_no_notice_when_nothing_is_filtered(rendered):
    """A permanent "0 hidden" line is noise that teaches the reader to skip
    the element -- which is the element they most need on the one occasion
    it says something."""
    for case in ("multiUnfiltered", "backToAll"):
        assert rendered[case]["noticeHidden"] is True, case
        assert rendered[case]["noticeText"] == "", case


# ---------------------------------------------------------------------------
# The filtering itself
# ---------------------------------------------------------------------------


@needs_node
def test_filtering_shows_only_that_device(rendered):
    assert rendered["filteredToUs5"]["visibleIds"] == ["AC-001", "AC-002"]
    assert rendered["filteredToHq"]["visibleIds"] == ["RT-000", "PC-001"]


@needs_node
def test_a_filtered_view_keeps_the_error_first_ordering(rendered):
    """rtr-hq has one error and one found. The error must still come first
    -- filtering is a view, and it must not reorder what F-4 ordered."""
    assert rendered["filteredToHq"]["visibleIds"][0] == "RT-000"


@needs_node
def test_going_back_to_all_devices_restores_everything(rendered):
    """The stored list is the server's, never a filtered copy -- otherwise
    each change narrows it further and "all" becomes unreachable."""
    assert sorted(rendered["backToAll"]["visibleIds"]) == sorted(
        rendered["multiUnfiltered"]["visibleIds"]
    )
    assert len(rendered["backToAll"]["visibleIds"]) == 5


@needs_node
def test_the_options_carry_counts(rendered):
    """So the reader can see where the findings are before choosing, rather
    than by trying each one."""
    labels = [o["label"] for o in rendered["multiUnfiltered"]["options"]]

    assert labels[0] == "All devices (5)"
    assert "rtr-us5 (2)" in labels
    assert "sw-lab-1 (1)" in labels


# ---------------------------------------------------------------------------
# Degrading for a single-device scan
# ---------------------------------------------------------------------------


@needs_node
def test_the_control_is_hidden_when_there_is_only_one_device(rendered):
    """A selector offering one choice cannot do anything. Hidden rather than
    disabled: a disabled control still asks the reader to work out why it
    is unusable."""
    assert rendered["singleDevice"]["rowHidden"] is True


@needs_node
def test_a_hidden_control_never_leaves_a_filter_active(rendered):
    """Found by the harness, not by reading the code.

    Filter to rtr-us5 on a multi-device scan, then rescan a single-device
    one. The device is still present so the choice was preserved -- while
    the control hid itself, because there is now only one device. That left
    an active filter with no visible way to clear it, and a "0 finding(s)
    hidden" notice explaining a control the reader cannot see.
    """
    result = rendered["singleDevice"]

    assert result["rowHidden"] is True
    assert result["selected"] == ""
    assert result["noticeHidden"] is True


@needs_node
def test_the_control_is_visible_when_there_is_a_real_choice(rendered):
    assert rendered["multiUnfiltered"]["rowHidden"] is False


# ---------------------------------------------------------------------------
# The choice across a rescan
# ---------------------------------------------------------------------------


@needs_node
def test_the_chosen_device_survives_a_rescan_that_still_has_it(rendered):
    """A rescan silently resetting to "all" would put back findings the
    reader had deliberately filtered away, without saying so."""
    result = rendered["choiceSurvivesRescan"]

    assert result["selected"] == "rtr-hq"
    assert result["visibleIds"] == ["RT-000", "PC-001"]


@needs_node
def test_the_choice_is_dropped_when_that_device_is_gone(rendered):
    """Keeping a selection that matches nothing would show an empty list
    with no explanation."""
    result = rendered["choiceDroppedWhenDeviceGone"]

    assert result["selected"] == ""
    assert len(result["visibleIds"]) == 2


# ---------------------------------------------------------------------------
# The markup and styling the behaviour depends on
# ---------------------------------------------------------------------------


def test_the_markup_ships_the_control_hidden():
    """It must start hidden rather than become hidden once JavaScript runs,
    or a single-device scan flashes a control it will never use."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")

    row = re.search(r'<div id="device-filter-row"[^>]*>', html)
    assert row, "no #device-filter-row in index.html"
    assert "hidden" in row.group(0)
    assert 'id="device-filter"' in html
    assert 'id="filter-notice"' in html


@pytest.mark.parametrize(
    "selector", [".device-filter", ".device-filter[hidden]", ".filter-notice"]
)
def test_the_control_has_real_css_rules(selector):
    """A class the stylesheet does not define renders as unstyled text.

    `.device-filter[hidden]` is listed explicitly because `display: flex`
    beats the attribute's default `display: none` -- without that rule the
    control stays visible in exactly the case it exists to disappear for,
    which is a CSS bug that looks like a JavaScript one.
    """
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    assert re.search(rf"^{re.escape(selector)}\s*[,{{]", css, re.MULTILINE), (
        f"{selector} is not defined as a rule in style.css"
    )


def test_the_blind_notice_uses_the_amber_family():
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    block = re.search(
        r"^\.filter-notice\.blind\s*\{(.*?)\}", css, re.MULTILINE | re.DOTALL
    )
    assert block, ".filter-notice.blind rule not found"
    assert "--blind" in block.group(1)
