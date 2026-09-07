"""The persistent, header-driven pfSense-conversion disclosure on the
dashboard (#302 review, round two, @shubhamkataria2005 and @ARSH871-bot).

WHAT THIS PROTECTS
    Before this, a pfSense conversion's skip notes reached the user exactly
    once, appended to the transient #upload-message box at upload time. A
    page reload followed by Scan Now showed clean summary tiles with no
    trace anything had been excluded -- /api/findings itself carried
    nothing about it. `updateConversionGapsNotice()` in web/static/app.js
    now reads two response headers (X-Netwise-Conversion-Gap-Count,
    X-Netwise-Conversion-Gaps-Unreadable) on EVERY /api/findings fetch and
    renders a persistent notice above the summary tiles.

    A second, independent claim is guarded here too: an unreadable skip
    record must render as its own, differently-worded state -- never as
    "0 excluded" (which would be a false claim of completeness) and never
    with the same wording as "N excluded" (which would claim to know a
    count it does not have).

WHY PYTHON CANNOT CATCH ANY OF IT DIRECTLY
    Only web/static/app.js decides what the notice says and whether it is
    visible. A Node harness loads the REAL app.js into a small DOM/fetch
    shim and drives loadFindings() end to end -- see
    tests/js/conversion_gaps_notice_harness.js. Skips if Node is absent.

RUN
    pytest tests/ -v
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "conversion_gaps_notice_harness.js"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the conversion-gaps notice harness needs it",
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


@needs_node
def test_nothing_excluded_stays_hidden(rendered):
    assert rendered["zeroCount"]["hidden"] is True


@needs_node
def test_excluded_parts_are_disclosed_persistently(rendered):
    case = rendered["twoExcluded"]
    assert case["hidden"] is False
    assert "2 parts" in case["text"]
    assert "excluded" in case["text"]


@needs_node
def test_an_unreadable_record_is_disclosed_with_its_own_wording(rendered):
    case = rendered["unreadable"]
    assert case["hidden"] is False
    assert "could not be read" in case["text"]


@needs_node
def test_an_unreadable_record_never_reads_as_a_specific_count():
    """The exact conflation this feature exists to prevent: 'unreadable'
    and 'N excluded' must never share wording, or a reader skimming the
    banner could mistake "we don't know" for a real, bounded number."""
    result = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True,
        encoding="utf-8", timeout=60,
    )
    out = json.loads(result.stdout)
    unreadable_text = out["unreadable"]["text"]
    excluded_text = out["twoExcluded"]["text"]
    assert unreadable_text != excluded_text
    assert "parts of the uploaded configuration were excluded" not in unreadable_text


@needs_node
def test_the_notice_rebuilds_fresh_on_every_fetch_not_stale(rendered):
    """The reload-then-Scan-Now case Shubham's review named directly: an
    unreadable-record disclosure must not linger once the next fetch's
    headers say there is nothing to disclose."""
    assert rendered["afterUnreadableThenClean"]["hidden"] is True


@needs_node
def test_a_failed_findings_load_clears_the_notice_rather_than_leaving_it_stale(rendered):
    assert rendered["beforeFailure"]["hidden"] is False
    assert rendered["afterFailedLoad"]["hidden"] is True


@needs_node
def test_missing_headers_degrade_to_hidden_rather_than_throwing(rendered):
    case = rendered["missingHeadersDidNotThrow"]
    assert case["threw"] is False
    assert case["state"]["hidden"] is True
