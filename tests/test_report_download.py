"""The report download control must not offer a report of nothing (#222).

WHAT THIS PROTECTS
    The control is two anchors the browser follows natively -- no fetch, no
    Blob. That is the right design, but it means the ONLY thing between an
    unavailable state and a real download is a click handler calling
    preventDefault(). An anchor has no `disabled` attribute, so a link that
    merely LOOKS greyed still downloads.

    The state it guards is not cosmetic. After an upload but before Scan
    Now, the findings pane is deliberately empty (#82, so a staged file is
    never confused with a checked one). Following the link there starts a
    real Batfish analysis nobody asked for and returns a report describing
    results the screen has never shown.

WHY PYTHON ALONE CANNOT CATCH IT
    `GET /api/report` is correct in every case -- #233 tests it thoroughly.
    Only `web/static/app.js` decides whether the link is followable, so the
    server suite passes either way.

HOW
    A Node harness loads the REAL web/static/app.js into a DOM shim and
    drives it through every state: boot, first render, cleared, rescan,
    failed load, empty result. Skips if Node is genuinely absent.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "report_download_harness.js"
STATIC = Path(__file__).parent.parent / "web" / "static"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the report download harness needs it",
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
# Availability -- the states where there IS something to export
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize(
    "case", ["afterSuccessfulRender", "afterRescan", "afterEmptyResult"]
)
def test_the_links_are_available_once_findings_are_on_screen(rendered, case):
    assert rendered[case]["ariaDisabled"] == ["false", "false"]


@needs_node
def test_an_empty_but_successful_result_is_still_exportable(rendered):
    """"We checked and found nothing" is a real result, not an absence of
    one. It renders as three zero tiles, and a report of it is a report
    somebody may need to hand to whoever asked."""
    assert rendered["afterEmptyResult"]["ariaDisabled"] == ["false", "false"]


@needs_node
@pytest.mark.parametrize("fmt", ["html", "csv"])
def test_an_available_link_is_allowed_to_navigate(rendered, fmt):
    """The download is the browser's. The handler must get out of its way."""
    assert rendered["clickWhenAvailable"][fmt]["prevented"] is False


# ---------------------------------------------------------------------------
# Unavailability -- the states where there is NOT
# ---------------------------------------------------------------------------


@needs_node
def test_the_links_start_unavailable_before_the_first_render(rendered):
    """app.js calls loadFindings() at boot but does not await it, so there is
    a real window -- a few hundred milliseconds -- before anything is on
    screen. A control that is briefly live in that window is a control that
    can be clicked before there is anything to export."""
    assert rendered["atBoot"]["ariaDisabled"] == ["true", "true"]


@needs_node
def test_clearing_the_results_makes_the_links_unavailable(rendered):
    """The state this control exists for. A staged-but-unscanned config is
    exactly when a report would be most misleading."""
    assert rendered["afterClear"]["ariaDisabled"] == ["true", "true"]


@needs_node
def test_a_failed_load_makes_the_links_unavailable(rendered):
    """loadFindings()' own notice says "no analysis has been shown". An
    available Download beside that sentence contradicts it."""
    assert rendered["afterFailedLoad"]["ariaDisabled"] == ["true", "true"]


@needs_node
@pytest.mark.parametrize("fmt", ["html", "csv"])
def test_an_unavailable_link_cannot_navigate(rendered, fmt):
    """THE assertion in this file.

    An anchor has no `disabled` attribute. Without preventDefault() the link
    looks greyed and downloads anyway, which is worse than either honest
    state -- the user is told no and gets a file.
    """
    assert rendered["clickWhenUnavailable"][fmt]["prevented"] is True


# ---------------------------------------------------------------------------
# The URLs are #233's contract
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize("case", ["atBoot", "afterSuccessfulRender", "afterClear"])
def test_the_hrefs_are_the_documented_endpoint_in_every_state(rendered, case):
    """If either href drifts, the server answers 400 with a message about
    valid formats and the user sees a failed download with no explanation.

    Asserted in several states because nothing in app.js should ever rewrite
    them -- availability changes an attribute, never the destination.
    """
    assert rendered[case]["hrefs"] == [
        "/api/report?format=html",
        "/api/report?format=csv",
    ]


def test_the_markup_ships_the_documented_urls_and_starts_unavailable():
    """The harness seeds these, so it cannot notice index.html drifting.

    Read the real file instead -- otherwise the suite would pass over a page
    whose links point somewhere else, or which ship available and are only
    disabled once JavaScript runs.
    """
    html = (STATIC / "index.html").read_text(encoding="utf-8")

    for fmt in ("html", "csv"):
        block = re.search(
            rf'<a\s[^>]*id="report-{fmt}"(.*?)>', html, re.DOTALL
        )
        assert block, f"no #report-{fmt} anchor in index.html"
        assert f'href="/api/report?format={fmt}"' in block.group(0)
        assert 'aria-disabled="true"' in block.group(0), (
            "the links must ship unavailable, not become so once JS runs"
        )


def test_no_download_attribute_so_the_server_names_the_file():
    """#233 stamps the filename with a timestamp
    (netwise-report-YYYYMMDD-HHMM.html). A bare `download` attribute lets the
    browser prefer its own guess, and two reports taken minutes apart would
    then collide."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    anchors = re.findall(r"<a\s[^>]*id=\"report-(?:html|csv)\".*?>", html, re.DOTALL)

    assert len(anchors) == 2
    for anchor in anchors:
        assert " download" not in anchor


# ---------------------------------------------------------------------------
# The hint explains the state rather than leaving a puzzle
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize(
    "case, expected",
    [
        ("atBoot", "run a scan first"),
        ("afterClear", "Scan Now"),
        ("afterFailedLoad", "could not be loaded"),
        ("afterSuccessfulRender", "Downloads what is shown above"),
    ],
)
def test_the_hint_says_why(rendered, case, expected):
    """A greyed control with no explanation is a puzzle -- the same reasoning
    as the disabled Scan Now button whose colour this borrows."""
    assert expected in rendered[case]["hint"]


@needs_node
def test_the_available_hint_does_not_promise_more_than_the_report_gives(rendered):
    """The report may describe mock findings -- #233 serves them deliberately
    before any upload, labelled "example findings (no upload yet)". The hint
    points at the server's own labelling rather than asserting the contents
    are a real scan."""
    hint = rendered["afterSuccessfulRender"]["hint"]

    assert "what is shown above" in hint
    assert "states what it describes" in hint


# ---------------------------------------------------------------------------
# The styling the state depends on exists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "selector", [".report-download", ".report-link", ".report-download-label"]
)
def test_the_control_has_real_css_rules(selector):
    """A class the stylesheet does not define renders as unstyled text, so
    the unavailable state would be invisible while every DOM assertion
    above still passed.

    Matches the selector and its brace: a substring check would also be
    satisfied by `.report-link-REMOVED`, which is how an equivalent test
    elsewhere in this suite was caught being fooled.
    """
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    assert re.search(rf"^{re.escape(selector)}\s*[,{{]", css, re.MULTILINE), (
        f"{selector} is not defined as a rule in style.css"
    )


def test_the_unavailable_state_is_styled_off_aria_disabled():
    """Anchors have no :disabled pseudo-class, so the greying must hang off
    the attribute app.js actually sets. If these disagree, the control
    changes behaviour without changing appearance -- the worst pairing."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")

    assert '.report-link[aria-disabled="true"]' in css
