"""Netwise -- the dashboard is distinct areas, not one overloaded column (#279).

WHY THIS FILE EXISTS
    `web/static/index.html` was two flat panes. The left ran the upload card,
    Scan Now, the results heading, its F-4 explainer, three tiles, two
    download links and the findings list down one uninterrupted column; the
    right put "Ask a question" and "Propose a change" under a bare `<hr>`.

    Nothing was wrong individually. It was all visible at once with no
    hierarchy, so a first-time reader had nothing telling them what to look
    at first -- which is the layout-level version of the problem the client
    raised on 24 August about the "Findings" heading.

WHAT THESE PIN, AND WHAT THEY DO NOT
    Not appearance. There is no assertion here about colour, spacing or
    font, because those are judgement and a test that pins them just makes
    restyling expensive.

    What they pin is the STRUCTURE the reorganisation exists to create --
    one activity per area, one heading per area -- and the two pieces of
    content that must survive a layout change because they were argued for
    on other grounds: the F-4 explainer, and the absence of numbering on the
    two areas that are not a sequence.

RUN
    pytest tests/ -v
"""

import re
from pathlib import Path

import pytest

HTML = (Path(__file__).parent.parent / "web" / "static" / "index.html").read_text(encoding="utf-8")
CSS = (Path(__file__).parent.parent / "web" / "static" / "style.css").read_text(encoding="utf-8")

AREAS = ["area-configure", "area-results", "area-ask", "area-propose"]


@pytest.mark.parametrize("area_id", AREAS)
def test_each_activity_has_its_own_area(area_id):
    assert f'id="{area_id}"' in HTML, f"no section#{area_id}"


def test_every_area_has_exactly_one_heading():
    """The whole point. Two headings in one area is the thing being fixed.

    Counted across the document rather than per area, because the failure
    mode is a heading left behind after its area got one -- which is exactly
    what happened on the first pass here: "Configure" was added above an
    "Analyse a config" that already existed, and "Scan results" ended up
    twice.
    """
    headings = re.findall(r"<h2[^>]*>", HTML)
    assert len(headings) == len(AREAS), (
        f"expected one h2 per area ({len(AREAS)}), found {len(headings)}"
    )


def test_the_bare_divider_is_gone():
    """An <hr> is a line, not a boundary.

    It told a screen reader nothing about a different activity starting, and
    a hurried eye very little. A section with its own heading does both.
    """
    assert "pane-divider" not in HTML


def test_ask_and_propose_are_not_numbered():
    """STRUCTURE MUST ENCODE SOMETHING TRUE.

    Configure and Scan results are a sequence -- you cannot review results
    before you scan, so "Step 1 / Step 2" is a fact about the product.
    Asking a question and proposing a change are independent and available
    in either order. Numbering them would assert an order that does not
    exist, which is decoration wearing the costume of information.
    """
    for area_id in ("area-ask", "area-propose"):
        start = HTML.index(f'id="{area_id}"')
        head = HTML[start:start + 400]
        assert "area-step" not in head, (
            f"{area_id} carries a step number, but it is not part of a sequence"
        )


def test_the_sequence_that_is_real_is_still_numbered():
    """The other half. Removing the numbers entirely would lose a true fact."""
    for area_id in ("area-configure", "area-results"):
        start = HTML.index(f'id="{area_id}"')
        assert "area-step" in HTML[start:start + 400], f"{area_id} lost its step marker"


def test_the_f4_explainer_survives_the_reorganisation():
    """It came out of the client meeting of 24 August and is not layout.

    The three-way split is the finding contract stated in words. A layout
    change that shortened or dropped it would undo the fix the client
    himself asked for, and the paragraph is easy to lose when a column is
    broken into cards.
    """
    assert 'id="results-explainer"' in HTML
    for phrase in ("Three separate counts, not one total.",
                   "Could not check", "is not a pass"):
        assert phrase in HTML, f"the explainer lost {phrase!r}"


def test_the_results_heading_id_is_preserved_exactly_once():
    """`results-heading` is what the pane's aria-labelledby points at.

    The first pass here added a SECOND "Scan results" heading with a new id
    and left the original in place, which is both a duplicate heading and a
    dangling label.
    """
    assert HTML.count('id="results-heading"') == 1


def test_the_areas_introduce_no_new_colours():
    """The issue asked for no gradient/neon/glow.

    Stronger than that: severity, status and --ai already carry meaning, so
    a decorative use of any of them would make a heading look like a
    finding. Every value in the area rules is an existing custom property.
    """
    # Slice from the "/*" that OPENS the section, not from the text inside
    # it. The first version sliced mid-comment, so the comment was
    # unterminated and the stripper below could not match it -- the test
    # then failed on "#279" in its own header. A false positive is still a
    # broken test, and this one failed for two different reasons before it
    # was right.
    marker = CSS.index("--- Areas (#279)")
    block = CSS[CSS.rindex("/*", 0, marker):]
    code = re.sub(r"/\*.*?\*/", "", block, flags=re.S)

    assert "gradient" not in code
    assert "box-shadow" not in code
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", code), "a literal colour was introduced"
    assert not re.search(r"\brgba?\(", code), "a literal colour was introduced"
