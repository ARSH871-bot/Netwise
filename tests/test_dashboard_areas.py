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
    assert 'id="results-explainer"' in HTML, "the explainer is gone"

    explainer = HTML[HTML.index('id="results-explainer"'):]
    explainer = explainer[:explainer.index("</p>")]
    # Collapse whitespace and drop tags before matching. The source wraps at
    # 79 columns and puts <strong> mid-phrase, so "checked, nothing found"
    # appears as "checked, nothing\n          found</strong>" -- a substring
    # check against the raw file fails on formatting rather than on content,
    # which is a test failing for a reason that has nothing to do with what
    # it is testing.
    explainer = re.sub(r"<[^>]+>", "", explainer)
    explainer = " ".join(explainer.split()).lower()

    # WHAT IS PINNED IS THE CLAIM, NOT THE SENTENCE.
    #
    # This asserted the exact string "Three separate counts, not one total."
    # until #288 improved that wording to "Three independent counts. They are
    # not shares of one total and do not need to add up." -- which answers a
    # question the original did not, and which my test would have blocked.
    #
    # Pinning a literal copy of prose is the same mistake as #194 (a guard
    # matched a wording; rewording it silently stopped the guard matching) and
    # #205 (a test held a copy of that wording and kept passing while proving
    # nothing). A test that forbids an improvement is worse than no test.
    #
    # So: the three states must be named and the "not a pass" claim must be
    # made. How they are phrased is the author's, and should be.
    for claim in ("problems found", "nothing found", "could not check"):
        assert claim in explainer, f"the explainer stopped naming {claim!r}"

    assert "not a pass" in explainer, (
        "the explainer must still say a could-not-check is not a pass -- that "
        "is the F-4 distinction, not a turn of phrase"
    )


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


# ---------------------------------------------------------------------------
# The outer columns are layout, not landmarks (raised by @ARSH871-bot on #284)
# ---------------------------------------------------------------------------

#: index.html with comments stripped. Every check below must run against this
#: rather than the raw file: the first version of this check matched markup
#: QUOTED INSIDE A COMMENT explaining the old structure, and reported a
#: problem that did not exist. Same shape as the colour test above failing on
#: "#279" in its own header -- a false positive is still a broken test, and
#: this file has now produced two.
HTML_NO_COMMENTS = re.sub(r"<!--.*?-->", "", HTML, flags=re.S)


def test_the_only_sections_are_the_four_areas():
    """The columns must not be landmarks competing with the areas.

    They were `<section aria-labelledby="results-heading">` and
    `<section aria-labelledby="chat-heading">`, so a screen reader heard an
    outer region called "Scan results" that also contained Configure, and one
    called "Ask a question" that also contained Propose a change.

    The ids resolved, so nothing was broken -- the LABELS were wrong for what
    they wrapped. That mattered more in #284 than before it: the whole claim
    of that change is that the four areas are the real boundaries, and a
    parent labelled as one of its children contradicts it in exactly the
    place the change is meant to fix.
    """
    assert HTML_NO_COMMENTS.count("<section") == len(AREAS), (
        "there should be exactly one <section> per area; the columns are "
        "plain <div> containers"
    )


@pytest.mark.parametrize("column", ["pane-results", "pane-chat"])
def test_the_columns_are_divs_not_sections(column):
    assert f'<div class="pane {column}">' in HTML_NO_COMMENTS


def test_every_aria_label_points_inside_its_own_element():
    """A label naming something outside the thing it labels is the bug above.

    Checked structurally rather than by listing the four known-good pairs, so
    a fifth area added later is covered on the day it lands.
    """
    ids = set(re.findall(r'id="([^"]+)"', HTML_NO_COMMENTS))
    for match in re.finditer(r"<(\w+)[^>]*aria-labelledby=\"([^\"]+)\"[^>]*>", HTML_NO_COMMENTS):
        tag, target = match.group(1), match.group(2)
        assert target in ids, f"aria-labelledby={target!r} points at nothing"

        start, depth, end = match.end(), 1, len(HTML_NO_COMMENTS)
        for inner in re.finditer(rf"</?{tag}\b", HTML_NO_COMMENTS[start:]):
            depth += -1 if inner.group(0).startswith("</") else 1
            if depth == 0:
                end = start + inner.start()
                break

        assert f'id="{target}"' in HTML_NO_COMMENTS[start:end], (
            f"<{tag}> is labelled by {target!r}, which is not inside it"
        )
