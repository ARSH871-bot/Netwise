"""Two findings that share an id must both appear on screen (F-4).

WHAT THIS PROTECTS
    `web/static/app.js` renders findings in list order and never keys them by
    id. That is a deliberate rule with a comment explaining it:

        "If this file keyed cards by id -- the obvious thing to do, and what a
         framework would do by default -- one of that pair would be silently
         dropped. The dropped one could be the error, leaving the user reading
         'policy compliance: all clear' with no sign that the change-impact
         check never ran."

    `policy_compliance` and `change_impact` share the `PC-` prefix and both
    number their sentinel finding 000, so a run where one is clean and the
    other errored produces two findings called `PC-000`. That collision is
    real today -- it is in `web/mock_findings.py`, which is what every user
    sees before their first upload -- and it stays until the A-2 amendment
    gives `change_impact` its own prefix (#95).

WHY THIS FILE WAS NEEDED
    The comment ended: *"The mock data keeps that collision on purpose so this
    stays tested."* **That was not true.** The mock data does preserve the
    collision, but the only Node harness drove the CHAT pane; nothing called
    `renderFindings()` at all.

    Preserving a fixture is not a test. Refactoring `render()` to a Map keyed
    by id -- the natural thing, and what any framework does by default --
    would have dropped a card and every test in the project would still have
    passed. That is this project's recurring failure family: a weaker claim
    ("the collision is in the fixture") standing in for a stronger one ("the
    rendering is checked").

HOW
    Same approach as `test_chat_rendering.py`: a Node harness loads the REAL
    `app.js` into a small DOM shim and calls the REAL `renderFindings()`. No
    jsdom, no npm install. Skips if Node is absent, because a missing runtime
    is not a broken frontend.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "findings_render_harness.js"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the findings-rendering harness needs it",
)


@pytest.fixture(scope="module")
def both():
    """Render the colliding PC-000 pair in BOTH orders, through the real app.js."""
    result = subprocess.run(
        ["node", str(HARNESS)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"harness failed (exit {result.returncode}):\n{result.stderr}"
    )
    return json.loads(result.stdout)


@pytest.fixture(params=["errorLast", "errorFirst"])
def rendered(both, request):
    """Every assertion below runs against both orderings.

    De-duplicating by id keeps the LAST value, so the ordering decides WHICH
    card disappears. Testing one order would half-catch the bug.
    """
    return both[request.param]


# ---------------------------------------------------------------------------
# The rule the comment describes
# ---------------------------------------------------------------------------


@needs_node
def test_both_findings_with_the_same_id_are_rendered(rendered):
    """The whole point. Key by id and this drops to 1."""
    assert rendered["totalCards"] == 2, (
        "two findings share the id PC-000 and both must appear. Getting 1 "
        "means the list is being keyed or de-duplicated by id, which silently "
        "hides one of them -- see the comment in web/static/app.js."
    )


@needs_node
def test_the_errored_finding_is_on_screen_and_shown_first(rendered):
    """Which card disappears matters more than that one does.

    Keying by id keeps the LAST value, so with the error FIRST it is the
    error that vanishes -- the user is told policy compliance is clean and
    never learns change impact did not run. That is F-4 arriving through the
    `id` field rather than the `status` field, and it is why this runs
    against both orderings.
    """
    headings = [s["heading"] for s in rendered["sections"]]

    assert "Could not check" in headings, (
        "the errored finding is not on screen at all"
    )
    assert headings[0] == "Could not check", (
        "a check that did not run must be shown above the results, not below "
        f"them. Got order: {headings}"
    )


@needs_node
def test_the_errored_card_says_in_words_that_it_is_not_a_clean_result(rendered):
    """Colour is a signal; a sentence cannot be misread."""
    blind = next(s for s in rendered["sections"] if s["heading"] == "Could not check")
    text = " ".join(blind["cardText"])

    assert "not a clean result" in text
    assert "change_impact" in text, "the card must name the check that failed"


@needs_node
def test_the_coverage_tiles_count_both(rendered):
    """"0 could not check" is a statement of coverage; a missing tile is not.

    If the pair were de-duplicated, one of these counts would read 0 while a
    finding of that kind existed.
    """
    tiles = {t["className"]: t["text"] for t in rendered["summaryTiles"]}

    assert "tile blind" in tiles, "the 'could not check' tile is always rendered"
    assert tiles["tile blind"].startswith("1"), tiles["tile blind"]
    assert tiles["tile clean"].startswith("1"), tiles["tile clean"]
    assert tiles["tile problems"].startswith("0"), tiles["tile problems"]


@needs_node
def test_the_harness_is_driving_the_real_file(rendered):
    """Guard against this whole file being vacuously green.

    A harness that silently rendered nothing -- a renamed function, a shim
    that swallowed appendChild -- would make the assertions above pass or
    skip without exercising anything. So require actual content.
    """
    assert rendered["sections"], "no sections were rendered at all"
    assert all(s["cardCount"] > 0 for s in rendered["sections"]), (
        "a section was rendered with no cards, which renderSection() should "
        "never produce -- the shim is probably not recording appendChild"
    )
