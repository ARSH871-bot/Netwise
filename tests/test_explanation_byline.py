"""The dashboard must never label fallback text as AI-authored (#109).

WHAT THIS PROTECTS
    `explain()` degrades to `_fallback_plain_restatement()` when Ollama is
    absent -- the finding's own summary and detail concatenated. Correct and
    deliberate (#52), but no model wrote it. Until #143 nothing downstream
    could tell the two apart, and the dashboard labelled both "AI explanation".

    The byline itself is CSS, and CSS cannot read `explanation_source`. The
    ONLY thing deciding which byline a reader sees is the class
    `renderFinding()` puts on that div:

        "model"       -> "ai-explanation"           -> "AI EXPLANATION"
        anything else -> "ai-explanation fallback"  -> "PLAIN-ENGLISH SUMMARY"

    So this file guards the one line where a working-looking dashboard can
    make a false claim about who wrote the text on it. Nothing else in the
    stack can catch it: `ai/explain.py` computes the source correctly,
    `web/main.py` sends it faithfully, and the CSS is right for whichever
    class it is handed.

THE DEFAULT IS DELIBERATE
    The test is `=== "model"`, not `!== "fallback"`. A missing, misspelled or
    unexpected value therefore lands on the byline that claims LESS. The
    parametrised cases below pin that from both sides: `null`, absent,
    `"cached"`, `"Model"` and `True` are all truthy-or-absent shapes that a
    naive check would let through as AI-authored.

    Same reasoning as `grounded !== true` in the chat pane, tested in
    tests/test_chat_rendering.py.

HOW
    A Node harness loads the REAL web/static/app.js into a small DOM shim and
    reports the class. No jsdom, no npm, no browser -- see
    tests/js/explanation_byline_harness.js for why. Skips if Node is genuinely
    absent, rather than failing.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "explanation_byline_harness.js"

AI_BYLINE = "ai-explanation"
NEUTRAL_BYLINE = "ai-explanation fallback"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the byline harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    """Run every case through the real renderFinding() once, and share it."""
    result = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"harness failed (exit {result.returncode}):\n{result.stderr}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# PART 1 -- WHICH CLASS THE CARD GETS.  Every test here is @needs_node.
# ---------------------------------------------------------------------------
#
# These drive the REAL renderFinding() through a Node harness and read the
# class off the resulting DOM. They need Node, and they SKIP without it --
# which is why Part 2 below exists and deliberately does not.
#
# ---------------------------------------------------------------------------
# The two real cases
# ---------------------------------------------------------------------------


@needs_node
def test_model_output_gets_the_ai_byline(rendered):
    """The only case that earns "AI EXPLANATION"."""
    assert rendered["source_model"] == AI_BYLINE


@needs_node
def test_fallback_text_does_not_get_the_ai_byline(rendered):
    """#109 itself: deterministic text under an AI byline is the false claim."""
    assert rendered["source_fallback"] == NEUTRAL_BYLINE
    assert "fallback" in rendered["source_fallback"]


# ---------------------------------------------------------------------------
# The cautious default -- the point of the file
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize(
    "case_name",
    [
        "source_missing",      # key absent entirely
        "source_null",         # present but null
        "source_unexpected",   # a value nobody has defined yet
        "source_capitalised",  # "Model" -- right word, wrong case
        "source_true",         # truthy, but not the string
    ],
)
def test_anything_other_than_model_uses_the_neutral_byline(rendered, case_name):
    """None of these may claim a model wrote the text.

    `source_capitalised` and `source_true` would slip through a truthiness
    check; `source_missing` and `source_null` would slip through
    `!== "fallback"`. Together they pin the comparison to `=== "model"` from
    both sides.
    """
    assert rendered[case_name] == NEUTRAL_BYLINE, (
        f"{case_name}: explanation_source was not exactly \"model\", so this "
        f"must use the neutral byline, but it rendered as "
        f"{rendered[case_name]!r} -- which tells the reader a model wrote it."
    )


# ---------------------------------------------------------------------------
# The absent case, so "no byline" is not confused with "wrong byline"
# ---------------------------------------------------------------------------


@needs_node
def test_no_explanation_renders_no_block_at_all(rendered):
    """A finding with no explanation shows nothing -- not an empty AI box.

    Guards the pre-#31 behaviour staying gone: a labelled box with no content
    would promise an explanation that does not exist.
    """
    assert rendered["no_explanation"] is None


# ---------------------------------------------------------------------------
# PART 2 -- THE WORDS, not just the class.  NOTHING here needs Node.
# ---------------------------------------------------------------------------
#
# Requested by @SamikaPerera on #189, and it is worth more than a tidy-up.
# Part 1 SKIPS wherever `node` is absent, and a skipped test is
# indistinguishable from a passing one in pytest's summary line. CI installs
# Node deliberately (`actions/setup-node`, added because the runner image only
# "happened to" ship it), so Part 1 does run there -- but it asserts nothing on
# any teammate's machine without Node.
#
# These read the stylesheet as text and need nothing but Python, so they are
# the half that always runs. That is the reason to keep both halves in one
# file rather than split them: whoever touches the byline later should see the
# coverage that runs everywhere next to the coverage that does not.
#
# Everything above asserts which CSS CLASS a card gets. The words a reader
# actually sees are `content:` strings in web/static/style.css, and nothing
# asserted them.
#
# Found by mutation, on a fix that looked fully defended:
#
#     always claim the model wrote it                6 failed   caught
#     invert the fail-safe direction                 5 failed   caught
#     never apply the fallback class                 6 failed   caught
#     fallback byline says the same as the model one  474 passed  NOT CAUGHT
#
# That last mutation restores the exact defect #109 was filed about -- text
# no model wrote, under an "AI explanation" byline -- and the suite stayed
# green. The mechanism was pinned; the claim was not. Someone tidying the
# stylesheet could undo the whole issue and be told everything was fine.
#
# These read the stylesheet rather than the rendered page, because the
# ::before content never appears in the DOM the harness can see. That is a
# real limit: this asserts what the stylesheet SAYS, not what a browser
# paints. It is still the difference between the claim being pinned and not.


def _byline_content(selector: str) -> str:
    """The `content:` string of one ::before rule in style.css."""
    css = (Path(__file__).parent.parent / "web" / "static"
           / "style.css").read_text(encoding="utf-8")
    match = re.search(
        re.escape(selector) + r"\s*\{[^}]*?content:\s*\"([^\"]*)\"",
        css, re.S)
    assert match is not None, (
        f"no ::before rule with a content: string found for {selector!r}. "
        f"If the byline moved out of CSS, move this test with it -- do not "
        f"delete it, because the claim it pins is the whole of #109."
    )
    return match.group(1)


def test_the_model_byline_claims_ai_authorship():
    """The other half, so the test below cannot pass by both being neutral."""
    assert "AI" in _byline_content(".ai-explanation::before")


def test_the_fallback_byline_does_not_claim_ai_authorship():
    """#109 itself, at the level of the words rather than the class.

    `_fallback_plain_restatement()` is the finding's own summary and detail
    concatenated -- correct and grounded (#52), and written by no model. A
    byline over it that says "AI" is the product attributing authorship it
    does not have.
    """
    fallback = _byline_content(".ai-explanation.fallback::before")

    assert "AI" not in fallback, (
        f"the fallback byline reads {fallback!r}, which claims a model wrote "
        f"text that _fallback_plain_restatement() produced deterministically. "
        f"That is #109, reintroduced."
    )
    assert fallback.strip(), "the fallback block must still be labelled"


def test_the_two_bylines_are_different():
    """A distinction that renders identically is not a distinction.

    Both classes could carry honest-looking text and still say the same
    thing, which would make the class assignment above pointless.
    """
    model = _byline_content(".ai-explanation::before")
    fallback = _byline_content(".ai-explanation.fallback::before")

    assert model != fallback, (
        f"both bylines read {model!r}, so a reader cannot tell model-written "
        f"prose from deterministic text -- which is what #109 is about"
    )
