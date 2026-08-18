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
