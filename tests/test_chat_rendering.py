"""The chat pane must never render a refusal as if it were an answer (US-11).

WHAT THIS PROTECTS
    `web/static/app.js` decides, from one `/api/ask` response, whether to show
    a normal reply or an amber refusal. The test is `grounded !== true`, NOT
    `=== false`, so that a missing or malformed key lands on the cautious side.

    That is a one-character difference with a real consequence: `=== false`
    would let a backend bug -- a typo'd key, a null, a JSON `"true"` string --
    silently render "we do not know" as a confident claim about someone's
    network. It is the same failure F-4 exists to prevent, arriving through the
    chat pane instead of the findings list.

    Nothing enforced it until this file. Every test in the project passed
    before and after flipping that operator.

HOW
    A Node harness (`tests/js/chat_render_harness.js`) loads the REAL app.js
    into a small DOM shim and calls the REAL addResponse(), then reports which
    classes each response produced. No jsdom, no npm install, no browser: the
    shim is about forty lines and Node ships on ubuntu-latest, so this runs in
    CI unchanged and keeps the suite's "needs neither Batfish nor Docker"
    property.

    If Node is genuinely absent the tests skip rather than fail -- a missing
    runtime is not a broken frontend, and pretending otherwise would make the
    suite lie in the direction this project cares about least.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "chat_render_harness.js"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the chat-rendering harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    """Run every case through the real addResponse() once, and share it."""
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


# ---------------------------------------------------------------------------
# 1. A real answer renders as a real answer
# ---------------------------------------------------------------------------


@needs_node
def test_grounded_true_is_not_styled_as_a_refusal(rendered):
    case = rendered["grounded_true"]
    assert case["isRefusal"] is False
    assert case["messageClass"] == "message system"


@needs_node
def test_grounded_true_shows_the_question_it_understood(rendered):
    """The box is the whole safety argument for a closed intent set -- see
    CLAUDE.md §7c. An answer that arrives without it cannot be checked by the
    person who asked."""
    case = rendered["grounded_true"]
    assert case["understoodShown"] is True
    assert case["understoodText"] == "Can rtr-us5 reach 10.20.0.5?"


# ---------------------------------------------------------------------------
# 2. A refusal renders as a refusal
# ---------------------------------------------------------------------------


@needs_node
def test_grounded_false_is_styled_as_a_refusal(rendered):
    case = rendered["grounded_false"]
    assert case["isRefusal"] is True
    assert "refusal" in case["messageClass"]


@needs_node
def test_refusal_with_no_query_shows_no_understood_box(rendered):
    """question_understood is null when nothing was translated. Showing an
    empty or invented box there would claim a query ran when none did."""
    case = rendered["grounded_false"]
    assert case["understoodShown"] is False
    assert case["understoodText"] is None


@needs_node
def test_a_query_that_ran_and_failed_keeps_its_understood_box(rendered):
    """The other refusal shape: the question WAS translated, then the check
    could not run. Both the box and the amber styling belong here -- dropping
    the box would hide which query failed."""
    case = rendered["refused_after_translation"]
    assert case["isRefusal"] is True
    assert case["understoodShown"] is True


# ---------------------------------------------------------------------------
# 3. The cautious default -- the actual point of this file
# ---------------------------------------------------------------------------


@needs_node
@pytest.mark.parametrize(
    "case_name",
    [
        "grounded_missing",       # key absent entirely
        "grounded_null",          # present but null
        "grounded_string_true",   # the STRING "true", not the boolean
        "grounded_one",           # truthy, but not `true`
    ],
)
def test_anything_other_than_true_renders_as_a_refusal(rendered, case_name):
    """Every one of these carries a confident-sounding answer string. None of
    them may be shown as a confident answer.

    `grounded_string_true` and `grounded_one` are the cases that would slip
    through a truthiness check (`if (result.grounded)`), and `grounded_missing`
    and `grounded_null` are the cases that would slip through `=== false`.
    Together they pin the operator to `!== true` from both sides.
    """
    case = rendered[case_name]
    assert case["isRefusal"] is True, (
        f"{case_name}: grounded was not exactly true, so this must render as a "
        f"refusal, but it rendered as {case['messageClass']!r}"
    )
