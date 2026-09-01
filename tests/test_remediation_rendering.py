"""A remediation block must show provenance honestly, or say plainly there
is none (#221).

WHAT THIS PROTECTS
    web/static/app.js decides what a remediation string looks like on
    screen; /api/findings' JSON is correct in every case regardless. A Node
    harness loads the REAL app.js and drives the REAL renderFindings() --
    same approach as test_findings_rendering.py, test_explanation_byline.py
    and friends. Skips if Node is absent rather than failing.

WHAT IS PINNED
    1. A found finding with remediation text gets a ".remediation" block,
       and it is NEVER also counted as ".ai-explanation" -- remediation is
       never model-written (web/main.py's _attach_remediation() only ever
       calls remediate_with_source(), which never touches Ollama), so it
       must never pick up the violet "AI explanation" styling meant for
       something a model produced.
    2. A found finding with no remediation says so in words
       (".no-remediation"), never silently -- the same "absence is not
       information" instinct #31 already applies to explanation.
    3. "none" and "error" findings never get either block, even if the
       (malformed, hypothetical) backend response carried a remediation
       key on one -- they were never asked for remediation and must not
       start claiming otherwise.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "remediation_render_harness.js"
STATIC = Path(__file__).parent.parent / "web" / "static"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the remediation-rendering harness needs it",
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
# A found finding with remediation text
# ---------------------------------------------------------------------------


@needs_node
def test_a_matched_finding_shows_its_remediation_text(rendered):
    blocks = rendered["withRemediation"]["remediationBlocks"]
    assert len(blocks) == 1
    assert "permit ip any any" in blocks[0]


@needs_node
def test_remediation_is_never_styled_as_an_ai_explanation(rendered):
    """Remediation is never model-written -- see the module docstring above
    for why. Picking up .ai-explanation's violet styling would misattribute
    a deterministic Python computation to the model."""
    assert rendered["withRemediation"]["aiExplanationBlocks"] == 0


# ---------------------------------------------------------------------------
# A found finding with no matching shape
# ---------------------------------------------------------------------------


@needs_node
def test_an_unmatched_finding_says_so_in_words(rendered):
    blocks = rendered["withoutRemediation"]["noRemediationBlocks"]
    assert len(blocks) == 1
    assert "No mechanical remediation is available" in blocks[0]


@needs_node
def test_an_unmatched_finding_shows_no_remediation_block(rendered):
    assert rendered["withoutRemediation"]["remediationBlocks"] == []


# ---------------------------------------------------------------------------
# "none" and "error" findings never acquire either block
# ---------------------------------------------------------------------------


@needs_node
def test_clean_and_blind_findings_never_show_remediation_even_if_the_backend_sent_it(rendered):
    """The scripted fixture deliberately sets a remediation key on a "none"
    and an "error" finding -- a malformed response, not something
    _attach_remediation() would ever actually send, but the frontend must
    stay cautious regardless of what arrives. Same discipline as
    `grounded !== true` in the chat pane: never trust a field's presence
    over the status that governs whether it should exist at all."""
    result = rendered["cleanAndBlind"]
    assert result["remediationBlocks"] == []
    assert result["noRemediationBlocks"] == []


# ---------------------------------------------------------------------------
# CSS: the classes app.js emits are real rules, and remediation keeps its
# own colour rather than borrowing --ai's.
# ---------------------------------------------------------------------------


def test_remediation_and_no_remediation_are_real_css_rules():
    """A class the stylesheet does not define renders as plain text, so the
    byline and colour distinction this feature depends on would silently
    vanish while every DOM assertion above still passed."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    import re

    for selector in (".remediation", ".no-remediation"):
        assert re.search(rf"^{re.escape(selector)}\s*[,{{]", css, re.MULTILINE), (
            f"{selector} is not defined as a rule in style.css"
        )


def test_remediation_uses_its_own_colour_not_the_ai_violet():
    """--ai is documented in style.css as a hue used by nothing else there,
    specifically so an explanation can never be misread as something else.
    Remediation must not quietly borrow it -- that would misattribute a
    deterministic computation to the model."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    import re

    block = re.search(r"^\.remediation\s*\{(.*?)\}", css, re.MULTILINE | re.DOTALL)
    assert block, ".remediation rule not found"
    assert "--ai" not in block.group(1)
    assert "--fix" in block.group(1)
