"""An explanation must show which evidence it came from (#236, phase A).

WHAT THIS PROTECTS
    Every explanation on screen is a paraphrase of `evidence.detail` /
    `evidence.source`, sitting directly above it in the same card. That link
    was always true and always invisible: nothing on screen said where the
    sentence came from, or let a reader jump to the raw line it was grounded
    in. `web/static/app.js` now builds a real anchor from the explanation to
    the evidence block, and this file drives the REAL `renderFindings()`
    through Node -- same approach as `test_findings_rendering.py` -- to prove
    it, not a re-implementation of the logic.

THE BUG THIS WOULD HAVE BEEN, IF THE LINK WERE BUILT FROM finding.id
    `web/static/app.js` already carries a comment, verified by
    `test_findings_rendering.py`, that `finding.id` is not unique: two
    findings from the same check can share one. If the evidence-link's href
    had been built from `finding.id` instead of a fresh per-render counter,
    two colliding findings would produce the SAME href, and following either
    explanation's link could land on the WRONG finding's evidence -- a broken
    trail that looks like a working one. `test_colliding_ids_still_get_their_own_evidence_link`
    is the regression test for exactly that.

ACCEPTANCE CRITERIA COVERED HERE (issue #236, phase A only)
    - click through from an explanation to evidence.detail and evidence.source
    - a fallback explanation shows provenance too
    - a found finding with no explanation says plainly that there is none

    Phase B (recording which Batfish question and parameters produced a
    finding) is out of scope: it needs a finding-format decision from all
    four team members, per the issue itself, and is not attempted here.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "provenance_render_harness.js"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the provenance-rendering harness needs it",
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


def _by_class(nodes, class_name):
    return [n for n in nodes if n["className"] == class_name]


def _evidence_id_for(nodes, marker_text):
    """The id of the .evidence block whose text contains `marker_text`."""
    for n in nodes:
        if n["className"] == "evidence" and marker_text in n["textContent"]:
            return n["id"]
    raise AssertionError(f"no evidence block contains {marker_text!r}")


# ---------------------------------------------------------------------------
# Model and fallback explanations both link to their own evidence
# ---------------------------------------------------------------------------


@needs_node
def test_a_model_explanation_links_to_its_own_evidence(rendered):
    nodes = rendered["modelAndFallback"]
    evidence_id = _evidence_id_for(nodes, "10.10.10.0/24")
    assert evidence_id, "the evidence block must carry a non-empty id"

    links = _by_class(nodes, "evidence-link")
    assert len(links) == 2, "both findings in this fixture have explanations"

    model_link = links[0]
    assert model_link["href"] == f"#{evidence_id}", (
        "the model explanation's link must point at its own evidence block, "
        f"got href={model_link['href']!r} for evidence id={evidence_id!r}"
    )


@needs_node
def test_a_fallback_explanation_links_to_its_own_evidence_too(rendered):
    """Acceptance criterion: 'a fallback explanation shows provenance too'."""
    nodes = rendered["modelAndFallback"]
    evidence_id = _evidence_id_for(nodes, "acl_in line 22 denies 10.20.30.0/24")

    fallback_blocks = _by_class(nodes, "ai-explanation fallback")
    assert len(fallback_blocks) == 1

    links = _by_class(nodes, "evidence-link")
    assert len(links) == 2, "the fallback explanation must get a link too"
    # The fixture only has two findings, so the second link is the fallback
    # one; checked against its own evidence id, not just any evidence id.
    fallback_link = links[1]
    assert fallback_link["href"] == f"#{evidence_id}"


@needs_node
def test_evidence_blocks_have_distinct_ids_not_the_shared_finding_id(rendered):
    nodes = rendered["modelAndFallback"]
    evidence_ids = [n["id"] for n in nodes if n["className"] == "evidence"]
    assert len(evidence_ids) == 2
    assert len(set(evidence_ids)) == 2, "two different findings must not share an evidence id"
    assert "AC-001" not in evidence_ids and "AC-002" not in evidence_ids, (
        "the evidence id must come from the render counter, not finding.id"
    )


# ---------------------------------------------------------------------------
# The collision case -- the bug this design avoids
# ---------------------------------------------------------------------------


@needs_node
def test_colliding_ids_still_get_their_own_evidence_link(rendered):
    """Two findings sharing finding.id must not share an evidence id or link.

    If the link were built from finding.id, both of these would produce the
    href, and following either one could land on the wrong finding's
    evidence -- worse than no link, because it looks like it works.
    """
    nodes = rendered["collidingPair"]

    evidence_ids = [n["id"] for n in nodes if n["className"] == "evidence"]
    assert len(evidence_ids) == 2
    assert len(set(evidence_ids)) == 2, (
        "both findings in the colliding pair are id AC-999; their evidence "
        "blocks must still get distinct ids"
    )

    first_evidence_id = _evidence_id_for(nodes, "first detail")
    second_evidence_id = _evidence_id_for(nodes, "second detail")
    assert first_evidence_id != second_evidence_id

    links = _by_class(nodes, "evidence-link")
    assert len(links) == 2
    assert links[0]["href"] == f"#{first_evidence_id}"
    assert links[1]["href"] == f"#{second_evidence_id}"
    assert links[0]["href"] != links[1]["href"]


# ---------------------------------------------------------------------------
# A found finding with no explanation says so in words
# ---------------------------------------------------------------------------


@needs_node
def test_a_found_finding_with_no_explanation_says_so(rendered):
    """Acceptance criterion: '... or says plainly that there is none'."""
    nodes = rendered["unexplained"]

    no_explanation = _by_class(nodes, "no-explanation")
    assert len(no_explanation) == 1
    assert "No explanation was generated" in no_explanation[0]["textContent"]

    assert _by_class(nodes, "ai-explanation") == [], (
        "no explanation text exists, so no ai-explanation block should render"
    )
    assert _by_class(nodes, "evidence-link") == [], (
        "there is nothing to link the (absent) explanation to"
    )


# ---------------------------------------------------------------------------
# Clean and blind findings never claim an explanation exists
# ---------------------------------------------------------------------------


@needs_node
def test_clean_and_blind_findings_get_no_explanation_machinery_at_all(rendered):
    """status="none" and status="error" were never explained and must not

    start claiming otherwise now. A clean or blind card showing
    ".no-explanation" would misread as "we tried to explain this and could
    not", which is not what either status means.
    """
    nodes = rendered["cleanAndBlind"]

    assert _by_class(nodes, "ai-explanation") == []
    assert _by_class(nodes, "evidence-link") == []
    assert _by_class(nodes, "no-explanation") == []
