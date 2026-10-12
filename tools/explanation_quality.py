"""Score the held-out explanation set for US-55 (#346).

WHAT THIS DOES
    Pure arithmetic over tests/fixtures/explanation_quality/holdout.json --
    the mean and minimum of each rating dimension (accuracy, usefulness)
    across every rater and finding in that file. Nothing here calls Ollama
    or Batfish, so this runs the same everywhere: a laptop, CI, two years
    from now. "Repeatable score" means exactly this -- the same frozen
    input always produces the same number, not that a live model's output
    is repeatable (it is not, see ai/explain.py's own docstring).

WHY A SEPARATE NUMBER PER DIMENSION, NOT ONE BLENDED SCORE
    docs/evaluation.md already makes this argument twice (the controls
    table, F-4 itself): a single averaged number hides exactly the case
    that matters. Blending accuracy and usefulness into one figure would
    let a high-usefulness, low-accuracy explanation (or the reverse) read
    as "fine" when it is not. Reported separately instead.

WHY MINIMUM, NOT JUST MEAN
    The mean alone would have hidden AC-002's accuracy=2 behind four other
    findings at 5, printing a healthy-looking 4.4 while one finding in the
    set is actually a confirmed defect (#384). The minimum is reported for
    that reason, but see EXPLANATION_QUALITY_THRESHOLD below for why the
    THRESHOLD decision is deliberately based on the mean, not the minimum.

RUN IT BY HAND
    python -m tools.explanation_quality
    python tools/explanation_quality.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

#: Resolved relative to this file, not the caller's working directory --
#: so this runs correctly from the repository root regardless of which of
#: the two documented invocation forms launched it.
DEFAULT_HOLDOUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "tests" / "fixtures" / "explanation_quality" / "holdout.json"
)

#: Acceptance criterion 3 of #346: "a documented threshold below which the
#: deterministic fallback is preferred". Grounded in the first real
#: measurement (see docs/evaluation.md Part 4): mean_accuracy 4.4,
#: mean_usefulness 3.4 -- so these two numbers sit comfortably below the
#: current measurement rather than just above it, which would make the
#: threshold meaningless.
#:
#: DELIBERATELY ON THE MEAN, NOT THE MINIMUM
#:     A single low-scoring finding (AC-002, accuracy=2, #384) is treated
#:     as a correctness BUG to fix for that one evidence shape -- the same
#:     way #52 and #145 were each fixed for their one shape, never by
#:     disabling the model for every finding. Tying this threshold to the
#:     minimum would mean one narrow, already-understood defect forces
#:     every explanation onto the deterministic fallback, which is a far
#:     bigger behaviour change than the finding justifies. The mean is what
#:     answers the real question this threshold exists for: has overall
#:     quality collapsed broadly, not did one shape have one bad day.
#:
#: WHY THIS IS A DOCUMENTED NUMBER AND NOT A RUNTIME CHECK
#:     There is no way to score a single live generation's quality
#:     automatically without another model judging it -- which would just
#:     move the hallucination risk up one level, not remove it, the same
#:     reasoning CLAUDE.md constraint 2 already applies to explanation
#:     generation itself. So crossing this threshold is detected the only
#:     honest way available: a human re-runs the held-out measurement (same
#:     method as docs/evaluation.md Part 4), and if the new mean falls
#:     below either number here, that is the trigger to seriously
#:     reconsider defaulting ai/explain.py to the fallback path for every
#:     finding, not an automatic flag flip.
EXPLANATION_QUALITY_THRESHOLD = {
    "mean_accuracy": 4.0,
    "mean_usefulness": 3.0,
}


def load_holdout(path: Path = DEFAULT_HOLDOUT_PATH) -> List[Dict[str, Any]]:
    """The held-out set's `findings` list, read from `path`.

    Raises FileNotFoundError / json.JSONDecodeError on a missing or
    malformed file rather than returning an empty result -- a silently
    empty score (mean of nothing) must never be mistaken for "nothing
    wrong was found", the same F-4 distinction CLAUDE.md requires of the
    product itself.
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data["findings"]


def _aggregate(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The mean/min/per-finding arithmetic, shared by the model score and
    the fallback report below. Does not raise on an empty list -- callers
    decide what emptiness means for them (score_holdout() raises for the
    model group; the fallback group is simply absent when there isn't one)."""
    accuracies: List[int] = []
    usefulnesses: List[int] = []
    per_finding: List[Dict[str, Any]] = []

    for finding in findings:
        ratings = finding["ratings"]
        finding_accuracies = [r["accuracy"] for r in ratings]
        finding_usefulnesses = [r["usefulness"] for r in ratings]
        accuracies.extend(finding_accuracies)
        usefulnesses.extend(finding_usefulnesses)
        per_finding.append({
            "id": finding["id"],
            "mean_accuracy": sum(finding_accuracies) / len(finding_accuracies),
            "mean_usefulness": sum(finding_usefulnesses) / len(finding_usefulnesses),
            "n_ratings": len(ratings),
        })

    return {
        "n_findings": len(findings),
        "n_ratings": len(accuracies),
        "mean_accuracy": sum(accuracies) / len(accuracies),
        "min_accuracy": min(accuracies),
        "mean_usefulness": sum(usefulnesses) / len(usefulnesses),
        "min_usefulness": min(usefulnesses),
        "per_finding": per_finding,
    }


def score_holdout(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate accuracy/usefulness across every MODEL-WRITTEN rating in
    `findings`. Fallback-sourced captures (`captured_explanation_source`
    other than `"model"`) are reported separately under the `"fallback"`
    key, never blended into the headline numbers.

    WHY THE SPLIT (found in review, @ARSH871-bot, on the first version of
    this set)
        `EXPLANATION_QUALITY_THRESHOLD` exists to answer one question: is
        the MODEL good enough to prefer over the deterministic fallback.
        `_fallback_error_explanation()` and `_fallback_plain_restatement()`
        cannot be wrong in the way this threshold cares about -- they are
        not generated, so "accuracy cannot be wrong by construction" (the
        held-out set's own note on RT-050). Averaging a fallback capture's
        score into the model's score lets a set with NO model output at
        all pass the threshold -- measured directly: five copies of
        RT-050's rating alone would score 5.00/4.00, comfortably above
        4.0/3.0, having said nothing whatsoever about model quality. That
        is a weaker claim standing in for a stronger one, the same failure
        shape this module's own docstring already names for blending
        accuracy into usefulness.

        RT-050 has a second, independent reason to stay out of the model
        score: it is `status="error"`, and `web/main.py` only attaches an
        explanation to a `status="found"` finding (confirmed directly,
        `web/main.py`'s explanation-attachment loop: `if finding.get(
        "status") != "found": continue`) -- so no user is ever shown an
        explanation for it regardless of what source produced the capture.

    Raises ValueError if there are no model-written entries to score --
    same reasoning as the empty-set case this function always refused: a
    score with nothing behind it must never print as a number. A held-out
    set consisting ENTIRELY of fallback captures hits this path too, which
    is deliberate -- see the test for the shape of that case.
    """
    model_findings = [
        f for f in findings
        if f.get("captured_explanation_source") == "model"
    ]
    if not model_findings:
        raise ValueError(
            "cannot score: no model-written entries in this held-out set "
            "(fallback-sourced captures cannot be wrong by construction, "
            "so they say nothing about whether the model is good enough)"
        )

    result = _aggregate(model_findings)

    fallback_findings = [
        f for f in findings
        if f.get("captured_explanation_source") != "model"
    ]
    if fallback_findings:
        result["fallback"] = _aggregate(fallback_findings)

    return result


def _format_report(score: Dict[str, Any]) -> str:
    """Plain-text rendering of score_holdout()'s return value, for the
    command-line entry point below. Not used by the test suite, which
    asserts on the dict directly rather than parsing text back out of it."""
    lines = [
        f"{score['n_findings']} model-written findings, {score['n_ratings']} ratings",
        f"accuracy:   mean {score['mean_accuracy']:.2f}  min {score['min_accuracy']}",
        f"usefulness: mean {score['mean_usefulness']:.2f}  min {score['min_usefulness']}",
        "",
        "per finding:",
    ]
    for row in score["per_finding"]:
        lines.append(
            f"  {row['id']:<8} accuracy {row['mean_accuracy']:.1f}  "
            f"usefulness {row['mean_usefulness']:.1f}  "
            f"({row['n_ratings']} rating(s))"
        )
    if "fallback" in score:
        lines.append("")
        lines.append(
            f"fallback-sourced (not scored against the threshold -- "
            f"cannot be wrong by construction):"
        )
        for row in score["fallback"]["per_finding"]:
            lines.append(
                f"  {row['id']:<8} accuracy {row['mean_accuracy']:.1f}  "
                f"usefulness {row['mean_usefulness']:.1f}  "
                f"({row['n_ratings']} rating(s))"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    print(_format_report(score_holdout(load_holdout())))
