"""
Netwise -- Layer 2, turning one F-1 finding into a plain-English explanation.

WHAT THIS DOES
    explain(finding: dict) -> str
    Takes ONE F-1 finding (see docs/finding-format.md) and returns a plain-
    English explanation, using the local Warden model (ai/Modelfile). That
    function is the whole public surface of this module.

WHY status="error" GETS A SAFETY NET, NOT JUST A CAREFUL PROMPT
    ai/Modelfile's system prompt was tested through several rounds against
    real findings pulled from the pipeline before landing on its current
    shape -- see that file's own commit message for the full account. The
    most dangerous failure -- the model stating a network result as fact
    when the check that would have proven it never actually ran -- stopped
    recurring across repeated testing once the prompt was tightened. But
    repeated testing on a 3B model, run entirely on CPU, never reached
    100%: occasional formatting drift (a stray hedge sentence, wording not
    quite matching the required shape) still happens.

    For a status="found" or status="none" finding, a formatting slip is
    cosmetic. For status="error" it is not: F-4 exists specifically because
    "we checked and found nothing" and "we could not check" must never be
    confused, and a slip here is the one place that could still say
    something false about the network. So error explanations are checked
    AFTER generation, not just prompted carefully beforehand -- see
    _looks_like_a_result_claim() below. This is not a retreat from using
    the model: the model still writes every error explanation. It is a
    cheap, deterministic backstop for the one case where a slip is not
    merely cosmetic.

RUN IT BY HAND
    python -m ai.explain
    Pulls a real finding out of the pipeline (tests/fixtures/rtr-us5-
    insecure) and prints the explanation, so this can be checked against
    live output rather than an invented example.

PREREQUISITE
    Ollama running locally, with the model built from ai/Modelfile:
        ollama create netwise-warden -f ai/Modelfile
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict

import ollama

# The model this module calls. Built from ai/Modelfile -- see that file for
# the persona, rules, and generation parameters actually in force. Nothing
# in this module tunes the model itself; that all lives in the Modelfile so
# there is one place to look, not two.
MODEL_NAME = "netwise-warden"

# Words that only belong in a response CONFIRMING something about the
# network. Per ai/Modelfile rule 4, an "error" finding earns neither a
# positive nor a negative claim about the network -- so none of these
# should appear anywhere in an error explanation. Matched as whole words,
# case-insensitively, with a trailing \w* so "reach" also catches
# "reaches"/"reachable" without matching an unrelated word that merely
# contains the same letters.
_RESULT_CLAIM_WORDS = (
    "reach",
    "reachable",
    "blocked",
    "works",
    "working",
    "vulnerable",
    "safe",
    "secure",
    "clear",
    "issues",
)
_RESULT_CLAIM_PATTERN = re.compile(
    r"\b(" + "|".join(_RESULT_CLAIM_WORDS) + r")\w*\b", re.IGNORECASE
)


def _looks_like_a_result_claim(text: str) -> bool:
    """True if `text` uses language that asserts something about the network.

    Used only for status="error" responses -- see the module docstring for
    why. Deliberately errs toward flagging too much rather than too little:
    a false positive here costs one retry or a safe fallback sentence; a
    false negative lets a wrong claim through to whoever reads it.
    """
    return bool(_RESULT_CLAIM_PATTERN.search(text))


def _fallback_error_explanation(finding: Dict[str, Any]) -> str:
    """The deterministic last resort for status="error", used only if the
    model fails the check above twice in a row.

    Always correct, because it is not generated -- it states only the two
    facts actually known: the check did not complete, and (if given) the
    technical reason why. No model call, so nothing here can hallucinate.
    """
    detail = finding.get("evidence", {}).get("detail") or "an unknown error"
    return (
        "This check could not be completed, so nothing is confirmed about "
        f"the network either way. The underlying reason: {detail}"
    )


def _build_prompt(finding: Dict[str, Any]) -> str:
    """Wrap the finding so the model cannot mistake it for one of the
    worked examples baked into ai/Modelfile's system prompt.

    WHY THIS WRAPPING EXISTS: measured directly while building the prompt.
    Without it, the model sometimes reproduced a worked example's answer
    almost verbatim for an unrelated finding, rather than reasoning about
    the finding it was actually given -- see ai/Modelfile's commit message
    for the full account of that failure and the fix.
    """
    finding_json = json.dumps(finding, indent=2)
    return (
        "Explain ONLY the finding below. Do not reuse any wording from the "
        "worked examples in your instructions above -- those show STYLE "
        "only, never content to repeat. This finding is a different, "
        "unrelated case; read its actual fields before answering.\n\n"
        "Finding to explain:\n" + finding_json
    )


def _generate(finding: Dict[str, Any]) -> str:
    """One call to the model. No validation here -- explain() decides
    whether the result is acceptable."""
    response = ollama.generate(model=MODEL_NAME, prompt=_build_prompt(finding))
    return response["response"].strip()


def explain(finding: Dict[str, Any]) -> str:
    """Return a plain-English explanation of ONE F-1 finding.

    Grounded strictly in `finding` -- CLAUDE.md constraint 2. This function
    never receives, and the model never sees, anything beyond the single
    finding passed in: no other findings, no wider network context.
    """
    if finding.get("status") != "error":
        return _generate(finding)

    # status="error": generate, then verify before trusting it. Retry once
    # if the first attempt slips into asserting a result about the network;
    # fall back to the fixed, always-correct sentence if the second attempt
    # does too, rather than ever showing an unverified response for the one
    # status where a slip is not just cosmetic.
    explanation = _generate(finding)
    if not _looks_like_a_result_claim(explanation):
        return explanation

    explanation = _generate(finding)
    if not _looks_like_a_result_claim(explanation):
        return explanation

    return _fallback_error_explanation(finding)


if __name__ == "__main__":
    from analysis.pipeline import analyse

    results = analyse("tests/fixtures/rtr-us5-insecure", check_names=["access_control"])
    finding = results[0]

    print("Finding:")
    print(json.dumps(finding, indent=2))
    print()
    print("Explanation:")
    print(explain(finding))
