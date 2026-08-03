"""
Netwise -- tests for ai/explain.py's error-case safety net.

WHY THIS FILE EXISTS
    ai/explain.py's module docstring explains why status="error" findings
    get a post-generation check rather than trusting the prompt alone:
    repeated live testing showed the model occasionally (not usually, but
    occasionally) slips a result claim into an error explanation even with
    a carefully tuned prompt. _looks_like_a_result_claim() is what catches
    that before anyone sees it, and _fallback_error_explanation() is the
    deterministic sentence used if it happens twice in a row.

    These are pure functions -- no Ollama, no network call -- so they run
    in milliseconds and can be tested directly, the same reasoning
    test_finding_ids.py and test_routing_classification.py give for testing
    pure logic without needing the real system running.

RUN
    pytest tests/ -v
"""

from ai.explain import (
    _build_prompt,
    _fallback_error_explanation,
    _looks_like_a_result_claim,
)

# --- _looks_like_a_result_claim ----------------------------------------------


def test_clean_error_explanation_is_not_flagged():
    text = (
        "This check could not be completed, so nothing is confirmed about "
        "the network either way. The underlying reason: BatfishException."
    )
    assert _looks_like_a_result_claim(text) is False


def test_flags_a_positive_result_claim():
    assert _looks_like_a_result_claim("The network can reach the server.") is True


def test_flags_a_negative_result_claim():
    assert _looks_like_a_result_claim("The HQ LAN cannot reach the branch LAN.") is True


def test_flags_hedged_claims_too():
    """A hedge is still a claim about the network -- 'cannot be confirmed to
    reach' is exactly the residual pattern found during live testing, not
    a hard false statement, but still not the required shape."""
    assert _looks_like_a_result_claim("This cannot be confirmed to reach the branch.") is True


def test_word_boundary_matching_not_substring_matching():
    """'clear' is banned, but a word that merely CONTAINS those letters
    should not trip the check -- this must match whole words only."""
    assert _looks_like_a_result_claim("The nuclear plant was mentioned nowhere.") is False


def test_matches_are_case_insensitive():
    assert _looks_like_a_result_claim("The device is SECURE.") is True


def test_catches_each_banned_word_family():
    """One case per banned word family, so a future edit that silently drops
    one from the pattern fails a specific, named test rather than the whole
    suite going quiet on one word."""
    cases = {
        "reach": "It can reach the server.",
        "blocked": "Traffic is blocked here.",
        "working": "The link is working.",
        "vulnerable": "The host is vulnerable.",
        "safe": "The path is safe.",
        "clear": "The result is clear.",
        "issues": "There are no issues.",
    }
    for word, sentence in cases.items():
        assert _looks_like_a_result_claim(sentence) is True, f"did not flag {word!r}"


# --- _fallback_error_explanation ----------------------------------------------


def test_fallback_includes_the_real_evidence_detail():
    finding = {
        "evidence": {"detail": "BatfishException: Work terminated abnormally"},
    }
    result = _fallback_error_explanation(finding)
    assert "BatfishException: Work terminated abnormally" in result


def test_fallback_never_contains_a_result_claim():
    """The fallback IS the safety net's last resort -- it would defeat the
    whole point if it could itself trip its own check."""
    finding = {"evidence": {"detail": "some crash reason"}}
    assert _looks_like_a_result_claim(_fallback_error_explanation(finding)) is False


def test_fallback_handles_a_missing_detail_gracefully():
    """evidence.detail is required by F-1 in practice, but this function
    must not crash if it is ever missing or empty -- it is the last line of
    defence and must not itself be a new way to fail."""
    assert _fallback_error_explanation({"evidence": {}}) != ""
    assert _fallback_error_explanation({}) != ""


# --- _build_prompt -------------------------------------------------------------


def test_prompt_contains_the_actual_finding_as_json():
    finding = {"id": "AC-001", "status": "found"}
    prompt = _build_prompt(finding)
    assert '"id": "AC-001"' in prompt
    assert '"status": "found"' in prompt


def test_prompt_tells_the_model_not_to_copy_the_examples():
    """Regression coverage for the exact failure found during live testing:
    without this instruction, the model reproduced a worked example's
    answer verbatim for an unrelated finding. See ai/Modelfile's commit
    message for the full account."""
    prompt = _build_prompt({"id": "AC-001"})
    assert "worked examples" in prompt.lower()
    assert "do not reuse" in prompt.lower()
