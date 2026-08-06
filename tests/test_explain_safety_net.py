"""
Netwise -- tests for ai/explain.py's two lines of defence.

WHY THIS FILE EXISTS
    ai/explain.py's module docstring explains the difference between two
    kinds of mistake found during live testing: wording mistakes (caught
    after generation, by _looks_like_a_result_claim() and
    _looks_like_speculation()) and reasoning mistakes about ACL shadowing
    (prevented before generation, by computing the real answer in
    _compute_dead_rule_outcome() rather than asking the model to derive it).

    These are all pure functions -- no Ollama, no network call -- so they
    run in milliseconds and can be tested directly, the same reasoning
    test_finding_ids.py and test_routing_classification.py give for testing
    pure logic without needing the real system running.

RUN
    pytest tests/ -v
"""

from ai import explain as explain_module
from ai.explain import (
    _build_prompt,
    _compute_dead_rule_outcome,
    _fallback_error_explanation,
    _fallback_plain_restatement,
    _looks_like_a_result_claim,
    _looks_like_speculation,
    explain,
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


# --- _looks_like_speculation --------------------------------------------------


def test_plain_grounded_sentence_is_not_flagged():
    text = (
        "The device's rule set allows all traffic through with no "
        "restriction, which is what let unencrypted web traffic reach the "
        "internal server."
    )
    assert _looks_like_speculation(text) is False


def test_flags_the_real_failure_found_during_live_testing():
    """The exact wording that slipped past a first round of prompt tuning:
    hedged instead of asserted, so it dodged a simpler word ban."""
    text = (
        "This means the network's traffic filtering rules are incomplete "
        "and may allow unwanted traffic through, which could potentially "
        "cause issues."
    )
    assert _looks_like_speculation(text) is True


def test_catches_each_hedge_word_family():
    cases = {
        "may": "This may cause a problem.",
        "might": "This might be an issue.",
        "could": "This could be a problem.",
        "potentially": "This is potentially a problem.",
        "possibly": "This is possibly relevant.",
        "can lead to": "This can lead to a problem.",
    }
    for word, sentence in cases.items():
        assert _looks_like_speculation(sentence) is True, f"did not flag {word!r}"


def test_speculation_check_is_case_insensitive():
    assert _looks_like_speculation("This COULD be a problem.") is True


# --- _compute_dead_rule_outcome -------------------------------------------------
# Regression coverage for the reasoning mistake found during live testing on a
# real finding: the model once stated ICMP traffic "should be blocked...
# which is not happening", backwards -- the traffic IS blocked, that is the
# whole finding. Shadowing logic has one correct answer, so it is computed
# here rather than left for the model to derive.


def test_dead_deny_shadowed_by_permit_means_traffic_is_permitted():
    """Real evidence.detail from access_control._check_dead_rules, pulled
    from Batfish's own bundled 'example' network (device as2dept1)."""
    detail = (
        "Unreachable line: deny   ip 1.128.0.0 0.0.255.255 2.128.0.0 "
        "0.0.255.255 (action DENY). Blocked by: permit ip any "
        "2.128.0.0 0.0.255.255. Reason: BLOCKING_LINES"
    )
    outcome = _compute_dead_rule_outcome(detail)
    assert outcome is not None
    assert "permitted" in outcome
    assert "denied" not in outcome


def test_dead_permit_shadowed_by_deny_means_traffic_is_denied():
    """Real evidence.detail, same network, device as2dept1 -- this is the
    exact case the model got backwards before this function existed."""
    detail = (
        "Unreachable line: permit icmp any any (action PERMIT). "
        "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
    )
    outcome = _compute_dead_rule_outcome(detail)
    assert outcome is not None
    assert "denied" in outcome
    assert "permitted" not in outcome


def test_returns_none_for_a_finding_that_is_not_a_dead_rule():
    detail = "BatfishException: Work terminated abnormally"
    assert _compute_dead_rule_outcome(detail) is None


def test_returns_none_when_blocking_lines_disagree():
    """Two blocking lines named, one permit and one deny -- not confident
    enough to state a single outcome, so this must refuse to guess rather
    than pick one arbitrarily."""
    detail = (
        "Unreachable line: permit tcp any any eq 80 (action PERMIT). "
        "Blocked by: deny ip any any, permit tcp any any eq 443. "
        "Reason: BLOCKING_LINES"
    )
    assert _compute_dead_rule_outcome(detail) is None


def test_returns_none_for_unrecognised_blocking_line_syntax():
    detail = (
        "Unreachable line: permit tcp any any eq 80 (action PERMIT). "
        "Blocked by: remark this is a comment. Reason: BLOCKING_LINES"
    )
    assert _compute_dead_rule_outcome(detail) is None


# --- _fallback_plain_restatement -----------------------------------------------


def test_plain_restatement_includes_summary_and_detail():
    finding = {
        "summary": "No issues found by access control",
        "evidence": {"detail": "2 policy statement(s) hold"},
    }
    result = _fallback_plain_restatement(finding)
    assert "No issues found by access control" in result
    assert "2 policy statement(s) hold" in result


def test_plain_restatement_never_contains_speculation():
    """Same reasoning as the error fallback: this IS the last resort, so it
    must not be able to trip the check it exists to back up."""
    finding = {"summary": "A finding", "evidence": {"detail": "some detail"}}
    assert _looks_like_speculation(_fallback_plain_restatement(finding)) is False


def test_plain_restatement_handles_missing_fields_gracefully():
    assert _fallback_plain_restatement({}) != ""


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


# --- explain() degrades when Ollama is unreachable -----------------------------
# Regression coverage for a real gap found in review: ollama.generate() raises a
# bare ConnectionError when Ollama is not running, and nothing caught it, so
# explain() raised straight past every caller. analyse() already reports an
# unreachable Batfish as a status="error" finding instead of raising; explain()
# not doing the same for an unreachable Ollama is what blocks #31 -- wiring
# explanations into the dashboard would otherwise mean a machine without Ollama
# running gets a broken findings view rather than findings without explanations.


def test_explain_falls_back_instead_of_raising_when_ollama_is_unreachable(monkeypatch):
    def unreachable(finding):
        raise ConnectionError("Failed to connect to Ollama.")

    monkeypatch.setattr(explain_module, "_generate", unreachable)

    finding = {
        "id": "AC-001",
        "status": "found",
        "summary": "Unencrypted web traffic reaches the internal server",
        "evidence": {"detail": "Expected DENY but got PERMIT"},
    }
    result = explain(finding)
    assert "Unencrypted web traffic reaches the internal server" in result


def test_explain_uses_the_error_fallback_when_ollama_is_unreachable(monkeypatch):
    """The found/none and error fallbacks are different functions -- this
    must still pick the right one when Ollama is the thing that failed, not
    generation quality."""

    def unreachable(finding):
        raise ConnectionError("Failed to connect to Ollama.")

    monkeypatch.setattr(explain_module, "_generate", unreachable)

    finding = {
        "id": "RT-000",
        "status": "error",
        "evidence": {"detail": "BatfishException: Work terminated abnormally"},
    }
    result = explain(finding)
    assert "BatfishException: Work terminated abnormally" in result
    assert _looks_like_a_result_claim(result) is False


def test_explain_does_not_retry_a_second_time_against_an_unreachable_ollama(monkeypatch):
    """A second attempt against a host already known to be down would only
    add latency for no chance of a different outcome -- one call, not two."""
    calls = []

    def unreachable(finding):
        calls.append(finding)
        raise ConnectionError("Failed to connect to Ollama.")

    monkeypatch.setattr(explain_module, "_generate", unreachable)
    explain({"id": "AC-001", "status": "found", "summary": "x", "evidence": {"detail": "y"}})
    assert len(calls) == 1


def test_explain_still_retries_normally_when_ollama_is_reachable(monkeypatch):
    """The Ollama-unreachable short-circuit must not change the existing
    generate-validate-retry behaviour for an ordinary validation failure."""
    calls = []

    def speculative_then_clean(finding):
        calls.append(finding)
        if len(calls) == 1:
            return "This could potentially be a problem."
        return "The device allows all traffic through with no restriction."

    monkeypatch.setattr(explain_module, "_generate", speculative_then_clean)
    result = explain({"id": "AC-001", "status": "found", "summary": "x", "evidence": {"detail": "y"}})
    assert len(calls) == 2
    assert "no restriction" in result


# --- _build_prompt -------------------------------------------------------------


def test_prompt_contains_the_actual_finding_as_json():
    finding = {"id": "AC-001", "status": "found"}
    prompt = _build_prompt(finding)
    assert '"id": "AC-001"' in prompt
    assert '"status": "found"' in prompt


def test_prompt_includes_the_computed_outcome_for_a_dead_rule_finding():
    finding = {
        "id": "AC-002",
        "evidence": {
            "detail": (
                "Unreachable line: permit icmp any any (action PERMIT). "
                "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
            )
        },
    }
    prompt = _build_prompt(finding)
    assert "denied" in prompt
    assert "already verified" in prompt.lower()


def test_prompt_omits_the_computed_outcome_for_an_unrelated_finding():
    """The injected fact block must only appear when the deterministic
    computation is actually confident -- otherwise the model is told
    nothing extra and reasons from the raw finding alone, same as any
    other finding shape."""
    finding = {"id": "RT-001", "evidence": {"detail": "BatfishException: Work terminated abnormally"}}
    prompt = _build_prompt(finding)
    assert "already verified" not in prompt.lower()


def test_prompt_tells_the_model_not_to_echo_the_computed_fact_as_a_label():
    """Regression coverage for a real failure: the model echoed the label
    on the injected fact verbatim as its own paragraph instead of folding
    it into the explanation's prose."""
    finding = {
        "id": "AC-001",
        "evidence": {
            "detail": (
                "Unreachable line: deny ip any any (action DENY). "
                "Blocked by: permit ip any any. Reason: BLOCKING_LINES"
            )
        },
    }
    prompt = _build_prompt(finding)
    assert "do not quote it, label it" in prompt.lower()


def test_prompt_tells_the_model_not_to_copy_the_examples():
    """Regression coverage for the exact failure found during live testing:
    without this instruction, the model reproduced a worked example's
    answer verbatim for an unrelated finding. See ai/Modelfile's commit
    message for the full account."""
    prompt = _build_prompt({"id": "AC-001"})
    assert "worked examples" in prompt.lower()
    assert "do not reuse" in prompt.lower()
