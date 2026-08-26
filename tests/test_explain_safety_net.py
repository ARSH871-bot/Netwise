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

import ollama

from ai import explain as explain_module
import pytest

from ai.explain import (
    _build_prompt,
    _compute_dead_rule_outcome,
    _compute_expected_actual_outcome,
    _compute_policy_outcome,
    _evidence_detail,
    _fallback_error_explanation,
    _fallback_plain_restatement,
    _looks_like_a_result_claim,
    _looks_like_speculation,
    explain,
    explain_with_source,
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


# --- _compute_policy_outcome (#145) ---------------------------------------------
# Regression coverage for the reasoning mistake found while independently
# rating explanations for #90: the model attributed the wrong action to "the
# policy" on two real findings (PC-001, PC-005). Which side (the device's
# live configuration vs. the written policy) is responsible has one correct
# answer, so it is computed here rather than left for the model to derive.


def test_prohibition_violation_blames_the_device_not_the_policy():
    """Real evidence.detail shape from policy_compliance._describe() for a
    'prohibition' rule -- the device permits what the policy forbids."""
    detail = (
        "Flow start=10.20.0.5 is permitted but policy requires it to be DENIED. "
        "Decided by: permit ip any any"
    )
    outcome = _compute_policy_outcome(detail)
    assert outcome is not None
    assert "PERMITTED" in outcome
    assert "FORBIDS" in outcome
    assert "DENIED" not in outcome
    assert "REQUIRES" not in outcome


def test_requirement_violation_blames_the_device_not_the_policy():
    """Real evidence.detail shape for a 'requirement' rule -- the device
    denies what the policy requires."""
    detail = (
        "Flow start=10.30.0.9 is denied but policy requires it to be PERMITTED. "
        "Decided by: deny tcp any any eq 443"
    )
    outcome = _compute_policy_outcome(detail)
    assert outcome is not None
    assert "DENIED" in outcome
    assert "REQUIRES" in outcome
    assert "PERMITTED" not in outcome
    assert "FORBIDS" not in outcome


def test_policy_outcome_returns_none_for_a_finding_that_is_not_policy_shaped():
    detail = "BatfishException: Work terminated abnormally"
    assert _compute_policy_outcome(detail) is None


def test_policy_outcome_returns_none_for_a_dead_rule_finding():
    """The two computations must not cross-match each other's shape."""
    detail = (
        "Unreachable line: permit icmp any any (action PERMIT). "
        "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
    )
    assert _compute_policy_outcome(detail) is None


def test_policy_outcome_handles_multiple_example_flows_suffix():
    """_describe() appends '(N example flows matched)' when more than one
    row comes back -- the pattern must still match with that suffix present."""
    detail = (
        "Flow start=10.20.0.5 is permitted but policy requires it to be DENIED. "
        "Decided by: permit ip any any (3 example flows matched)"
    )
    outcome = _compute_policy_outcome(detail)
    assert outcome is not None
    assert "PERMITTED" in outcome


# --- _compute_expected_actual_outcome (testFilters) ------------------------------
# Not a bug found by accident -- added on the same structural reasoning that
# found the two above: this evidence shape is the same "which of two opposite
# states is which" attribution task, on real access_control policy-statement
# findings. Live-tested six times against a real finding in this shape before
# adding the guard; no inversion reproduced on that occasion, recorded as a
# clean but limited result rather than proof of safety.


def test_a_required_permit_that_is_actually_denied():
    """Real evidence.detail shape from access_control.run()'s policy-
    statement loop -- something required to be allowed is currently blocked."""
    detail = "Expected PERMIT but got DENY, decided by: deny ip any any"
    outcome = _compute_expected_actual_outcome(detail)
    assert outcome is not None
    assert "DENY" in outcome
    assert "PERMIT" in outcome


def test_a_required_deny_that_is_actually_permitted():
    """The other direction -- something required to be blocked is currently
    let through."""
    detail = "Expected DENY but got PERMIT, decided by: permit ip any any"
    outcome = _compute_expected_actual_outcome(detail)
    assert outcome is not None
    assert "PERMIT" in outcome
    assert "DENY" in outcome


def test_expected_actual_outcome_returns_none_for_an_unrelated_finding():
    detail = "BatfishException: Work terminated abnormally"
    assert _compute_expected_actual_outcome(detail) is None


def test_expected_actual_outcome_returns_none_for_a_dead_rule_finding():
    """The three computations must not cross-match each other's shape."""
    detail = (
        "Unreachable line: permit icmp any any (action PERMIT). "
        "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
    )
    assert _compute_expected_actual_outcome(detail) is None


def test_expected_actual_outcome_returns_none_for_a_policy_compliance_finding():
    """Against the REAL producer, not a copy of its wording (found in review
    of #193 by Shubham -- see #194, #145, #192).

    A hardcoded literal here passes for the wrong reason once wording drifts:
    it stops matching EITHER guard, so the "mutual exclusion" the test claims
    to prove is no longer being exercised at all, and nothing goes red. Using
    _real_detail() means a future rewording of policy_compliance._describe()
    fails this test loudly instead of leaving it green while it tests
    nothing -- the exact failure mode #145/#169 already found once."""
    detail = _real_detail("prohibition")
    assert _compute_expected_actual_outcome(detail) is None
    assert _compute_policy_outcome(detail) is not None  # the OTHER guard still matches


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


# --- explain() skips generation entirely when there is no real evidence to
# ground it in -----------------------------------------------------------------
# Regression coverage for a confirmed, reproducible hallucination found in a
# senior-level adversarial QA pass: with live Ollama, a status="found" finding
# with no evidence.detail at all reliably produced a specific, confident,
# invented technical claim ("the device has a rule that allows all traffic
# through with no restriction"), reproduced 3/3. Neither existing safety check
# catches it -- _looks_like_a_result_claim() only runs for status="error", and
# _looks_like_speculation() only catches HEDGED claims, not confident ones.
# This is exactly what CLAUDE.md constraint 2 calls "a critical failure, not a
# bug." The fix is to never call the model at all when there is nothing real
# to rephrase, not to try to catch the hallucination after the fact.


def test_explain_skips_generation_when_there_is_no_evidence_detail(monkeypatch):
    calls = []
    monkeypatch.setattr(explain_module, "_generate", lambda finding: calls.append(finding) or "unused")

    finding = {"id": "AC-101", "status": "found", "summary": "A finding"}
    result = explain(finding)

    assert calls == [], "the model must not be called at all with no real evidence"
    assert result == "A finding"


def test_explain_skips_generation_for_status_none_with_no_evidence_too(monkeypatch):
    """The same guard for status="none" -- this is also the exact shape that
    reproduced the Modelfile worked-example-echo failure (a different
    symptom of the same root cause: nothing real to ground a generated
    answer in)."""
    calls = []
    monkeypatch.setattr(explain_module, "_generate", lambda finding: calls.append(finding) or "unused")

    finding = {"id": "AC-201", "status": "none", "summary": "No issues found by access control"}
    result = explain(finding)

    assert calls == []
    assert result == "No issues found by access control"


def test_explain_skips_generation_for_status_error_with_no_evidence_too(monkeypatch):
    calls = []
    monkeypatch.setattr(explain_module, "_generate", lambda finding: calls.append(finding) or "unused")

    finding = {"id": "RT-000", "status": "error", "summary": "Could not check"}
    result = explain(finding)

    assert calls == []
    assert "unknown error" in result


def test_explain_still_generates_normally_when_real_evidence_is_present(monkeypatch):
    """The guard must not become a blanket ban on generation -- only fire
    when there is genuinely nothing to ground an answer in."""
    calls = []

    def stub(finding):
        calls.append(finding)
        return "The device allows all traffic through with no restriction."

    monkeypatch.setattr(explain_module, "_generate", stub)
    finding = {
        "id": "AC-001",
        "status": "found",
        "summary": "x",
        "evidence": {"detail": "Expected DENY but got PERMIT"},
    }
    result = explain(finding)

    assert len(calls) == 1, "generation must still happen when evidence.detail is real"
    assert "no restriction" in result


def test_explain_falls_back_when_the_model_is_not_built(monkeypatch):
    """Ollama up, but nobody has run `ollama create netwise-warden -f
    ai/Modelfile` yet -- at least as likely in practice as Ollama being
    fully down, and missed by the first pass at this fix, which only
    caught ConnectionError."""

    def not_built(finding):
        raise ollama.ResponseError("model 'netwise-warden' not found", 404)

    monkeypatch.setattr(explain_module, "_generate", not_built)
    result = explain({"id": "AC-001", "status": "found", "summary": "x", "evidence": {"detail": "y"}})
    assert "x" in result


def test_explain_falls_back_on_a_malformed_request_too(monkeypatch):
    """The third member of the same family as ConnectionError and
    ResponseError -- a request the client itself rejects before sending."""

    def malformed(finding):
        raise ollama.RequestError("bad request")

    monkeypatch.setattr(explain_module, "_generate", malformed)
    result = explain({"id": "RT-000", "status": "error", "evidence": {"detail": "d"}})
    assert "d" in result


# --- _evidence_detail ------------------------------------------------------------
# Regression coverage for a real crash: dict.get(key, default) only falls back
# to `default` when `key` is ABSENT, not when it is present with value None.
# findings.make_finding() does not reject evidence={"detail": None} or
# evidence=None outright, so this is one bug away in any check, not
# hypothetical.


def test_evidence_detail_handles_a_none_detail():
    assert _evidence_detail({"evidence": {"detail": None}}) == ""


def test_evidence_detail_handles_evidence_being_none_entirely():
    assert _evidence_detail({"evidence": None}) == ""


def test_evidence_detail_handles_evidence_missing_entirely():
    assert _evidence_detail({}) == ""


def test_evidence_detail_handles_a_non_string_detail():
    assert _evidence_detail({"evidence": {"detail": 12345}}) == ""


def test_evidence_detail_returns_the_real_string_when_present():
    assert _evidence_detail({"evidence": {"detail": "the real detail"}}) == "the real detail"


def test_build_prompt_does_not_crash_when_evidence_detail_is_none():
    """The exact path that crashed before this fix: _build_prompt() passes
    evidence.detail to _compute_dead_rule_outcome()'s regex .search() call,
    which requires a string, not None. Tested at this level (not through
    explain()) so it stays a pure, millisecond test with no model call,
    same reasoning as every other test in this file."""
    finding = {"id": "AC-001", "status": "found", "summary": "test", "evidence": {"detail": None}}
    prompt = _build_prompt(finding)
    assert '"id": "AC-001"' in prompt


def test_explain_does_not_crash_when_evidence_detail_is_none(monkeypatch):
    """explain() end to end. evidence.detail=None means _evidence_detail()
    returns "", which the thin-evidence guard (see explain()'s docstring)
    now treats the same as no evidence at all -- generation is skipped, not
    attempted and then rescued. Asserting the model is never even called is
    the point: the crash this test used to cover doesn't need rescuing
    anymore, because the path that crashed is no longer reached."""
    calls = []
    monkeypatch.setattr(explain_module, "_generate", lambda finding: calls.append(finding) or "unused")
    finding = {"id": "AC-001", "status": "found", "summary": "test", "evidence": {"detail": None}}
    assert explain(finding) == "test"
    assert calls == []


def test_fallback_error_explanation_does_not_crash_when_evidence_is_none_entirely():
    """The deterministic last resort for status="error" -- the one place
    that must not be able to fail -- crashed on evidence=None outright, not
    just on evidence={"detail": None}, before this fix."""
    result = _fallback_error_explanation({"evidence": None})
    assert "unknown error" in result


def test_fallback_plain_restatement_does_not_crash_when_evidence_is_none_entirely():
    result = _fallback_plain_restatement({"summary": "x", "evidence": None})
    assert result == "x"


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


def test_prompt_includes_the_computed_outcome_for_a_policy_finding():
    """#145 -- the model must be handed which side is actually responsible,
    the same way it is for a dead-rule finding."""
    finding = {
        "id": "PC-005",
        "evidence": {
            "detail": (
                "Flow start=10.30.0.9 is denied but policy requires it to be PERMITTED. "
                "Decided by: deny tcp any any eq 443"
            )
        },
    }
    prompt = _build_prompt(finding)
    assert "already verified" in prompt.lower()
    assert "DENIED" in prompt
    assert "REQUIRES" in prompt


def test_prompt_prefers_the_dead_rule_computation_when_both_could_apply():
    """The three patterns are mutually exclusive in practice (see each
    function's docstring), but _build_prompt() tries the dead-rule check
    first -- pin that order down directly rather than relying on the
    regexes never colliding by accident."""
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
    assert "already verified" in prompt.lower()
    assert "denied" in prompt


def test_prompt_includes_the_computed_outcome_for_a_testfilters_finding():
    """access_control's own policy-statement findings get the same
    deterministic help as a dead-rule or policy_compliance finding."""
    finding = {
        "id": "AC-099",
        "evidence": {"detail": "Expected PERMIT but got DENY, decided by: deny ip any any"},
    }
    prompt = _build_prompt(finding)
    assert "already verified" in prompt.lower()
    assert "DENY" in prompt
    assert "PERMIT" in prompt


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


# --- explain_with_source(): the provenance signal for #109 -------------------
#
# The dashboard's "AI explanation" byline is unconditional, and explain()'s
# bare str return gave nothing downstream a way to tell a genuine model
# response apart from _fallback_plain_restatement()'s deterministic text.
# These pin the one new fact this function reports; explain()'s own
# behaviour is covered by every test above it in this file, unchanged.


def test_a_clean_generation_reports_model_as_the_source(monkeypatch):
    monkeypatch.setattr(
        explain_module, "_generate", lambda finding: "The device allows all traffic through."
    )
    finding = {"id": "AC-001", "status": "found", "summary": "x", "evidence": {"detail": "y"}}

    text, source = explain_with_source(finding)

    assert source == "model"
    assert "allows all traffic" in text


def test_an_unreachable_ollama_reports_fallback_as_the_source(monkeypatch):
    def unreachable(finding):
        raise ConnectionError("Failed to connect to Ollama.")

    monkeypatch.setattr(explain_module, "_generate", unreachable)
    finding = {
        "id": "AC-001",
        "status": "found",
        "summary": "Unencrypted web traffic reaches the internal server",
        "evidence": {"detail": "Expected DENY but got PERMIT"},
    }

    text, source = explain_with_source(finding)

    assert source == "fallback"
    assert "Unencrypted web traffic reaches the internal server" in text


def test_the_no_evidence_skip_also_reports_fallback(monkeypatch):
    """The thin-evidence guard skips generation entirely (#52) -- still a
    fallback, same as an unreachable Ollama, not a third category."""
    monkeypatch.setattr(explain_module, "_generate", lambda finding: "unused")
    finding = {"id": "AC-101", "status": "found", "summary": "A finding"}

    text, source = explain_with_source(finding)

    assert source == "fallback"
    assert text == "A finding"


def test_explain_still_returns_only_the_text_it_always_did(monkeypatch):
    """explain() delegates to explain_with_source() now -- confirm the
    public, str-only contract every existing caller and test relies on
    did not quietly become a tuple."""
    monkeypatch.setattr(
        explain_module, "_generate", lambda finding: "The device allows all traffic through."
    )
    finding = {"id": "AC-001", "status": "found", "summary": "x", "evidence": {"detail": "y"}}

    result = explain(finding)

    assert isinstance(result, str)
    assert "allows all traffic" in result


# --- the seam between policy_compliance and this module ------------------------
#
# _POLICY_DETAIL_PATTERN parses a string that another module writes. Every other
# test in this file passes that string as a LITERAL, so all of them keep passing
# if policy_compliance._describe() changes its wording -- and the safeguard just
# silently stops matching, which is its documented "nothing to compute from"
# path rather than an error.
#
# That is exactly what would have happened when #145's evidence-format fix
# landed: the pattern matched the old pronoun wording, the fix replaced it, and
# nothing on either side asserted the join. Caught on review of #169 before both
# shipped.
#
# These call the REAL _describe(), so a wording change on either side fails here.


def _real_detail(kind):
    """The genuine evidence string, from the genuine function."""
    from analysis.checks import policy_compliance as pc

    rule = {
        "number": 1,
        "description": "d",
        "kind": kind,
        "node": "rtr-us5",
        "filter": "acl_in",
        "violation_severity": "high",
        "violation_summary": "s",
        "queries": [{}],
    }
    hit = {"Flow": "start=rtr-us5 [10.10.10.0:49152->10.20.0.5:443 TCP]",
           "Line_Content": "deny   ip 10.10.10.0 0.0.0.255 any"}
    return pc._describe(rule, [hit])


@pytest.mark.parametrize("kind", ["prohibition", "requirement"])
def test_the_safeguard_can_read_what_policy_compliance_actually_writes(kind):
    """The join, asserted against the real producer rather than a literal."""
    detail = _real_detail(kind)
    outcome = _compute_policy_outcome(detail)

    assert outcome is not None, (
        f"policy_compliance._describe() emits a {kind} string this module "
        f"cannot parse, so the safeguard silently stops helping: {detail!r}"
    )


@pytest.mark.parametrize(
    "kind, current, required",
    [("prohibition", "PERMITTED", "FORBIDS"), ("requirement", "DENIED", "REQUIRES")],
)
def test_the_computed_outcome_matches_the_direction_it_was_given(kind, current, required):
    """Both halves right, not just parseable.

    Parsing the string and then attributing the wrong side would be the
    original bug with an extra step, so the direction is checked too.
    """
    outcome = _compute_policy_outcome(_real_detail(kind))
    assert current in outcome, f"{kind}: should say the traffic is currently {current}"
    assert required in outcome.upper(), f"{kind}: should say what the policy {required}"


def test_evidence_never_leaves_the_required_action_as_a_pronoun():
    """#145 itself: both wordings must name the action, not refer to it.

    The defect was "policy forbids it" / "policy requires it" -- the required
    action left as a reference the reader resolves to the nearest noun, which
    is the flow's CURRENT treatment, i.e. backwards.
    """
    for kind in ("prohibition", "requirement"):
        detail = _real_detail(kind)
        assert "requires it to be" in detail, f"{kind}: names the required action"
        assert "forbids it." not in detail, f"{kind}: no bare pronoun ending"
        assert "requires it." not in detail, f"{kind}: no bare pronoun ending"
