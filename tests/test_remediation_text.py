"""
Netwise -- tests for ai/explain.py's deterministic remediation text (#221).

WHY THIS IS ITS OWN FILE, NOT AN ADDITION TO test_explain_safety_net.py
    That file tests the two lines of defence around what the MODEL says.
    Remediation never calls the model at all (ai/Modelfile rule 6 forbids
    it recommending a fix unless the evidence already states one, and this
    feature stays entirely on the safe side of that line) -- it is pure
    regex-over-a-string logic, testing a genuinely different question ("what
    would fix this" rather than "what does this mean"). Keeping it separate
    means a change to one file's assumptions cannot silently affect the
    other's.

WHAT THESE TESTS PIN
    Real evidence.detail text, pulled from this project's own fixtures via
    the actual pipeline (see the comment above each detail string for which
    fixture and finding id it came from) -- not invented shapes. Coverage
    measured directly before writing this file:

        rtr-us5-insecure: 4/5 found-status findings match a known shape
        rtr-us5-messy:    5/6 found-status findings match a known shape

    The two misses (a GUARANTEES/searchFilters proof, and an undefined-
    reference finding) are tested explicitly below to confirm they return
    None rather than a stretched guess.

RUN
    pytest tests/test_remediation_text.py -v
"""

from ai.explain import (
    _remediate_dead_rule,
    _remediate_expected_actual,
    _remediate_policy_mismatch,
    remediate_with_source,
)

# --- _remediate_dead_rule -----------------------------------------------------
# Real evidence.detail from tests/fixtures/rtr-us5-messy, findings AC-002/AC-003.


def test_names_the_shadowing_line_for_a_dead_rule():
    detail = (
        "Unreachable line: permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 "
        "eq domain (action PERMIT). Blocked by: deny   ip 10.10.10.0 "
        "0.0.255 any. Reason: BLOCKING_LINES"
    )
    remediation = _remediate_dead_rule(detail)
    assert remediation is not None
    assert "deny   ip 10.10.10.0 0.0.255 any" in remediation
    assert "shadows it" in remediation


def test_dead_rule_returns_none_for_unrelated_detail():
    assert _remediate_dead_rule("BatfishException: Work terminated abnormally") is None


def test_dead_rule_returns_none_when_blocking_lines_disagree():
    """Same ambiguity guard as _compute_dead_rule_outcome() -- multiple
    blocking lines means there is no single line to name as THE fix."""
    detail = (
        "Unreachable line: permit tcp any any eq 80 (action PERMIT). "
        "Blocked by: deny ip any any, permit tcp any any eq 443. "
        "Reason: BLOCKING_LINES"
    )
    assert _remediate_dead_rule(detail) is None


# --- _remediate_policy_mismatch -----------------------------------------------
# Real evidence.detail from tests/fixtures/rtr-us5-insecure, finding PC-001,
# and rtr-us5-insecure's PC-002 for the "example flows matched" suffix.


def test_names_the_deciding_rule_for_a_policy_mismatch():
    detail = (
        "Flow start=rtr-us5 [10.10.10.0:49152->8.8.8.8:80 TCP (SYN)] is "
        "permitted but policy requires it to be DENIED. Decided by: permit "
        "ip any any [Rules checked: Netwise's built-in example policy "
        "(analysis/checks/policy_compliance.py) -- no policy file was "
        "supplied.]"
    )
    remediation = _remediate_policy_mismatch(detail)
    assert remediation is not None
    assert "`permit ip any any`" in remediation
    assert "DENIED" in remediation
    assert "policy is not what needs to change" in remediation


def test_the_example_flows_suffix_does_not_leak_into_the_named_rule():
    """_describe() appends '(N example flows matched)' after the deciding
    line when more than one flow matches it -- that is a flow COUNT, not
    part of the rule, and must not end up inside the backtick-quoted text a
    reader would try to copy."""
    detail = (
        "Flow start=rtr-us5 [10.10.10.0:49152->10.20.0.5:33434 UDP] is "
        "permitted but policy requires it to be DENIED. Decided by: permit "
        "ip any any (2 example flows matched) [Rules checked: Netwise's "
        "built-in example policy (analysis/checks/policy_compliance.py) -- "
        "no policy file was supplied.]"
    )
    remediation = _remediate_policy_mismatch(detail)
    assert remediation is not None
    assert "`permit ip any any`" in remediation
    assert "example flows matched" not in remediation


def test_policy_mismatch_names_the_correct_direction_for_a_requirement_violation():
    """Real evidence.detail from rtr-us5-messy, finding PC-004 -- the device
    denies what the policy requires, the opposite direction from PC-001."""
    detail = (
        "Flow start=rtr-us5 [10.10.10.0:49152->218.8.104.58:53 UDP] is "
        "denied but policy requires it to be PERMITTED. Decided by: "
        "deny   ip 10.10.10.0 0.0.0.255 any [Rules checked: Netwise's "
        "built-in example policy (analysis/checks/policy_compliance.py) -- "
        "no policy file was supplied.]"
    )
    remediation = _remediate_policy_mismatch(detail)
    assert remediation is not None
    assert "deny   ip 10.10.10.0 0.0.0.255 any" in remediation
    assert "PERMITTED" in remediation


def test_policy_mismatch_returns_none_for_unrelated_detail():
    assert _remediate_policy_mismatch("BatfishException: Work terminated abnormally") is None


def test_policy_mismatch_returns_none_for_a_dead_rule_finding():
    """The three shape-functions must not cross-match each other's text."""
    detail = (
        "Unreachable line: permit icmp any any (action PERMIT). "
        "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
    )
    assert _remediate_policy_mismatch(detail) is None


# --- _remediate_expected_actual ------------------------------------------------
# Real evidence.detail from tests/fixtures/rtr-us5-insecure, finding AC-001.


def test_names_the_deciding_rule_for_an_expected_actual_mismatch():
    detail = "Expected DENY but got PERMIT, decided by: permit ip any any"
    remediation = _remediate_expected_actual(detail)
    assert remediation is not None
    assert "`permit ip any any`" in remediation
    assert "DENY" in remediation


def test_expected_actual_returns_none_for_unrelated_detail():
    assert _remediate_expected_actual("BatfishException: Work terminated abnormally") is None


def test_expected_actual_returns_none_for_a_policy_mismatch_finding():
    """The three shape-functions must not cross-match each other's text."""
    detail = (
        "Flow start=10.20.0.5 is permitted but policy requires it to be "
        "DENIED. Decided by: permit ip any any"
    )
    assert _remediate_expected_actual(detail) is None


# --- The two known misses, confirmed rather than assumed ---------------------
# Real evidence.detail from tests/fixtures/rtr-us5-insecure (AC-002) and
# rtr-us5-messy (AC-004) -- neither is a shape any of the three functions
# above claims to cover, and both must return None rather than a guess.


def test_a_guarantees_proof_has_no_single_line_to_name():
    """AC-002 on rtr-us5-insecure: a searchFilters proof over a whole space
    of traffic, not one flow's fate -- there is no "decided by" line."""
    detail = (
        "Example permitted flow: start=rtr-us5 "
        "[10.10.10.0:49152->8.8.8.8:80 TCP (SYN)], allowed by: permit ip "
        "any any"
    )
    assert _remediate_dead_rule(detail) is None
    assert _remediate_policy_mismatch(detail) is None
    assert _remediate_expected_actual(detail) is None


def test_an_undefined_reference_needs_a_different_kind_of_guidance():
    """AC-004 on rtr-us5-messy: the fix is "define the missing structure",
    not "change this rule" -- a different claim than any of the three shapes
    above make, so none of them should match it."""
    detail = (
        "Referenced as: interface incoming ip access-list. The structure "
        "'acl_guest_in' is never defined in this snapshot."
    )
    assert _remediate_dead_rule(detail) is None
    assert _remediate_policy_mismatch(detail) is None
    assert _remediate_expected_actual(detail) is None


# --- remediate_with_source(): the public function -----------------------------


def test_remediate_with_source_reports_deterministic_as_the_source():
    finding = {
        "id": "AC-001",
        "status": "found",
        "summary": "x",
        "evidence": {"detail": "Expected DENY but got PERMIT, decided by: permit ip any any"},
    }
    result = remediate_with_source(finding)
    assert result is not None
    text, source = result
    assert source == "deterministic"
    assert "`permit ip any any`" in text


def test_remediate_with_source_returns_none_for_an_unmatched_finding():
    finding = {
        "id": "AC-004",
        "status": "found",
        "summary": "x",
        "evidence": {
            "detail": "Referenced as: interface incoming ip access-list. "
            "The structure 'acl_guest_in' is never defined in this snapshot."
        },
    }
    assert remediate_with_source(finding) is None


def test_remediate_with_source_returns_none_for_a_finding_with_no_evidence():
    """Same _evidence_detail() guard explain() relies on -- a finding with
    no usable evidence.detail has nothing to compute a remediation from."""
    finding = {"id": "AC-101", "status": "found", "summary": "A finding"}
    assert remediate_with_source(finding) is None


def test_remediate_with_source_never_raises_on_a_malformed_finding():
    """_evidence_detail() already guarantees this for explain(); the same
    guarantee must hold here, since web/main.py's _attach_remediation() is
    documented to wrap this in try/except as defence in depth, not as the
    only thing standing between a malformed finding and a 500."""
    for finding in ({}, {"evidence": None}, {"evidence": {"detail": None}}):
        assert remediate_with_source(finding) is None


def test_remediate_with_source_prefers_the_first_matching_shape():
    """dead-rule, then policy-mismatch, then expected-actual, same order
    _remediate_dead_rule/_remediate_policy_mismatch/_remediate_expected_actual
    are tried in remediate_with_source() -- pinned so a future reordering is
    a visible, deliberate change rather than a silent one. No real finding
    is known to match more than one shape; this is a hypothetical string
    confirming which one wins if it ever did."""
    finding = {
        "id": "AC-999",
        "status": "found",
        "summary": "x",
        "evidence": {
            "detail": "Unreachable line: permit icmp any any (action PERMIT). "
            "Blocked by: deny   ip any any. Reason: BLOCKING_LINES"
        },
    }
    text, _ = remediate_with_source(finding)
    assert "shadows it" in text  # the dead-rule wording, not the other two's
