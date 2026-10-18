"""A proposed change, checked against every policy rule (#323, US-31).

WHAT THESE PIN
    `analyse_change()` used to answer "what traffic moved". It now also
    answers "which of my rules does that break or fix", by asking each
    policy_compliance rule the same question the check asks, once per
    snapshot.

    The case most worth pinning is the swap: one breach resolved and another
    created by the same edit. A net count of zero is exactly how that hides,
    and the live test at the bottom shows the filter and reachability stages
    alone report such an edit as pure tightening.
"""

from pathlib import Path

import pytest

from analysis import change_impact, policy as policy_module
from analysis.checks import policy_compliance as pc
from conftest import needs_batfish

FIXTURES = Path(__file__).parent / "fixtures"


def rule(number, kind, severity="high"):
    return {
        "number": number, "kind": kind, "node": "rtr-us5", "filter": "acl_in",
        "description": f"rule {number}", "violation_severity": severity,
        "violation_summary": f"rule {number} violated",
        "queries": [{"dstIps": "10.20.0.5"}],
    }


def stage(monkeypatch, rules, verdicts):
    """Run the policy stage with fixed rules and fixed per-snapshot verdicts.

    `verdicts` maps rule number -> (breached_before, breached_after), or to an
    Exception to raise when that rule is asked.
    """
    monkeypatch.setattr(pc, "rules_in_use", lambda: (rules, "test policy", True))

    def fake(bf, snapshot, r):
        v = verdicts[r["number"]]
        if isinstance(v, Exception):
            raise v
        return v[0] if snapshot == change_impact.BEFORE_SNAPSHOT else v[1]

    monkeypatch.setattr(change_impact, "_rule_breached", fake)
    return change_impact._policy_change_findings(object(), 1)


# --- the four outcomes -----------------------------------------------------

def test_a_change_that_causes_a_breach_says_it_breaks_the_rule(monkeypatch):
    found, unchanged, _ = stage(monkeypatch, [rule(1, "prohibition")], {1: (False, True)})
    assert len(found) == 1
    f = found[0]
    assert f["status"] == "found"
    assert "BREAKS" in f["summary"] and "rule 1" in f["summary"]
    assert f["severity"] == "high", "a created breach carries the rule's own severity"
    assert unchanged == []


def test_a_change_that_repairs_a_breach_says_it_fixes_the_rule(monkeypatch):
    found, _, _ = stage(monkeypatch, [rule(1, "prohibition")], {1: (True, False)})
    assert len(found) == 1
    assert "FIXES" in found[0]["summary"]
    assert found[0]["severity"] == "low", "a fix is good news, not a high finding"


def test_a_change_that_fixes_one_and_breaks_another_reports_both(monkeypatch):
    """US-31's own criterion, and the reason this stage exists."""
    found, _, _ = stage(
        monkeypatch,
        [rule(1, "prohibition"), rule(4, "requirement", severity="medium")],
        {1: (True, False), 4: (False, True)},
    )
    summaries = [f["summary"] for f in found]
    assert any("FIXES" in s and "rule 1" in s for s in summaries)
    assert any("BREAKS" in s and "rule 4" in s for s in summaries)


def test_a_rule_with_the_same_verdict_either_side_is_unchanged_not_a_finding(monkeypatch):
    found, unchanged, _ = stage(
        monkeypatch, [rule(1, "prohibition"), rule(2, "prohibition")],
        {1: (False, False), 2: (True, True)},
    )
    assert found == []
    assert unchanged == ["1 (holds)", "2 (still breached)"], (
        "a rule broken before AND after is unchanged -- this edit did not cause it"
    )


@pytest.mark.parametrize("kind,before,after,direction,normalised", [
    ("prohibition", False, True, "opening", "opening"),     # forbidden traffic now permitted
    ("prohibition", True, False, "tightening", "closing"),
    ("requirement", False, True, "tightening", "closing"),  # required traffic now denied
    ("requirement", True, False, "opening", "opening"),
])
def test_direction_is_stated_in_this_modules_own_terms(monkeypatch, kind, before, after, direction, normalised):
    found, _, _ = stage(monkeypatch, [rule(1, kind)], {1: (before, after)})
    assert f"Direction: {direction}" in found[0]["evidence"]["detail"]


@pytest.mark.parametrize("kind,before,after,normalised", [
    ("prohibition", False, True, "opening"),
    ("prohibition", True, False, "closing"),
    ("requirement", False, True, "closing"),
    ("requirement", True, False, "opening"),
])
def test_direction_field_is_set_regardless_of_severity(monkeypatch, kind, before, after, normalised):
    """#402: severity alone cannot be used to infer direction for a policy
    finding (a high-severity REQUIREMENT breach closes access, it does not
    open it) -- this is the field a caller should read instead."""
    found, _, _ = stage(
        monkeypatch, [rule(1, kind, severity="high")], {1: (before, after)},
    )
    assert found[0]["direction"] == normalised


# --- F-4: could-not-ask is never unchanged ----------------------------------

def test_a_rule_that_cannot_be_asked_is_an_error_never_unchanged(monkeypatch):
    found, unchanged, _ = stage(
        monkeypatch, [rule(1, "prohibition"), rule(2, "prohibition")],
        {1: RuntimeError("searchFilters failed"), 2: (False, False)},
    )
    errors = [f for f in found if f["status"] == "error"]
    assert len(errors) == 1
    assert "rule 1" in errors[0]["evidence"]["detail"]
    assert unchanged == ["2 (holds)"], "the rule we could not ask must not be listed as holding"


def test_the_ids_this_stage_emits_are_unique(monkeypatch):
    found, _, _ = stage(
        monkeypatch, [rule(n, "prohibition") for n in (1, 2, 3)] + [rule(9, "prohibition")],
        {1: (False, True), 2: (True, False), 3: (False, True), 9: RuntimeError("x")},
    )
    ids = [f["id"] for f in found]
    assert len(ids) == len(set(ids))


# --- how analyse_change() folds it in --------------------------------------

def _stub_pipeline(monkeypatch, *, filters=(), policy_stage=None):
    from types import SimpleNamespace
    monkeypatch.setattr(change_impact, "connect",
                        lambda host=None: SimpleNamespace(set_network=lambda n: None,
                                                          set_snapshot=lambda n: None))
    monkeypatch.setattr(change_impact, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(change_impact, "find_parse_problems", lambda bf: [])
    monkeypatch.setattr(change_impact, "_filter_change_findings",
                        lambda bf, n: (list(filters), n + len(filters)))
    monkeypatch.setattr(change_impact, "_reachability_change_findings", lambda bf, n: ([], n))
    if policy_stage is not None:
        monkeypatch.setattr(change_impact, "_policy_change_findings", policy_stage)


def test_unchanged_rules_join_the_all_clear_rather_than_a_second_ch000(monkeypatch):
    """Two cards both numbered 0 would collide on id. When nothing moved,
    the unchanged rules are named inside the single all-clear."""
    _stub_pipeline(monkeypatch, policy_stage=lambda bf, n: ([], ["1 (holds)", "2 (holds)"], n))
    results = change_impact.analyse_change("before", "after")
    assert len(results) == 1
    assert results[0]["status"] == "none"
    assert "1 (holds)" in results[0]["evidence"]["detail"]


def test_with_real_changes_the_unchanged_rules_still_get_reported(monkeypatch):
    moved = change_impact.findings.make_finding(
        check="change_impact", severity="high", device="rtr-us5", summary="moved",
        detail="d", source="s", status="found", number=1)
    _stub_pipeline(monkeypatch, filters=[moved],
                   policy_stage=lambda bf, n: ([], ["3 (holds)"], n))
    results = change_impact.analyse_change("before", "after")
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids))
    assert any(f["status"] == "none" and "3 (holds)" in f["evidence"]["detail"] for f in results)


def test_the_policy_is_cleared_even_when_the_stage_raises(monkeypatch):
    """A policy outliving the call that supplied it would answer the next
    caller's question with someone else's rules."""
    def boom(bf, n):
        raise RuntimeError("policy stage failed")
    _stub_pipeline(monkeypatch, policy_stage=boom)
    sentinel = policy_module.load_policy({"device": "rtr-us5", "policy_compliance": []})
    results = change_impact.analyse_change("before", "after", policy=sentinel)
    assert policy_module.active_policy() is None
    assert any(f["status"] == "error" and "policy comparison" in f["summary"] for f in results)


# --- live: the swap, against real Batfish ----------------------------------

@needs_batfish
def test_live_a_swap_is_reported_as_both_a_fix_and_a_break(tmp_path):
    """insecure -> (secure ACL minus its DNS line). Fixes the three holes,
    breaks the DNS requirement. The filter and reachability stages alone say
    only "blocks traffic", which reads as a safe hardening."""
    secure = (FIXTURES / "rtr-us5-secure" / "configs" / "rtr-us5.cfg").read_text()
    after = "\n".join(line for line in secure.splitlines() if "eq domain" not in line) + "\n"
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "rtr-us5.cfg").write_text(after)

    results = change_impact.analyse_change(FIXTURES / "rtr-us5-insecure", tmp_path)
    summaries = [f["summary"] for f in results]
    assert any("FIXES policy rule 1" in s for s in summaries)
    assert any("BREAKS policy rule 4" in s for s in summaries), summaries
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids))
