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


def stage(monkeypatch, rules, verdicts, breach=(False, False), devices=None,
          user_supplied=True):
    """Run the policy stage with fixed rules and fixed per-snapshot verdicts.

    `verdicts` maps rule number -> (breached_before, breached_after), or to an
    Exception to raise when that rule is asked. `breach` is what
    `_breach_changed` reports for a rule breached on both sides: (grew,
    shrank). Returns (findings, unchanged, number), plus the whole stage dict.

    It returns the stage's own findings and nothing it makes up: CH-051 is
    built by analyse_change(), so it is tested there, against the real code
    (#406 review, item 3).
    """
    monkeypatch.setattr(pc, "rules_in_use", lambda: (rules, "test policy", user_supplied))

    def fake(bf, snapshot, r):
        v = verdicts[r["number"]]
        if isinstance(v, Exception):
            raise v
        return v[0] if snapshot == change_impact.BEFORE_SNAPSHOT else v[1]

    monkeypatch.setattr(change_impact, "_rule_breached", fake)
    monkeypatch.setattr(change_impact, "_breach_changed", lambda bf, r: breach)
    before, after = devices if devices else (None, None)
    out = change_impact._policy_change_findings(object(), 1, before, after)
    unchanged = [f"{n} (holds)" for n in out["unchanged"]]
    return list(out["findings"]), unchanged, out["number"], out


# --- the four outcomes -----------------------------------------------------

def test_a_change_that_causes_a_breach_says_it_breaks_the_rule(monkeypatch):
    found, unchanged, _, _ = stage(monkeypatch, [rule(1, "prohibition")], {1: (False, True)})
    assert len(found) == 1
    f = found[0]
    assert f["status"] == "found"
    assert "BREAKS" in f["summary"] and "rule 1" in f["summary"]
    assert f["severity"] == "high", "a created breach carries the rule's own severity"
    assert unchanged == []


def test_a_change_that_repairs_a_breach_says_it_fixes_the_rule(monkeypatch):
    found, _, _, _ = stage(monkeypatch, [rule(1, "prohibition")], {1: (True, False)})
    assert len(found) == 1
    assert "FIXES" in found[0]["summary"]
    assert found[0]["severity"] == "low", "a fix is good news, not a high finding"


def test_a_change_that_fixes_one_and_breaks_another_reports_both(monkeypatch):
    """US-31's own criterion, and the reason this stage exists."""
    found, _, _, _ = stage(
        monkeypatch,
        [rule(1, "prohibition"), rule(4, "requirement", severity="medium")],
        {1: (True, False), 4: (False, True)},
    )
    summaries = [f["summary"] for f in found]
    assert any("FIXES" in s and "rule 1" in s for s in summaries)
    assert any("BREAKS" in s and "rule 4" in s for s in summaries)


def test_a_rule_that_holds_either_side_is_unchanged_not_a_finding(monkeypatch):
    found, unchanged, _, _ = stage(monkeypatch, [rule(1, "prohibition")], {1: (False, False)})
    assert found == []
    assert unchanged == ["1 (holds)"]


def test_a_rule_breached_on_both_sides_is_never_a_green_tick(monkeypatch):
    """#402 item 4. "Still breached" sat inside the `none` card, which the
    propose pane draws as a tick. A violation that survives the change is
    still a violation."""
    found, unchanged, _, _ = stage(monkeypatch, [rule(2, "prohibition")], {2: (True, True)})
    assert unchanged == []
    assert len(found) == 1 and found[0]["status"] == "found"
    assert "breached before and after" in found[0]["summary"]
    assert found[0]["severity"] == "low", "not caused by this change"


def test_a_breach_that_moves_to_other_traffic_is_reported_as_altered(monkeypatch):
    """Closing LAN->8.8.8.8 while opening LAN->1.1.1.1 keeps a rule breached
    throughout; the differential query says traffic moved both ways."""
    found, _, _, _ = stage(monkeypatch, [rule(2, "prohibition")], {2: (True, True)},
                           breach=(True, True))
    assert "alters how" in found[0]["summary"]
    assert found[0]["severity"] == "high", "it is the rule's own severity"
    assert "Direction: changed" in found[0]["evidence"]["detail"]


@pytest.mark.parametrize("kind,direction", [("prohibition", "opening"),
                                            ("requirement", "tightening")])
def test_a_breach_that_only_grows_is_the_rules_own_severity(monkeypatch, kind, direction):
    found, _, _, _ = stage(monkeypatch, [rule(2, kind)], {2: (True, True)},
                           breach=(True, False))
    assert "widens how" in found[0]["summary"]
    assert found[0]["severity"] == "high"
    assert f"Direction: {direction}" in found[0]["evidence"]["detail"]


@pytest.mark.parametrize("kind,direction", [("prohibition", "tightening"),
                                            ("requirement", "opening")])
def test_a_breach_that_only_shrinks_is_low_never_high(monkeypatch, kind, direction):
    """#406 review, item 1. A pure deny shrinks a prohibition's breach. Rated
    at the rule's own severity, it raised the "opens access" banner."""
    found, _, _, _ = stage(monkeypatch, [rule(2, kind)], {2: (True, True)},
                           breach=(False, True))
    assert "narrows how" in found[0]["summary"]
    assert found[0]["severity"] == "low"
    assert f"Direction: {direction}" in found[0]["evidence"]["detail"]
    assert "still breached" in found[0]["evidence"]["detail"]


@pytest.mark.parametrize("kind,before,after,direction", [
    ("prohibition", False, True, "opening"),     # forbidden traffic now permitted
    ("prohibition", True, False, "tightening"),
    ("requirement", False, True, "tightening"),  # required traffic now denied
    ("requirement", True, False, "opening"),
])
def test_direction_is_stated_in_this_modules_own_terms(monkeypatch, kind, before, after, direction):
    found, _, _, _ = stage(monkeypatch, [rule(1, kind)], {1: (before, after)})
    assert f"Direction: {direction}" in found[0]["evidence"]["detail"]


# --- F-4: could-not-ask is never unchanged ----------------------------------

def test_a_rule_that_cannot_be_asked_is_an_error_never_unchanged(monkeypatch):
    found, unchanged, _, out = stage(
        monkeypatch, [rule(1, "prohibition"), rule(2, "prohibition")],
        {1: RuntimeError("searchFilters failed"), 2: (False, False)},
    )
    assert len(out["not_compared"]) == 1 and "rule 1" in out["not_compared"][0]
    assert unchanged == ["2 (holds)"], "the rule we could not ask must not be listed as holding"


def test_the_ids_this_stage_emits_are_unique(monkeypatch):
    found, _, _, _ = stage(
        monkeypatch, [rule(n, "prohibition") for n in (1, 2, 3)] + [rule(9, "prohibition")],
        {1: (False, True), 2: (True, False), 3: (False, True), 9: RuntimeError("x")},
    )
    ids = [f["id"] for f in found]
    assert len(ids) == len(set(ids))


# --- device names: compared as Batfish compares them (#406 review, item 2) ---

def test_a_device_named_in_capitals_is_still_the_device_batfish_found(monkeypatch):
    r = dict(rule(1, "prohibition"), node="RTR-US5")
    found, _, _, out = stage(monkeypatch, [r], {1: (False, True)},
                             devices=({"rtr-us5"}, {"rtr-us5"}))
    assert out["absent"] == [] and out["not_compared"] == []
    assert "BREAKS" in found[0]["summary"], "a breach the change caused, not a tick"


def test_the_comparison_is_case_free_from_either_side(monkeypatch):
    """Batfish's names are lower case today; the rule is "compare as Batfish
    resolves", not "trust that the set happens to be lower case"."""
    found, _, _, out = stage(monkeypatch, [rule(1, "prohibition")], {1: (False, True)},
                             devices=({"RTR-US5"}, {"RTR-US5"}))
    assert out["absent"] == [] and out["not_compared"] == []
    assert "BREAKS" in found[0]["summary"]


def test_the_users_rule_about_a_device_in_neither_config_is_not_compared(monkeypatch):
    """A scan calls this PC-050, could not check. A tick here would disagree."""
    r = dict(rule(1, "prohibition"), node="edge-fw9")
    _, _, _, out = stage(monkeypatch, [r], {1: (False, False)},
                         devices=({"rtr-us5"}, {"rtr-us5"}), user_supplied=True)
    assert out["absent"] == []
    assert len(out["not_compared"]) == 1 and "edge-fw9" in out["not_compared"][0]


def test_our_example_rule_about_a_device_in_neither_config_is_not_applicable(monkeypatch):
    """#402 item 1 still holds for the built-in rules: an error there made
    every proposal on a network without rtr-us5 unverified."""
    r = dict(rule(1, "prohibition"), node="edge-fw9")
    _, _, _, out = stage(monkeypatch, [r], {1: (False, False)},
                         devices=({"rtr-us5"}, {"rtr-us5"}), user_supplied=False)
    assert out["absent"] == ["1 (edge-fw9)"] and out["not_compared"] == []


# --- _breach_changed reads both verdicts, from the real differential call ---

class _Frame:
    def __init__(self, rows):
        self._rows = rows

    def iterrows(self):
        return enumerate(self._rows)


class _DiffSession:
    """Records every differential searchFilters call; answers per query."""

    def __init__(self, rows_per_query):
        self.calls = []
        rows = iter(rows_per_query)
        session = self

        class _Q:
            def searchFilters(self, **kwargs):
                class _A:
                    def answer(self, **answer_kwargs):
                        session.calls.append(answer_kwargs)
                        frame = _Frame(next(rows))
                        return type("R", (), {"frame": lambda self: frame})()
                return _A()
        self.q = _Q()


def _row(now, then):
    return {"Snapshot_Action": now, "Reference_Action": then}


@pytest.mark.parametrize("kind,rows,expected", [
    ("prohibition", [_row("PERMIT", "DENY")], (True, False)),     # newly permitted: grew
    ("prohibition", [_row("DENY", "PERMIT")], (False, True)),     # newly denied: shrank
    ("prohibition", [_row("DENY", "PERMIT"), _row("PERMIT", "DENY")], (True, True)),
    ("requirement", [_row("DENY", "PERMIT")], (True, False)),     # newly denied: grew
    ("requirement", [_row("PERMIT", "DENY")], (False, True)),
    ("prohibition", [], (False, False)),
])
def test_breach_changed_reads_which_way_each_flow_moved(kind, rows, expected):
    bf = _DiffSession([rows])
    assert change_impact._breach_changed(bf, rule(1, kind)) == expected
    assert bf.calls == [{"snapshot": change_impact.AFTER_SNAPSHOT,
                         "reference_snapshot": change_impact.BEFORE_SNAPSHOT}]


def test_breach_changed_asks_every_query_arm():
    r = dict(rule(1, "prohibition"), queries=[{"dstIps": "10.20.0.5"}, {"dstIps": "10.20.0.6"}])
    bf = _DiffSession([[], [_row("PERMIT", "DENY")]])
    assert change_impact._breach_changed(bf, r) == (True, False)
    assert len(bf.calls) == 2


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
    monkeypatch.setattr(change_impact, "_devices", lambda bf: ({"rtr-us5"}, {"rtr-us5"}))
    if policy_stage is not None:
        monkeypatch.setattr(change_impact, "_policy_change_findings", policy_stage)


def test_unchanged_rules_join_the_all_clear_rather_than_a_second_ch000(monkeypatch):
    """Two cards both numbered 0 would collide on id. When nothing moved,
    the unchanged rules are named inside the single all-clear."""
    _stub_pipeline(monkeypatch, policy_stage=lambda bf, n, b=None, a=None: {"findings": [], "unchanged": ["1", "2"], "number": n})
    results = change_impact.analyse_change("before", "after")
    assert len(results) == 1
    assert results[0]["status"] == "none"
    assert "1, 2" in results[0]["evidence"]["detail"]


def test_with_real_changes_the_unchanged_rules_still_get_reported(monkeypatch):
    moved = change_impact.findings.make_finding(
        check="change_impact", severity="high", device="rtr-us5", summary="moved",
        detail="d", source="s", status="found", number=1)
    _stub_pipeline(monkeypatch, filters=[moved],
                   policy_stage=lambda bf, n, b=None, a=None: {"findings": [], "unchanged": ["3"], "number": n})
    results = change_impact.analyse_change("before", "after")
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids))
    assert any(f["status"] == "none" and "3." in f["evidence"]["detail"] for f in results)


def test_rules_not_compared_become_a_real_ch051_error(monkeypatch):
    """#406 review, item 3: the CH-051 card analyse_change() builds, not one
    a test made up. Both lists reach it."""
    _stub_pipeline(monkeypatch, policy_stage=lambda bf, n, b=None, a=None: {
        "findings": [], "unchanged": [], "number": n,
        "not_compared": ["rule 1: searchFilters failed"],
        "one_side": ["rule 2: rtr-b is in the after configuration only"]})
    results = change_impact.analyse_change("before", "after")
    card = [f for f in results if f["id"] == "CH-051"]
    assert len(card) == 1 and card[0]["status"] == "error"
    assert "2 policy rule(s)" in card[0]["summary"]
    assert "searchFilters failed" in card[0]["evidence"]["detail"]
    assert "after configuration only" in card[0]["evidence"]["detail"]
    assert not any(f["status"] == "none" and "No change detected" in f["summary"] for f in results)


def test_a_failed_filter_comparison_is_ch050_never_no_change(monkeypatch):
    """#406 review: silencing this path turned a failed compareFilters into
    a green "No change detected"."""
    _stub_pipeline(monkeypatch, policy_stage=lambda bf, n, b=None, a=None: {
        "findings": [], "unchanged": [], "number": n})

    def broken(bf, n):
        raise RuntimeError("compareFilters failed")
    monkeypatch.setattr(change_impact, "_filter_change_findings", broken)
    results = change_impact.analyse_change("before", "after")
    assert [f["id"] for f in results if f["status"] == "error"] == ["CH-050"]
    assert not any(f["status"] == "none" for f in results)


def test_a_long_diff_never_folds_away_a_broken_policy_rule():
    """#406 review: 60 moved lines plus a removed DNS line hid "BREAKS rule 4"
    inside "15 further change(s)"."""
    mk = change_impact.findings.make_finding
    lines = [mk(check="change_impact", severity="high", device="rtr-us5",
                summary=f"line {i}", detail="d", source="rtr-us5:acl_in",
                status="found", number=i) for i in range(1, 61)]
    breaks = mk(check="change_impact", severity="high", device="rtr-us5",
                summary="This change BREAKS policy rule 4", detail="d",
                source="your policy; rule 4", status="found", number=61)
    kept = change_impact._cap(lines + [breaks])
    assert len(kept) == 49 and kept[-1]["id"] == "CH-049", "48 kept, plus the summary"
    assert any("BREAKS policy rule 4" in f["summary"] for f in kept[:-1])
    ids = [f["id"] for f in kept[:-1]]
    assert ids == sorted(ids), "what is kept stays in the order found"


def test_the_policy_is_cleared_even_when_the_stage_raises(monkeypatch):
    """A policy outliving the call that supplied it would answer the next
    caller's question with someone else's rules."""
    def boom(bf, n, b=None, a=None):
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


@needs_batfish
def test_live_a_pure_deny_narrows_a_breach_and_raises_no_banner():
    """#406 review, item 1, through the public entry point named there."""
    from ai.propose import propose_change
    out = propose_change("block 10.10.10.5 to 10.20.0.5 on tcp/22 on rtr-us5",
                         FIXTURES / "rtr-us5-insecure")
    assert out["warning"] is False, out["answer"]
    assert any("narrows how policy rule 2" in f["summary"] and f["severity"] == "low"
               for f in out["impact"])
    assert not any(f["severity"] == "high" for f in out["impact"])


@needs_batfish
def test_live_a_device_named_in_capitals_still_reports_the_breach(tmp_path):
    """#406 review, item 2: `hostname RTR-US5`, policy `device: RTR-US5`, the
    change removes DNS. Main found the breach; the first version of this
    branch filed it under a tick."""
    secure = (FIXTURES / "rtr-us5-secure" / "configs" / "rtr-us5.cfg").read_text()
    before = secure.replace("hostname rtr-us5", "hostname RTR-US5")
    after = "\n".join(line for line in before.splitlines() if "eq domain" not in line) + "\n"
    for name, text in (("before", before), ("after", after)):
        (tmp_path / name / "configs").mkdir(parents=True)
        (tmp_path / name / "configs" / "rtr-us5.cfg").write_text(text)
    policy = policy_module.load_policy({"device": "RTR-US5", "policy_compliance": [{
        "number": 1, "description": "DNS to the approved resolver must work",
        "kind": "requirement", "filter": "acl_in", "violation_severity": "high",
        "violation_summary": "DNS blocked",
        "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "218.8.104.58",
                     "ipProtocols": ["udp"], "dstPorts": "53"}]}]})
    results = change_impact.analyse_change(tmp_path / "before", tmp_path / "after",
                                           policy=policy)
    assert any("BREAKS policy rule 1" in f["summary"] and f["severity"] == "high"
               for f in results), [f["summary"] for f in results]
