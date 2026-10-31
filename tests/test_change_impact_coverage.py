"""What change impact looked at, and what it says it looked at (#403, #402).

Every test here is a case where the old answer was confident and wrong:

    #403        a router deleted between before and after -> "No change detected"
    #402 item 1 a network without rtr-us5 -> every proposal "could not be verified"
    #402 item 3 a policy of access_control rules -> silence about them
    #402 item 5 four mutants that only a live test (skipped on CI) could catch
    #402 item 6 a failed reachability stage silently skipping the policy stage,
                and ids that a long diff could collide with
"""

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from analysis import change_impact, findings, policy as policy_module
from analysis.checks import policy_compliance as pc
from conftest import needs_batfish

FIXTURES = Path(__file__).parent / "fixtures"


def _pipeline(monkeypatch, *, devices=({"rtr-us5"}, {"rtr-us5"}), filters=(),
              flows_raise=False, stage=None):
    monkeypatch.setattr(change_impact, "connect", lambda host=None: SimpleNamespace(
        set_network=lambda n: None, set_snapshot=lambda n: None))
    monkeypatch.setattr(change_impact, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(change_impact, "find_parse_problems", lambda bf: [])
    monkeypatch.setattr(change_impact, "_devices", lambda bf: devices)
    monkeypatch.setattr(change_impact, "_filter_change_findings",
                        lambda bf, n: (list(filters), n + len(filters)))

    def flows(bf, n):
        if flows_raise:
            raise RuntimeError("differentialReachability exploded")
        return [], n
    monkeypatch.setattr(change_impact, "_reachability_change_findings", flows)
    if stage is not None:
        monkeypatch.setattr(change_impact, "_policy_change_findings", stage)
    else:
        monkeypatch.setattr(change_impact, "_policy_change_findings",
                            lambda bf, n, b=None, a=None: {"findings": [], "number": n})


def _found(n, severity="high"):
    return findings.make_finding(check="change_impact", severity=severity, device="r",
                                 summary=f"change {n}", detail="d", source="s",
                                 status="found", number=n)


# --- #403: devices on one side only ------------------------------------------

def test_a_removed_device_is_a_change_never_no_change_detected(monkeypatch):
    _pipeline(monkeypatch, devices=({"rtr-a", "rtr-b"}, {"rtr-a"}))
    results = change_impact.analyse_change("before", "after")
    assert not any("No change detected" in f["summary"] for f in results)
    removed = [f for f in results if "removed" in f["summary"]]
    assert len(removed) == 1 and removed[0]["status"] == "found"
    assert removed[0]["device"] == "rtr-b"


def test_an_added_device_is_a_change(monkeypatch):
    _pipeline(monkeypatch, devices=({"rtr-a"}, {"rtr-a", "rtr-c"}))
    results = change_impact.analyse_change("before", "after")
    added = [f for f in results if "added" in f["summary"]]
    assert len(added) == 1 and added[0]["status"] == "found" and added[0]["device"] == "rtr-c"


def test_unknown_device_lists_are_an_error_never_no_change(monkeypatch):
    """None means "we could not find out", which is not "nothing changed"."""
    _pipeline(monkeypatch, devices=({"rtr-a"}, None))
    results = change_impact.analyse_change("before", "after")
    assert [f["status"] for f in results] == ["error"]
    assert results[0]["id"] == "CH-052"


# --- #402 item 1: rules about devices that are not there ----------------------

def _rule(n, node="rtr-us5", kind="prohibition"):
    return {"number": n, "kind": kind, "node": node, "filter": "acl_in",
            "description": f"rule {n}", "violation_severity": "high",
            "violation_summary": "x", "queries": [{"dstIps": "10.20.0.5"}]}


def test_a_rule_about_a_device_in_neither_config_is_not_applicable_not_an_error(monkeypatch):
    monkeypatch.setattr(pc, "rules_in_use", lambda: ([_rule(1)], "built-in", False))
    monkeypatch.setattr(change_impact, "_rule_breached",
                        lambda *a: pytest.fail("must not ask Batfish about an absent device"))
    out = change_impact._policy_change_findings(object(), 1, {"edge-fw1"}, {"edge-fw1"})
    assert out["absent"] == ["1 (rtr-us5)"]
    assert out["not_compared"] == [] and out["findings"] == []


def test_a_stranger_network_is_verified_rather_than_could_not_compare(monkeypatch):
    """Arsh's repro, end to end through analyse_change: five built-in rules
    about rtr-us5 on a network called edge-fw1 produced CH-051 x5 errors, so
    propose_change() said verified=False on every request."""
    monkeypatch.setattr(pc, "rules_in_use", lambda: ([_rule(n) for n in range(1, 6)], "built-in", False))
    _pipeline(monkeypatch, devices=({"edge-fw1"}, {"edge-fw1"}),
              stage=change_impact._policy_change_findings)
    results = change_impact.analyse_change("before", "after")
    assert all(f["status"] != "error" for f in results), results
    assert "neither configuration" in results[0]["evidence"]["detail"]


def test_a_rule_about_a_device_on_one_side_only_cannot_be_compared(monkeypatch):
    monkeypatch.setattr(pc, "rules_in_use", lambda: ([_rule(1, node="rtr-b")], "built-in", False))
    out = change_impact._policy_change_findings(object(), 1, {"rtr-a", "rtr-b"}, {"rtr-a"})
    assert len(out["one_side"]) == 1 and "before configuration only" in out["one_side"][0]


# --- #402 item 3: say what was not compared ------------------------------------

def _policy(**sections):
    return policy_module.load_policy({"device": "rtr-us5", **sections})


AC_RULE = {"node": "rtr-us5", "description": "8443 must be denied", "filter": "acl_in",
           "headers": {"dstPorts": "8443"}, "expected": "DENY",
           "violation_severity": "high", "violation_summary": "8443 open"}


def test_rules_in_sections_change_impact_does_not_compare_are_named(monkeypatch):
    policy_module.set_active_policy(_policy(access_control=[AC_RULE],
                                            policy_compliance=[_rule(1)]))
    try:
        _, _, _, note = change_impact._policy_coverage()
    finally:
        policy_module.clear_active_policy()
    assert note.startswith("NOT compared")
    assert "1 access_control" in note


def test_a_policy_with_no_policy_compliance_rules_says_so_loudly():
    policy_module.set_active_policy(_policy(access_control=[AC_RULE]))
    try:
        rules, _, _, note = change_impact._policy_coverage()
    finally:
        policy_module.clear_active_policy()
    assert rules == []
    assert "no policy_compliance rules" in note and "no rule of yours was checked" in note


# --- #402 item 5: the mutants a fake session can catch -------------------------

class _Session:
    """Records every question _rule_breached asks, answers from a table."""

    def __init__(self, breached_arms):
        self.snapshots, self.asked, self.breached = [], [], breached_arms
        self.current = None
        self.q = SimpleNamespace(searchFilters=self._search)

    def set_snapshot(self, name):
        self.current = name
        self.snapshots.append(name)

    def _search(self, nodes, filters, action, headers):
        self.asked.append((self.current, action, str(headers)))
        rows = 1 if (self.current, str(headers)) in self.breached else 0
        return SimpleNamespace(answer=lambda **k: SimpleNamespace(
            frame=lambda: SimpleNamespace(__len__=lambda s: rows, iloc=[None] * rows)))


def test_rule_breached_switches_to_the_snapshot_it_is_asked_about(monkeypatch):
    calls = []
    monkeypatch.setattr(pc, "_search", lambda bf, n, f, a, h: calls.append((bf.current, a)) or [])
    s = _Session(set())
    change_impact._rule_breached(s, change_impact.AFTER_SNAPSHOT, _rule(1))
    assert s.snapshots == [change_impact.AFTER_SNAPSHOT]
    assert calls[0][0] == change_impact.AFTER_SNAPSHOT


@pytest.mark.parametrize("kind", ["prohibition", "requirement"])
def test_rule_breached_asks_with_the_checks_own_action_for_the_kind(monkeypatch, kind):
    seen = []
    monkeypatch.setattr(pc, "_search", lambda bf, n, f, a, h: seen.append(a) or [])
    change_impact._rule_breached(_Session(set()), change_impact.BEFORE_SNAPSHOT, _rule(1, kind=kind))
    assert seen == [pc.ACTION_BY_KIND[kind]]


def test_rule_breached_asks_every_arm_not_just_the_first(monkeypatch):
    """Survived without Batfish before: only the second arm breaches."""
    r = _rule(1)
    r["queries"] = [{"dstIps": "10.20.0.5"}, {"dstIps": "10.20.0.6"}]
    monkeypatch.setattr(pc, "_search", lambda bf, n, f, a, h: [1] if h["dstIps"] == "10.20.0.6" else [])
    assert change_impact._rule_breached(_Session(set()), change_impact.BEFORE_SNAPSHOT, r) is True


def test_the_policy_passed_in_is_the_policy_evaluated(monkeypatch):
    """Survived both with and without Batfish: set_active_policy(None) in
    place of set_active_policy(policy)."""
    mine = _policy(policy_compliance=[_rule(7)])
    seen = []

    def stage(bf, n, b=None, a=None):
        seen.append(policy_module.active_policy())
        return {"findings": [], "number": n}
    _pipeline(monkeypatch, stage=stage)
    change_impact.analyse_change("before", "after", policy=mine)
    assert seen == [mine]
    assert policy_module.active_policy() is None, "and it is cleared afterwards"


# --- #402 item 6: stages are independent, ids cannot collide -------------------

def test_the_policy_stage_runs_when_reachability_fails(monkeypatch):
    ran = []

    def stage(bf, n, b=None, a=None):
        ran.append(True)
        return {"findings": [_found(n)], "number": n + 1}
    _pipeline(monkeypatch, flows_raise=True, stage=stage)
    results = change_impact.analyse_change("before", "after")
    assert ran == [True]
    assert {f["status"] for f in results} == {"found", "error"}


def test_a_long_diff_cannot_collide_with_the_reserved_ids(monkeypatch):
    """60 filter findings used to be numbered CH-001..CH-060, two of which
    are this module's own error cards."""
    _pipeline(monkeypatch, filters=[_found(n) for n in range(1, 61)], flows_raise=True)
    results = change_impact.analyse_change("before", "after")
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids)), ids
    assert "CH-049" in ids and "further change" in next(f for f in results if f["id"] == "CH-049")["summary"]
    assert max(int(i[3:]) for i in ids if i != "CH-049" and not i.startswith("CH-05")) <= 48


def test_the_change_impact_cli_prints_every_policy_note(monkeypatch, capsys, tmp_path):
    p = tmp_path / "p.json"
    p.write_text('{"device": "rtr-us5", "policy_compliance": [{"description": "d", '
                 '"kind": "prohibition", "filter": "acl_in", "violation_severity": "high", '
                 '"violation_summary": "s", "queries": [{"dstIps": "10.20.0.5"}]}]}')
    monkeypatch.setattr(change_impact, "analyse_change", lambda *a, **k: [])
    monkeypatch.setattr("sys.argv", ["change_impact", "b", "a", str(p)])
    change_impact.main()
    assert any(line.startswith("note:") for line in capsys.readouterr().out.splitlines()), \
        "the assigned rule number is a note the CLI used to drop"


# --- live, against real Batfish ---------------------------------------------

@needs_batfish
def test_live_removing_a_device_is_reported(tmp_path):
    """#403's own repro: multi-device-10 minus rtr-dev009."""
    after = tmp_path / "after"
    shutil.copytree(FIXTURES / "multi-device-10", after)
    (after / "configs" / "rtr-dev009.cfg").unlink()
    results = change_impact.analyse_change(FIXTURES / "multi-device-10", after)
    assert not any("No change detected" in f["summary"] for f in results)
    assert any(f["device"] == "rtr-dev009" and "removed" in f["summary"] for f in results)


@needs_batfish
def test_live_a_stranger_network_proposal_is_verified(tmp_path):
    """#402 item 1's repro: rtr-us5 renamed edge-fw1. Before this, every
    built-in rule came back as CH-051 and verified was False."""
    for side in ("before", "after"):
        d = tmp_path / side / "configs"
        d.mkdir(parents=True)
        text = (FIXTURES / "rtr-us5-secure" / "configs" / "rtr-us5.cfg").read_text()
        d.joinpath("edge-fw1.cfg").write_text(text.replace("hostname rtr-us5", "hostname edge-fw1"))
    results = change_impact.analyse_change(tmp_path / "before", tmp_path / "after")
    assert all(f["status"] != "error" for f in results), [f["summary"] for f in results]
