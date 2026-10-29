"""Two policies that are each fine, and contradict each other (Studio 6).

Security writes one policy for a firewall, the application owners another.
Each loads cleanly on its own, because load_policy() reads one file at a
time. Applied together, a prohibition in one and a requirement in the other
can describe the same traffic, and then no configuration satisfies both.

These pin `policy_conflicts.between()` and its command line.
"""

import json


from analysis import policy_conflicts
from analysis.policy import load_policy


def rule(n, kind, queries, node="rtr-us5", flt="acl_in"):
    return {"number": n, "description": f"rule {n}", "node": node, "kind": kind, "filter": flt,
            "violation_severity": "high", "violation_summary": "x", "queries": queries}


SECURITY = [rule(1, "prohibition", [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}])]
APP_OWNERS = [rule(1, "requirement", [{"srcIps": "10.10.10.64/26", "dstIps": "10.20.0.0/16",
                                       "ipProtocols": ["tcp"], "dstPorts": "443"}])]


def test_each_policy_loads_on_its_own():
    """The premise: nothing catches this today."""
    load_policy({"device": "rtr-us5", "policy_compliance": SECURITY})
    assert load_policy({"device": "rtr-us5", "policy_compliance": APP_OWNERS})


def test_a_prohibition_in_one_against_a_requirement_in_the_other_is_a_conflict():
    conflicts, undecided = policy_conflicts.between(SECURITY, APP_OWNERS, "security.json", "apps.json")
    assert len(conflicts) == 1 and undecided == []
    # The claim, not the sentence: which file forbids, which requires.
    forbidder, _, requirer = conflicts[0].partition(" forbids what ")
    assert forbidder.startswith("security.json rule 1")
    assert requirer.startswith("apps.json rule 1") and " requires " in requirer
    assert "10.10.10.64/26" in conflicts[0] and "443" in conflicts[0], "names the overlap"


def test_both_directions_are_checked():
    """The prohibition is in the SECOND file here."""
    conflicts, _ = policy_conflicts.between(APP_OWNERS, SECURITY, "apps.json", "security.json")
    assert len(conflicts) == 1
    forbidder, _, requirer = conflicts[0].partition(" forbids what ")
    assert forbidder.startswith("security.json rule 1"), "the file with the prohibition forbids"
    assert requirer.startswith("apps.json rule 1")


def test_rules_with_the_same_number_are_told_apart_by_their_file():
    """Both files have a "rule 1" -- the message must say which is which."""
    conflicts, _ = policy_conflicts.between(SECURITY, APP_OWNERS, "a.json", "b.json")
    assert "a.json rule 1" in conflicts[0] and "b.json rule 1" in conflicts[0]


def test_two_policies_that_agree_do_not_conflict():
    same = [rule(9, "prohibition", [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}])]
    assert policy_conflicts.between(SECURITY, same) == ([], [])


def test_disjoint_traffic_across_policies_does_not_conflict():
    other = [rule(1, "requirement", [{"srcIps": "192.168.1.0/24", "dstIps": "10.20.0.5"}])]
    assert policy_conflicts.between(SECURITY, other) == ([], [])


def test_different_devices_across_policies_do_not_conflict():
    elsewhere = [dict(APP_OWNERS[0], node="rtr-hq")]
    assert policy_conflicts.between(SECURITY, elsewhere) == ([], [])


def test_a_pair_that_cannot_be_compared_is_reported_not_dropped():
    vague = [rule(1, "requirement", [{"dstIps": "0.0.0.0/0 \\ (1.1.1.1)"}])]
    conflicts, undecided = policy_conflicts.between(SECURITY, vague, "a.json", "b.json")
    assert conflicts == [] and len(undecided) == 1
    assert "a.json rule 1" in undecided[0] and "b.json rule 1" in undecided[0]


def test_within_one_policy_is_unchanged_by_the_refactor():
    """contradictions() and between() share one loop; this pins that the
    single-policy wording did not pick up a policy name."""
    conflicts, _ = policy_conflicts.contradictions(SECURITY + [dict(APP_OWNERS[0], number=2)])
    assert conflicts[0].startswith("rule 1 ('rule 1') forbids what rule 2")


# --- the command line ----------------------------------------------------------

def _write(path, entries):
    path.write_text(json.dumps({"device": "rtr-us5", "policy_compliance": entries}))
    return str(path)


def test_cli_reports_a_conflict_and_exits_1(tmp_path, capsys):
    a, b = _write(tmp_path / "security.json", SECURITY), _write(tmp_path / "apps.json", APP_OWNERS)
    assert policy_conflicts.main([a, b]) == 1
    out = capsys.readouterr().out
    assert out.startswith("CONFLICT: security.json rule 1")
    assert "forbids what apps.json rule 1" in out


def test_cli_exits_0_when_the_policies_agree(tmp_path, capsys):
    other = [rule(1, "requirement", [{"srcIps": "192.168.1.0/24", "dstIps": "10.20.0.5"}])]
    a, b = _write(tmp_path / "a.json", SECURITY), _write(tmp_path / "b.json", other)
    assert policy_conflicts.main([a, b]) == 0
    assert "No rule in a.json forbids what b.json requires" in capsys.readouterr().out


def test_cli_refuses_a_file_that_contradicts_itself_and_names_it(tmp_path, capsys):
    bad = _write(tmp_path / "bad.json", SECURITY + [dict(APP_OWNERS[0], number=2)])
    ok = _write(tmp_path / "ok.json", SECURITY)
    assert policy_conflicts.main([bad, ok]) == 2
    out = capsys.readouterr().out
    assert "bad.json: not loaded" in out and "contradicts itself" in out


def test_cli_prints_usage_with_the_wrong_number_of_files(capsys):
    assert policy_conflicts.main(["only-one.json"]) == 2
    assert "usage:" in capsys.readouterr().out
