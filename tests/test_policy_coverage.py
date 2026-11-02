"""Which interfaces and subnets does no policy rule talk about? (#421)"""

import ipaddress
from pathlib import Path

from analysis import policy_coverage as pcov
from conftest import needs_batfish

FIXTURES = Path(__file__).parent / "fixtures"


def rule(n, queries, node="rtr-hq"):
    return {"number": n, "node": node, "kind": "prohibition", "filter": "acl_in", "queries": queries}


def iface(name, subnet):
    return {"interface": name, "subnet": ipaddress.ip_network(subnet), "active": True}


NET = {"rtr-hq": [iface("Gi0/0", "10.10.10.0/24"), iface("Gi0/1", "10.1.1.0/30")]}


def covered(rows):
    return {r["interface"]: r["covered"] for r in rows}


def test_a_subnet_a_rule_names_is_covered_and_one_it_does_not_is_not():
    rows = pcov.coverage_map([rule(1, [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}])], NET)
    assert covered(rows) == {"Gi0/0": True, "Gi0/1": False}
    assert rows[0]["rules"] == [1]


def test_a_destination_counts_as_much_as_a_source():
    rows = pcov.coverage_map([rule(1, [{"srcIps": "192.168.0.0/16", "dstIps": "10.1.1.0/30"}])], NET)
    assert covered(rows) == {"Gi0/0": False, "Gi0/1": True}


def test_a_query_with_no_address_constraint_covers_everything():
    rows = pcov.coverage_map([rule(1, [{"dstPorts": "23"}])], NET)
    assert set(covered(rows).values()) == {True}


def test_a_rule_about_a_device_not_in_the_snapshot_covers_nothing():
    """It never runs (PC-050), so its addresses cannot count."""
    rows = pcov.coverage_map([rule(1, [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}], node="rtr-us5")], NET)
    assert set(covered(rows).values()) == {False}


def test_syntax_we_cannot_parse_is_unknown_not_uncovered():
    rows = pcov.coverage_map([rule(1, [{"srcIps": "0.0.0.0/0 \\ (1.1.1.1)", "dstIps": "10.20.0.5"}])], NET)
    assert set(covered(rows).values()) == {None}
    assert rows[0]["unsure"] == [1]


def test_a_definite_rule_wins_over_an_unsure_one():
    rows = pcov.coverage_map([rule(1, [{"srcIps": "0.0.0.0/0 \\ (1.1.1.1)", "dstIps": "10.20.0.5"}]),
                              rule(2, [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}])], NET)
    assert covered(rows)["Gi0/0"] is True


def test_a_device_whose_interfaces_cannot_be_read_is_unknown_never_covered():
    rows = pcov.coverage_map([rule(1, [{"dstPorts": "23"}])], {}, devices={"rtr-hq"})
    assert len(rows) == 1 and rows[0]["covered"] is None and rows[0]["reason"]


def test_interfaces_unreadable_altogether_is_unknown():
    rows = pcov.coverage_map([rule(1, [{"dstPorts": "23"}])], None, devices={"rtr-hq", "rtr-b"})
    assert {r["covered"] for r in rows} == {None}


def test_the_summary_counts_unknowns_separately():
    rows = pcov.coverage_map([rule(1, [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}])], NET, devices={"rtr-hq", "rtr-x"})
    assert pcov.summary(rows) == "1 of 2 interface subnet(s) are covered by a policy rule; 1 could not be decided"


@needs_batfish
def test_live_routing_fixture_with_a_policy_about_the_hq_lan(tmp_path, capsys):
    p = tmp_path / "p.json"
    p.write_text('{"device": "rtr-hq", "policy_compliance": [{"number": 1, "description": "d", '
                 '"kind": "prohibition", "filter": "acl_in", "violation_severity": "high", '
                 '"violation_summary": "s", "queries": [{"srcIps": "10.10.10.0/24", '
                 '"dstIps": "10.20.20.0/24", "ipProtocols": ["tcp"], "dstPorts": "23"}]}]}')
    assert pcov.main([str(FIXTURES / "routing-secure"), str(p)]) == 0
    out = capsys.readouterr().out
    assert "2 of 4 interface subnet(s) are covered" in out
    assert out.count("UNCOVERED") == 2, "the two point-to-point links"
