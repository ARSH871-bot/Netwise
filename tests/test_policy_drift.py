"""Has an edit made my policy weaker? (#418)

The cases here are the ones a reviewer would not see by reading the diff of
a policy file: a /24 becoming a /25 is a one-character change.
"""

import json

import pytest

from analysis import policy_drift
from analysis.policy_drift import _query_inside, drift


def r(n, kind, queries, node="rtr-us5", flt="acl_in", description=None):
    return {"number": n, "description": description or f"rule {n}", "node": node,
            "filter": flt, "kind": kind, "queries": queries}


P24 = [{"srcIps": "10.10.10.0/24"}]
P25 = [{"srcIps": "10.10.10.0/25"}]


# --- what is weaker -------------------------------------------------------------

def test_a_prohibition_narrowed_from_a_24_to_a_25_is_weaker():
    weaker, unknown = drift([r(1, "prohibition", P24)], [r(1, "prohibition", P25)])
    assert len(weaker) == 1 and unknown == []
    assert "forbids less" in weaker[0] and "10.10.10.0/24" in weaker[0]


def test_a_requirement_widened_is_weaker():
    weaker, _ = drift([r(4, "requirement", [{"dstPorts": "443"}])],
                      [r(4, "requirement", [{"dstPorts": "443,80"}])])
    assert len(weaker) == 1 and "requires more" in weaker[0]


def test_a_removed_rule_is_weaker():
    weaker, _ = drift([r(1, "prohibition", P24), r(2, "prohibition", P25)], [r(1, "prohibition", P24)])
    assert weaker == ["rule 2 ('rule 2') was removed, so nothing checks what it covered any more"]


def test_a_rule_that_changed_kind_is_reported():
    weaker, _ = drift([r(1, "prohibition", P24)], [r(1, "requirement", P24)])
    assert len(weaker) == 1 and "changed from a prohibition to a requirement" in weaker[0]


@pytest.mark.parametrize("change", [{"node": "rtr-hq"}, {"flt": "acl_out"}])
def test_a_rule_that_moved_device_or_filter_is_reported(change):
    weaker, _ = drift([r(1, "prohibition", P24)], [r(1, "prohibition", P24, **change)])
    assert len(weaker) == 1 and "moved from" in weaker[0]


# --- what is NOT weaker ---------------------------------------------------------

@pytest.mark.parametrize("old,new", [
    (P25, P24),                                                  # prohibition widened: stricter
    (P24, P24),                                                  # unchanged
    (P24, [{"srcIps": "10.10.10.0/25,10.10.10.128/25"}]),        # same space, two halves in one field
    ([{"dstPorts": "0-442,444-65535"}], [{"dstPorts": "0-65535"}]),
])
def test_a_prohibition_that_still_covers_everything_it_did_is_not_weaker(old, new):
    assert drift([r(1, "prohibition", old)], [r(1, "prohibition", new)]) == ([], [])


def test_a_requirement_narrowed_is_not_weaker():
    assert drift([r(4, "requirement", [{"dstPorts": "443,80"}])],
                 [r(4, "requirement", [{"dstPorts": "443"}])]) == ([], [])


def test_an_added_rule_is_not_weaker():
    assert drift([r(1, "prohibition", P24)], [r(1, "prohibition", P24), r(2, "prohibition", P25)]) == ([], [])


# --- undecidable is its own answer ----------------------------------------------

def test_coverage_split_across_several_new_queries_is_undecidable_not_unchanged():
    """It IS covered here -- two /25s with the same ports. The module does not
    compute unions of multi-field boxes, so it says it cannot tell. That is
    the safe direction: it never calls a policy unchanged without proof."""
    old = [r(1, "prohibition", [{"srcIps": "10.10.10.0/24", "dstPorts": "0-100"}])]
    new = [r(1, "prohibition", [{"srcIps": "10.10.10.0/25", "dstPorts": "0-100"},
                                {"srcIps": "10.10.10.128/25", "dstPorts": "0-100"}])]
    weaker, unknown = drift(old, new)
    assert weaker == [] and len(unknown) == 1


def test_a_specifier_this_module_cannot_parse_is_undecidable():
    weaker, unknown = drift([r(1, "prohibition", [{"dstIps": "0.0.0.0/0 \\ (1.1.1.1)"}])],
                            [r(1, "prohibition", [{"dstIps": "10.0.0.0/8"}])])
    assert weaker == [] and len(unknown) == 1


def test_a_prohibition_moved_to_entirely_different_traffic_is_weaker_not_undecidable():
    """None of the new queries share any traffic with the old one, so the old
    traffic is provably no longer forbidden. With two new queries this cannot
    lean on the single-overlap rule -- it pins the disjoint case itself."""
    old = [r(1, "prohibition", [{"srcIps": "10.10.10.0/24"}])]
    new = [r(1, "prohibition", [{"srcIps": "192.168.0.0/16"}, {"srcIps": "172.16.0.0/12"}])]
    weaker, unknown = drift(old, new)
    assert len(weaker) == 1 and unknown == []


def test_only_one_overlapping_new_query_is_decided_exactly():
    """The /24 meets only the first of two new queries, so containment in the
    union is containment in that one -- a definite 'weaker'."""
    old = [r(1, "prohibition", [{"srcIps": "10.10.10.0/24"}])]
    new = [r(1, "prohibition", [{"srcIps": "10.10.10.0/25"}, {"srcIps": "192.168.0.0/16"}])]
    weaker, unknown = drift(old, new)
    assert len(weaker) == 1 and unknown == []


# --- containment primitive ------------------------------------------------------

@pytest.mark.parametrize("inner,outer,expected", [
    ({"srcIps": "10.10.10.0/25"}, {"srcIps": "10.10.10.0/24"}, True),
    ({"srcIps": "10.10.10.0/24"}, {"srcIps": "10.10.10.0/25"}, False),
    ({"srcIps": "10.10.10.0/24"}, {"srcIps": "10.10.10.0/25,10.10.10.128/25"}, True),
    ({"dstPorts": "80-90"}, {"dstPorts": "1-85,86-100"}, True),
    ({"dstPorts": "80-90"}, {"dstPorts": "1-85"}, False),
    ({"ipProtocols": ["tcp"]}, {"ipProtocols": ["tcp", "udp"]}, True),
    ({}, {"srcIps": "0.0.0.0/0"}, True),           # "any" is inside "everything"
    ({}, {"srcIps": "10.0.0.0/8"}, False),          # "any" is not inside a /8
    ({}, {"ipProtocols": ["tcp", "udp", "icmp"]}, False),   # the closed list is not every protocol
])
def test_query_containment(inner, outer, expected):
    assert _query_inside(inner, outer)[0] is expected


# --- command line ----------------------------------------------------------------

def _write(path, entries):
    path.write_text(json.dumps({"device": "rtr-us5", "policy_compliance": [
        dict(e, violation_severity="high", violation_summary="x") for e in entries]}))
    return str(path)


def test_cli_exits_1_and_says_weaker(tmp_path, capsys):
    old = _write(tmp_path / "old.json", [r(1, "prohibition", P24)])
    new = _write(tmp_path / "new.json", [r(1, "prohibition", P25)])
    assert policy_drift.main([old, new]) == 1
    assert capsys.readouterr().out.startswith("WEAKER: rule 1")


def test_cli_exits_0_when_not_weaker(tmp_path, capsys):
    old = _write(tmp_path / "old.json", [r(1, "prohibition", P25)])
    new = _write(tmp_path / "new.json", [r(1, "prohibition", P24)])
    assert policy_drift.main([old, new]) == 0
    assert "Not weaker" in capsys.readouterr().out


def test_cli_warns_when_pairing_relies_on_assigned_numbers(tmp_path, capsys):
    """Inserting one rule shifts every assigned number after it."""
    entry = r(1, "prohibition", P24)
    del entry["number"]
    old = _write(tmp_path / "old.json", [entry])
    new = _write(tmp_path / "new.json", [entry])
    policy_drift.main([old, new])
    assert "relies on rule numbers the loader assigned" in capsys.readouterr().out
