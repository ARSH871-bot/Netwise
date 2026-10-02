"""A user policy must not be able to make two findings share an id (#376).

WHAT WAS MEASURED, ON REAL BATFISH, 2 OCTOBER
    Each of these loaded, ran, and produced two findings with one id. The
    pipeline's duplicate-id guard caught every one -- and told the user
    Netwise had an "Internal error", when the cause was their file:

        51 routing entries, one on an absent device   RT-050 twice
        100 routing entries                            RT-100 twice
        ONE routing entry with "number": 100           RT-100 twice
        TWO policy_compliance entries, "number": 1     PC-001 twice
        "number": 60 beside a rule that cannot run     PC-060 twice

    The last three need no large policy at all. The loader never looked at an
    explicit `number`, and never counted entries against what a check can
    number.

WHERE THE LIMITS COME FROM
    Each check owns `HIGHEST_POLICY_NUMBER`, derived from its own id bands, and
    the loader reads it from there. Part 3 checks the derivation against the
    bands; part 4 checks the limit is safe on real Batfish at its worst case.
"""

import pytest

from analysis import draft_policy
from analysis.checks import policy_compliance, routing
from analysis.policy import PolicyError, load_policy
from conftest import needs_batfish


def _rule(i, **extra):
    entry = {"description": f"rule {i}", "node": "rtr-us5", "filter": "acl_in",
             "kind": "prohibition",
             "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "218.8.104.58",
                          "ipProtocols": ["udp"], "dstPorts": "53"}],
             "violation_severity": "low", "violation_summary": f"rule {i} violated"}
    entry.update(extra)
    return entry


def _route(i, **extra):
    entry = {"description": f"route {i}", "node": "rtr-a", "src_ip": "10.0.0.1",
             "dst_ip": "203.0.113.1", "expected": "REACHABLE",
             "violation_severity": "low", "violation_summary": f"route {i} broken"}
    entry.update(extra)
    return entry


SECTIONS = [("policy_compliance", _rule, policy_compliance, "PC"),
            ("routing", _route, routing, "RT")]
IDS = ["policy_compliance", "routing"]


# --- 1. How many entries -------------------------------------------------------


@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_a_section_at_its_limit_loads(section, make, check, prefix):
    limit = check.HIGHEST_POLICY_NUMBER
    loaded = load_policy({section: [make(i) for i in range(1, limit + 1)]})
    assert len(loaded.entries_for(section)) == limit


@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_one_entry_over_the_limit_is_refused_naming_the_limit(section, make, check, prefix):
    limit = check.HIGHEST_POLICY_NUMBER
    with pytest.raises(PolicyError) as refused:
        load_policy({section: [make(i) for i in range(1, limit + 2)]})
    message = str(refused.value)
    assert f"{limit + 1} entries" in message and f"at most {limit}" in message
    assert "Internal error" not in message


# --- 2. Explicit numbers ---------------------------------------------------------


@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_two_entries_with_the_same_number_are_refused_naming_both(section, make, check, prefix):
    with pytest.raises(PolicyError) as refused:
        load_policy({section: [make(1, number=1), make(2, number=1)]})
    message = str(refused.value)
    assert f"{section} entry 2" in message and f"{section} entry 1" in message
    assert f"{prefix}-001" in message


@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_a_number_above_the_limit_is_refused_even_in_a_one_entry_policy(section, make, check, prefix):
    """The measured RT-100 case: one entry, one explicit number, a collision."""
    too_high = check.HIGHEST_POLICY_NUMBER + 1
    with pytest.raises(PolicyError) as refused:
        load_policy({section: [make(1, number=too_high)]})
    assert f"from 1 to {check.HIGHEST_POLICY_NUMBER}" in str(refused.value)
    assert f"got {too_high}" in str(refused.value)


@pytest.mark.parametrize("bad", [0, -1, True, "1", 1.0, None],
                         ids=["zero", "negative", "bool", "string", "float", "null"])
@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_a_number_that_is_not_a_whole_number_in_range_is_refused(section, make, check, prefix, bad):
    with pytest.raises(PolicyError, match="must be a whole number"):
        load_policy({section: [make(1, number=bad)]})


@pytest.mark.parametrize("section, make, check, prefix", SECTIONS, ids=IDS)
def test_explicit_numbers_in_range_and_distinct_still_load(section, make, check, prefix):
    """The guard must not refuse what our own built-in rules do."""
    limit = check.HIGHEST_POLICY_NUMBER
    loaded = load_policy({section: [make(1, number=limit), make(2, number=1)]})
    assert [e["number"] for e in loaded.entries_for(section)] == [limit, 1]


def test_every_number_problem_is_reported_together():
    """One upload names all of them, the same rule as missing keys."""
    with pytest.raises(PolicyError) as refused:
        load_policy({"policy_compliance": [_rule(1, number=1), _rule(2, number=1)],
                     "routing": [_route(1, number=100)]})
    message = str(refused.value)
    assert "PC-001" in message and "got 100" in message


# --- 3. The limits come from the checks, and are right ---------------------------


def test_the_loader_reads_the_checks_limit_rather_than_its_own_copy(monkeypatch):
    monkeypatch.setattr(policy_compliance, "HIGHEST_POLICY_NUMBER", 2)
    with pytest.raises(PolicyError, match="at most 2"):
        load_policy({"policy_compliance": [_rule(i) for i in range(1, 4)]})


def test_policy_compliance_limit_keeps_every_rule_clear_of_the_checks_own_ids():
    """Rule n reports PC-n, or PC-(n+50) if it cannot run. Neither may meet
    the check's own cards or another rule's number."""
    limit = policy_compliance.HIGHEST_POLICY_NUMBER
    own = {policy_compliance.UNCOVERED_NUMBER, policy_compliance.SKIPPED_NUMBER}
    rules = set(range(1, limit + 1))
    errors = {n + policy_compliance.ERROR_NUMBER_OFFSET for n in rules}
    assert not rules & own and not errors & own and not errors & rules
    assert limit + 1 in own, "the limit is not as high as it can be"


def test_routing_limit_keeps_every_route_clear_of_the_checks_own_ids():
    limit = routing.HIGHEST_POLICY_NUMBER
    own = {routing.SKIPPED_NUMBER, routing.UNREAD_POLICY_NUMBER}
    assert not set(range(1, limit + 1)) & own
    assert limit < routing.HYGIENE_FIRST_NUMBER
    assert limit + 1 in own, "the limit is not as high as it can be"


def test_the_drafter_stops_at_the_checks_limit_not_a_copy_of_it(monkeypatch):
    """Behavioural rather than comparing two numbers: a literal 48 in the
    drafter would pass a value comparison today and drift silently the day the
    bands move. The drafter used to keep its own copy; it now reads this one."""
    from test_draft_policy import DNS, _Session

    monkeypatch.setattr(policy_compliance, "HIGHEST_POLICY_NUMBER", 2)
    draft = draft_policy.draft_policy(_Session([("rtr-us5", "acl_in", [DNS, DNS, DNS])]))
    assert len(draft["policy_compliance"]) == 2


# --- 4. On real Batfish, at the limit's worst case ---------------------------------


@needs_batfish
def test_policy_compliance_at_its_limit_produces_no_shared_id():
    """48 rules: one cannot run (error at PC-051), one names an absent device
    (the PC-050 card), the rest are violated. Nothing may collide."""
    from analysis import pipeline
    from pathlib import Path

    limit = policy_compliance.HIGHEST_POLICY_NUMBER
    rules = ([_rule(1, filter="no_such_acl")]
             + [_rule(i) for i in range(2, limit)]
             + [_rule(limit, node="rtr-absent")])
    results = pipeline.analyse(Path(__file__).parent / "fixtures" / "rtr-us5-secure",
                               check_names=["policy_compliance"], policy=load_policy(
                                   {"policy_compliance": rules}))
    ids = [r["id"] for r in results]
    assert len(ids) == len(set(ids)), sorted(i for i in ids if ids.count(i) > 1)
    assert {"PC-050", "PC-051"} <= set(ids), "the worst case did not happen"


@needs_batfish
def test_routing_at_its_limit_produces_no_shared_id():
    """49 routes on routing-faults: one on an absent device (RT-050), the rest
    violated, beside the four hygiene findings from RT-100."""
    from analysis import pipeline
    from pathlib import Path

    limit = routing.HIGHEST_POLICY_NUMBER
    routes = [_route(i) for i in range(1, limit)] + [_route(limit, node="rtr-absent")]
    results = pipeline.analyse(Path(__file__).parent / "fixtures" / "routing-faults",
                               check_names=["routing"], policy=load_policy({"routing": routes}))
    ids = [r["id"] for r in results]
    assert len(ids) == len(set(ids)), sorted(i for i in ids if ids.count(i) > 1)
    assert {"RT-050", "RT-100"} <= set(ids), "the worst case did not happen"
