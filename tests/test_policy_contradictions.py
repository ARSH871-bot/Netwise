"""A policy that forbids what it requires must be refused (#322, US-30).

WHAT THESE PIN
    Two things, and the second is the one that will rot first.

    1. A PROVEN contradiction raises, naming both rules and the traffic they
       disagree about. Without the overlap in the message the user is told
       two rules fight and left to work out where.

    2. A pair this module CANNOT decide is never silently treated as clean.
       `analysis/policy_conflicts.py` parses a deliberate subset of Batfish
       header specifiers; everything else is undecidable and surfaces on
       `Policy.undecidable`. A future change that widens the parser must keep
       that third answer, because losing it turns "we could not check" into
       "we checked and found nothing", which is F-4 reached through the
       policy file.
"""

from pathlib import Path

import pytest

from analysis import policy_conflicts
from analysis.policy import PolicyError, load_policy, load_policy_file

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "docs" / "examples" / "policy.example.json"


def rule(number, kind, queries, node="rtr-us5", filter_name="acl_in", description=None):
    return {
        "number": number,
        "description": description or f"rule {number}",
        "node": node,
        "kind": kind,
        "filter": filter_name,
        "violation_severity": "high",
        "violation_summary": "something was not as the policy requires",
        "queries": queries,
    }


def policy(*entries):
    return {"device": "rtr-us5", "policy_compliance": list(entries)}


LAN_TO_SERVER = [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}]
ACCOUNTS_TO_SERVER = [{"srcIps": "10.10.10.64/26", "dstIps": "10.20.0.0/16", "dstPorts": "443"}]


# --- 1. the contradiction itself ----------------------------------------

def test_a_prohibition_that_forbids_what_a_requirement_requires_is_refused():
    with pytest.raises(PolicyError) as caught:
        load_policy(policy(
            rule(3, "prohibition", LAN_TO_SERVER),
            rule(7, "requirement", ACCOUNTS_TO_SERVER),
        ))
    assert "contradicts itself" in str(caught.value)


def test_the_message_names_both_rule_numbers_and_the_overlap():
    """US-30 asks for the pair AND the overlap. A message naming only the
    rules sends the user to diff two header specifiers by eye."""
    with pytest.raises(PolicyError) as caught:
        load_policy(policy(
            rule(3, "prohibition", LAN_TO_SERVER),
            rule(7, "requirement", ACCOUNTS_TO_SERVER),
        ))
    message = str(caught.value)
    assert "rule 3" in message and "rule 7" in message
    # the overlap is the INTERSECTION, not either rule restated
    assert "10.10.10.64/26" in message
    assert "10.20.0.5/32" in message
    assert "443" in message


def test_the_scan_is_blocked_rather_than_run_on_contradictory_rules():
    """`load_policy` is the gate every entry point goes through, so raising
    here is what stops a scan producing a violation either way round."""
    with pytest.raises(PolicyError):
        load_policy(policy(
            rule(1, "prohibition", [{"dstIps": "10.20.0.5"}]),
            rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
        ))


# --- 2. what is NOT a contradiction --------------------------------------

def test_two_prohibitions_over_the_same_traffic_are_consistent():
    """Denying twice is denying. Only permit-versus-deny cannot be satisfied."""
    loaded = load_policy(policy(
        rule(1, "prohibition", LAN_TO_SERVER),
        rule(2, "prohibition", LAN_TO_SERVER),
    ))
    assert loaded.undecidable == []


def test_two_requirements_over_the_same_traffic_are_consistent():
    loaded = load_policy(policy(
        rule(1, "requirement", LAN_TO_SERVER),
        rule(2, "requirement", LAN_TO_SERVER),
    ))
    assert loaded.undecidable == []


def test_rules_on_different_devices_cannot_contradict():
    loaded = load_policy(policy(
        rule(1, "prohibition", LAN_TO_SERVER, node="rtr-us5"),
        rule(2, "requirement", LAN_TO_SERVER, node="rtr-hq"),
    ))
    assert len(loaded.entries_for("policy_compliance")) == 2
    assert loaded.undecidable == []


def test_rules_on_different_filters_cannot_contradict():
    loaded = load_policy(policy(
        rule(1, "prohibition", LAN_TO_SERVER, filter_name="acl_in"),
        rule(2, "requirement", LAN_TO_SERVER, filter_name="acl_out"),
    ))
    assert len(loaded.entries_for("policy_compliance")) == 2
    assert loaded.undecidable == []


def test_disjoint_traffic_is_not_a_contradiction():
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"srcIps": "10.10.10.0/24"}]),
        rule(2, "requirement", [{"srcIps": "192.168.1.0/24"}]),
    ))
    assert loaded.undecidable == []
    assert policy_conflicts.overlap(
        {"srcIps": "10.10.10.0/24"}, {"srcIps": "192.168.1.0/24"})[0] is False


def test_a_port_range_that_excludes_the_required_port_does_not_collide():
    """The real shape in docs/examples/policy.example.json: "everything except
    443" against "443". Treating the ranges as "both mention ports" would
    refuse a policy that is perfectly consistent."""
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "10.20.0.5", "dstPorts": "0-442,444-65535"}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5", "dstPorts": "443"}]),
    ))
    assert loaded.undecidable == [], "the ports were parsed, so nothing is undecided"
    assert policy_conflicts.overlap(
        {"dstPorts": "0-442,444-65535"}, {"dstPorts": "443"})[0] is False


def test_a_protocol_that_does_not_match_does_not_collide():
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "10.20.0.5", "ipProtocols": ["udp"]}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5", "ipProtocols": ["tcp"]}]),
    ))
    assert loaded.undecidable == []


# --- 3. undecidable is its own answer ------------------------------------

def test_a_specifier_we_cannot_parse_is_recorded_rather_than_cleared():
    """The whole safety argument. `\\` is Batfish set difference, which this
    module does not implement. The pair MUST NOT load silently."""
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "0.0.0.0/0 \\ (10.20.0.5)"}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
    ))
    assert len(loaded.undecidable) == 1
    note = loaded.undecidable[0]
    assert "rule 1" in note and "rule 2" in note
    assert "could not be compared" in note


def test_a_negated_protocol_is_undecidable_rather_than_ignored():
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "10.20.0.5", "ipProtocols": ["!tcp"]}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
    ))
    assert loaded.undecidable, "a negated protocol must not read as no constraint"


def test_a_query_field_we_do_not_model_makes_the_pair_undecidable():
    """The dangerous direction. An unmodelled field might be the one keeping
    two rules apart; skipping it would WIDEN each space and invent an overlap
    that is not there, refusing a policy that is fine."""
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "10.20.0.5", "icmpCodes": "0"}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
    ))
    assert loaded.undecidable
    assert "icmpCodes" in loaded.undecidable[0]


def test_an_undecidable_pair_does_not_block_the_scan():
    """It is a warning, not a refusal. We have not shown a contradiction, and
    refusing on a maybe would make the subset this module parses into a
    restriction on what a user may write."""
    loaded = load_policy(policy(
        rule(1, "prohibition", [{"dstIps": "0.0.0.0/0 \\ (10.20.0.5)"}]),
        rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
    ))
    assert loaded.entries_for("policy_compliance"), "the policy still loaded"
    assert loaded.undecidable, "and the pair was recorded rather than cleared"


def test_a_proven_contradiction_wins_over_an_undecidable_one():
    """A rule with two queries, one undecidable and one provably colliding.
    The provable one must still raise rather than be softened to a note."""
    with pytest.raises(PolicyError):
        load_policy(policy(
            rule(1, "prohibition", [{"dstIps": "0.0.0.0/0 \\ (1.1.1.1)"},
                                    {"dstIps": "10.20.0.5"}]),
            rule(2, "requirement", [{"dstIps": "10.20.0.5"}]),
        ))


# --- 4. the shipped example ----------------------------------------------

def test_the_example_policy_still_loads_and_reports_what_it_could_not_compare():
    """docs/examples/policy.example.json is what a user copies. It uses the
    specifier syntax this module does not parse, so it must load AND say so."""
    loaded = load_policy_file(EXAMPLE)
    assert loaded.entries_for("policy_compliance")
    assert len(loaded.undecidable) == 1, loaded.undecidable
    assert "rule 1" in loaded.undecidable[0] and "rule 4" in loaded.undecidable[0]


def test_the_example_does_not_warn_about_a_pair_a_parsed_field_proves_disjoint():
    """#387 review. Rules 2 and 4 used to warn because rule 2 says `!tcp` --
    but rule 2 is about 10.20.0.5 and rule 4 about 218.8.104.58, which is
    provably disjoint on a field we DO parse. A false warning in our own
    example teaches people to skip the warnings."""
    loaded = load_policy_file(EXAMPLE)
    assert not any("rule 2" in u for u in loaded.undecidable)


# --- 4b. what the review found ---------------------------------------------

P = {"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}
R = {"srcIps": "10.10.10.64/26", "dstIps": "10.20.0.0/16", "ipProtocols": ["tcp"], "dstPorts": "443"}


@pytest.mark.parametrize("tokens", [["6"], "tcp,udp", ["tcp, udp"], ["TCP"]])
def test_protocol_numbers_and_comma_lists_are_understood_not_guessed(tokens):
    """Batfish reads `"6"` as TCP and pybatfish splits `"tcp,udp"`. Taking
    them as unknown names made a real contradiction load as consistent."""
    with pytest.raises(PolicyError):
        load_policy(policy(rule(1, "prohibition", [{**P, "ipProtocols": tokens}]),
                           rule(2, "requirement", [R])))


def test_an_unrecognised_protocol_is_undecidable_not_disjoint():
    loaded = load_policy(policy(rule(1, "prohibition", [{**P, "ipProtocols": ["banana"]}]),
                                rule(2, "requirement", [R])))
    assert len(loaded.undecidable) == 1


@pytest.mark.parametrize("other", ["ACL_IN", "acl_in ", "/acl_in/", "@in(GigabitEthernet0/0)"])
def test_a_filter_batfish_may_resolve_to_the_same_acl_is_not_skipped(other):
    """`ACL_IN` and `acl_in` were "different filter: cannot collide". Batfish
    resolves them to the same ACL, so the pair is reported, not skipped."""
    loaded = load_policy(policy(rule(1, "prohibition", [P]),
                                rule(2, "requirement", [R], filter_name=other)))
    assert len(loaded.undecidable) == 1
    assert "could not be compared" in loaded.undecidable[0]


def test_one_disjoint_parsed_field_beats_an_unparsed_one():
    verdict, _ = policy_conflicts.overlap(
        {"dstIps": "10.20.0.5", "ipProtocols": ["!tcp"]}, {"dstIps": "218.8.104.58"})
    assert verdict is False


def test_an_unparsed_field_earlier_in_field_order_cannot_hide_a_disjoint_later_one():
    """The order matters for the mutant this pins. srcIps is compared before
    dstIps, so an implementation that gave up at the first unparsed field
    would answer "undecidable" here instead of "disjoint"."""
    verdict, _ = policy_conflicts.overlap(
        {"srcIps": "0.0.0.0/0 \\ (1.1.1.1)", "dstIps": "10.20.0.5"},
        {"dstIps": "218.8.104.58"})
    assert verdict is False


def test_an_unmodelled_field_cannot_hide_a_disjoint_parsed_one():
    verdict, _ = policy_conflicts.overlap(
        {"dstIps": "10.20.0.5", "icmpCodes": "0"}, {"dstIps": "218.8.104.58"})
    assert verdict is False


def test_rules_without_numbers_are_named_by_the_numbers_assigned_to_them():
    """Pins the ordering in load_policy(): the contradiction check runs AFTER
    numbers are assigned. Before it, both rules read "an unnumbered rule"."""
    a, b = rule(1, "prohibition", [P]), rule(2, "requirement", [R])
    del a["number"], b["number"]
    with pytest.raises(PolicyError) as caught:
        load_policy(policy(a, b))
    assert "unnumbered" not in str(caught.value)
    assert "rule 1" in str(caught.value) and "rule 2" in str(caught.value)


def test_overlapping_port_ranges_are_described_once():
    _, detail = policy_conflicts.overlap({"dstPorts": "1-100,50-200"}, {"dstPorts": "60-70"})
    assert detail == "dst ports 60-70"


def test_a_boolean_is_not_a_port():
    verdict, _ = policy_conflicts.overlap({"dstPorts": True}, {"dstPorts": "1"})
    assert verdict is None


# --- 4c. the CLIs say it -----------------------------------------------------

def test_the_pipeline_cli_prints_each_undecidable_pair(monkeypatch, capsys):
    """Deleting the print in analysis/pipeline.py used to fail no test."""
    from analysis import pipeline
    monkeypatch.setattr(pipeline, "analyse", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "_print_summary", lambda results: None)
    monkeypatch.setattr("sys.argv", ["pipeline", "unused-dir", "--policy", str(EXAMPLE)])
    pipeline.main()
    warnings = [line for line in capsys.readouterr().out.splitlines() if line.startswith("warning:")]
    assert len(warnings) == 1 and "rule 1" in warnings[0] and "rule 4" in warnings[0]


def test_the_change_impact_cli_prints_each_undecidable_pair(monkeypatch, capsys):
    from analysis import change_impact
    monkeypatch.setattr(change_impact, "analyse_change", lambda *a, **k: [])
    monkeypatch.setattr("sys.argv", ["change_impact", "before", "after", str(EXAMPLE)])
    change_impact.main()
    warnings = [line for line in capsys.readouterr().out.splitlines() if line.startswith("warning:")]
    assert len(warnings) == 1


# --- 5. the overlap primitive itself -------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ({"srcIps": "10.10.10.0/24"}, {"srcIps": "10.10.10.7"}, True),
    ({"srcIps": "10.10.10.0/24"}, {"srcIps": "192.168.1.0/24"}, False),
    ({"dstPorts": "440-500"}, {"dstPorts": "443"}, True),
    ({"dstPorts": "0-442,444-65535"}, {"dstPorts": "443"}, False),
    ({"ipProtocols": ["tcp", "udp"]}, {"ipProtocols": ["udp"]}, True),
    ({}, {"dstIps": "10.20.0.5"}, True),          # absent field constrains nothing
])
def test_overlap_decides_the_cases_it_claims_to(a, b, expected):
    verdict, _ = policy_conflicts.overlap(a, b)
    assert verdict is expected


@pytest.mark.parametrize("spec", [
    {"dstIps": "0.0.0.0/0 \\ (10.20.0.5)"},
    {"ipProtocols": ["!tcp"]},
    {"dstIps": "ref.Interface(name)"},
    {"dstPorts": "not-a-port"},
    {"unknownField": "x"},
])
def test_overlap_returns_undecidable_rather_than_guessing(spec):
    verdict, reason = policy_conflicts.overlap(spec, {"dstIps": "10.20.0.5"})
    assert verdict is None
    assert reason
