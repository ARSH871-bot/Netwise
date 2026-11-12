"""
Netwise -- the policy loader refuses a traffic description Batfish cannot be
asked (#442 review, #467).

WHY THIS FILE EXISTS
    `policy_compliance` queries and `access_control` headers go straight to
    Batfish's HeaderConstraints, which accepts almost anything locally. So a
    rule the check could not use loaded fine and failed only at scan time,
    as "could not check" with an error the user could not act on. Measured on
    main 2833a1e, through load_policy() and a real scan:

        queries: []                  -> PC-051 "this rule has no queries"
        queries: "10.10.10.0/24"     -> PC-051 "13 of 13 queries could not run"
                                        (one query per CHARACTER)
        queries: ["10.10.10.0/24"]   -> PC-051 TypeError from pybatfish
        {"srcIp": ...}  (typo)       -> PC-051 TypeError, unexpected keyword
        {"srcIps": "10.10.10.300"}   -> PC-051 "Work terminated abnormally"

    Each is now refused at load, naming the rule and what is wrong.

    The other direction matters as much. Batfish's address language is large
    -- ranges, wildcards, set difference -- and refusing a valid rule would be
    worse than the problem. Only an element that is plainly meant as one
    address or prefix is checked; the live test at the bottom proves each
    accepted form really runs in Batfish.

RUN
    pytest tests/test_policy_traffic_shape.py -v
"""

import json
from pathlib import Path

import pytest

from analysis import pipeline
from analysis.policy import PolicyError, load_policy
from conftest import needs_batfish

FIXTURES = Path(__file__).parent / "fixtures"


def compliance(queries):
    return {"device": "rtr-us5", "policy_compliance": [{
        "number": 1, "description": "x", "kind": "prohibition", "filter": "acl_in",
        "violation_severity": "high", "violation_summary": "y", "queries": queries}]}


def access(headers):
    return {"device": "rtr-us5", "access_control": [{
        "description": "x", "filter": "acl_in", "expected": "DENY",
        "violation_severity": "high", "violation_summary": "y", "headers": headers}]}


@pytest.mark.parametrize("queries,says", [
    ([], "non-empty list"),
    ("10.10.10.0/24", "non-empty list"),
    (["10.10.10.0/24"], "expected a mapping"),
    ([{"srcIp": "10.10.10.0/24"}], "unknown traffic field(s) 'srcIp'"),
    ([{"srcIps": "10.10.10.300"}], "srcIps '10.10.10.300' is not a valid address"),
    ([{"dstIps": "10.20.0.5, 999.1.1.1"}], "dstIps '999.1.1.1' is not a valid address"),
    ([{"srcIps": "10.10.10.0/24"}, "oops"], "query 2"),
])
def test_a_query_batfish_cannot_be_asked_is_refused_by_name(queries, says):
    with pytest.raises(PolicyError, match="query|queries") as raised:
        load_policy(compliance(queries))
    assert says in str(raised.value)
    assert "entry 1 ('x')" in str(raised.value)


@pytest.mark.parametrize("headers,says", [
    ("10.10.10.0/24", "expected a mapping"),
    ({"source": "10.10.10.0/24"}, "unknown traffic field(s) 'source'"),
    ({"dstIps": "10.20.0.500"}, "not a valid address"),
])
def test_access_control_headers_get_the_same_check(headers, says):
    with pytest.raises(PolicyError) as raised:
        load_policy(access(headers))
    assert says in str(raised.value) and "'headers'" in str(raised.value)


@pytest.mark.parametrize("spec", [
    {},                                                    # all traffic: a rule can mean it
    {"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"},
    {"srcIps": "10.0.0.1, 10.0.0.2"},                      # a plain list
    {"srcIps": "10.10.10.1-10.10.10.9"},                   # a range
    {"srcIps": "10.10.10.0:0.0.0.255"},                    # a wildcard
    {"dstIps": "0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)"},  # set difference, as POL-1
    {"ipProtocols": ["!tcp"], "dstPorts": "0-442,444-65535"},
    {"applications": ["dns"]},
])
def test_every_form_batfish_accepts_still_loads(spec):
    assert load_policy(compliance([spec])).entries_for("policy_compliance")[0]["queries"] == [spec]
    assert load_policy(access(spec)).entries_for("access_control")[0]["headers"] == spec


def test_the_shipped_example_still_loads():
    example = Path(__file__).resolve().parents[1] / "docs" / "examples" / "policy.example.json"
    assert load_policy(json.loads(example.read_text())).entries_for("policy_compliance")


@needs_batfish
@pytest.mark.parametrize("spec", [
    {"srcIps": "10.10.10.1-10.10.10.9", "dstIps": "10.20.0.5"},
    {"srcIps": "10.10.10.0:0.0.0.255", "dstIps": "10.20.0.5"},
    {"srcIps": "10.10.10.0/24", "dstIps": "0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)"},
])
def test_live_each_accepted_form_really_runs_in_batfish(spec):
    """No false refusal: what the loader lets through, Batfish can answer."""
    results = [f for f in pipeline.analyse(FIXTURES / "rtr-us5-secure",
                                           check_names=["policy_compliance"],
                                           policy=load_policy(compliance([spec])))
               if f["check"] == "policy_compliance"]
    assert "error" not in {f["status"] for f in results}, [f["evidence"]["detail"] for f in results]


@needs_batfish
def test_live_the_refused_address_really_fails_in_batfish():
    """And the one refused: Batfish itself cannot use it. Built past the
    loader, the way main used to let it through."""
    from analysis.checks import policy_compliance
    rule = dict(compliance([{"srcIps": "10.10.10.300", "dstIps": "10.20.0.5"}])["policy_compliance"][0],
                node="rtr-us5")
    original = policy_compliance.POLICY_RULES
    policy_compliance.POLICY_RULES = [rule]
    try:
        results = [f for f in pipeline.analyse(FIXTURES / "rtr-us5-secure",
                                               check_names=["policy_compliance"])
                   if f["check"] == "policy_compliance"]
    finally:
        policy_compliance.POLICY_RULES = original
    assert [f["status"] for f in results] == ["error"]
