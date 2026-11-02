"""
Netwise -- a policy rule only passes if its filter is in the path (#430).

WHY THIS FILE EXISTS
    searchFilters proves what a filter WOULD do to traffic passing through it.
    It does not prove any traffic passes through it. Measured while researching
    #423, on rtr-us5-secure with `ip access-group acl_in in` removed:

        PC-000  none   No issues found by policy compliance
        traceroute LAN -> 10.20.0.5 TCP/23    DELIVERED_TO_SUBNET

    A green tick while forbidden traffic is delivered. A rule whose filter is
    applied to no interface now reports "could not check" instead.

    Most tests here fake the session. The last one runs the measurement above
    against real Batfish, because the claim is about what Batfish's model
    says, and a fake can only repeat what the test told it.

RUN
    pytest tests/test_policy_filter_applied.py -v
"""

from pathlib import Path

import pytest

from analysis import pipeline
from analysis.checks import policy_compliance
from conftest import needs_batfish

RULE = {
    "number": 2,
    "description": "The internal server is reachable only over HTTPS",
    "kind": "prohibition",
    "node": "rtr-us5",
    "filter": "acl_in",
    "violation_severity": "high",
    "violation_summary": "The internal server accepts traffic other than HTTPS",
    "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}],
}


# --- which filters count as applied -----------------------------------------


class _Interface:
    def __init__(self, hostname):
        self.hostname = hostname


class _Frame:
    """Just enough of a pandas frame for _applied_filters to iterate."""

    def __init__(self, rows):
        self._rows = rows

    def iterrows(self):
        return enumerate(self._rows)


class _Session:
    def __init__(self, rows):
        frame = _Frame(rows)

        class _Q:
            def interfaceProperties(self, **kwargs):
                class _A:
                    def answer(self):
                        return self

                    def frame(self):
                        return frame
                return _A()
        self.q = _Q()


def _row(node, incoming=None, outgoing=None):
    return {"Interface": _Interface(node), "Incoming_Filter_Name": incoming,
            "Outgoing_Filter_Name": outgoing}


def test_both_directions_count_and_names_are_casefolded():
    applied = policy_compliance._applied_filters(_Session([
        _row("rtr-us5", incoming="ACL_IN"),
        _row("rtr-us5", outgoing="acl_out"),
        _row("rtr-us5"),                       # an interface with no filter
        _row("rtr-hq", incoming="hq_in"),
    ]))
    assert applied == {"rtr-us5": {"acl_in", "acl_out"}, "rtr-hq": {"hq_in"}}


@pytest.mark.parametrize("node, name, expected", [
    ("rtr-us5", "acl_in", False),        # applied
    ("rtr-us5", "ACL_IN ", False),       # Batfish resolves this to acl_in
    ("rtr-us5", "acl_out", True),        # defined or not, applied nowhere
    ("rtr-hq", "acl_in", True),          # applied, but on another device
    ("rtr-us5", "/acl/", False),         # a specifier: not one name to look for
    ("rtr-us5", "@in(Gi0/0)", False),
])
def test_not_in_path(node, name, expected):
    applied = {"rtr-us5": {"acl_in"}}
    assert policy_compliance._not_in_path(node, name, applied) is expected


# --- what run() reports -----------------------------------------------------


@pytest.fixture
def one_rule(monkeypatch):
    monkeypatch.setattr(policy_compliance, "POLICY_RULES", [RULE])
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    searched = []

    def _search(bf, node, filt, action, headers):
        searched.append(filt)
        return []
    monkeypatch.setattr(policy_compliance, "_search", _search)
    return searched


def test_an_unapplied_filter_is_could_not_check_not_a_pass(one_rule, monkeypatch):
    monkeypatch.setattr(policy_compliance, "_applied_filters",
                        lambda bf: {"rtr-us5": {"some_other_acl"}})

    results = policy_compliance.run(object())

    assert [f["status"] for f in results] == ["error"]
    assert results[0]["id"] == "PC-052"
    assert results[0]["summary"].startswith("Could not check policy rule")
    assert "is not applied to any interface" in results[0]["evidence"]["detail"]
    # The filter's answer is not asked for at all, so it cannot leak through.
    assert one_rule == []


def test_the_message_blames_the_model_not_the_config(one_rule, monkeypatch):
    # vendor-asa applies its ACL in a line Batfish does not parse, so "your
    # config does not apply it" would be false there.
    monkeypatch.setattr(policy_compliance, "_applied_filters", lambda bf: {})

    detail = policy_compliance.run(object())[0]["evidence"]["detail"]

    assert "In Batfish's model of rtr-us5" in detail
    assert "check the parse warnings" in detail


def test_not_knowing_what_is_applied_is_could_not_check(one_rule, monkeypatch):
    def _broken(bf):
        raise RuntimeError("interfaceProperties failed")
    monkeypatch.setattr(policy_compliance, "_applied_filters", _broken)

    results = policy_compliance.run(object())

    assert [f["status"] for f in results] == ["error"]
    assert "could not find out which filters are applied" in results[0]["evidence"]["detail"]
    assert one_rule == []


def test_a_specifier_filter_is_still_searched_when_the_lookup_fails(one_rule, monkeypatch):
    # The guard never applies to a specifier, so its failing must not either.
    monkeypatch.setattr(policy_compliance, "POLICY_RULES", [dict(RULE, filter="/acl_in/")])

    def _broken(bf):
        raise RuntimeError("interfaceProperties failed")
    monkeypatch.setattr(policy_compliance, "_applied_filters", _broken)

    results = policy_compliance.run(object())

    assert [f["status"] for f in results] == ["none"]
    assert one_rule == ["/acl_in/"]


def test_an_applied_filter_is_checked_as_before(one_rule, monkeypatch):
    monkeypatch.setattr(policy_compliance, "_applied_filters",
                        lambda bf: {"rtr-us5": {"acl_in"}})

    results = policy_compliance.run(object())

    assert [f["status"] for f in results] == ["none"]
    assert one_rule == ["acl_in"]


# --- the measurement, against real Batfish ----------------------------------


SECURE = Path(__file__).parent / "fixtures" / "rtr-us5-secure" / "configs" / "rtr-us5.cfg"


@needs_batfish
def test_real_batfish_no_green_tick_for_an_acl_applied_nowhere(tmp_path):
    configs = tmp_path / "configs"
    configs.mkdir()
    text = SECURE.read_text()
    assert "ip access-group acl_in in" in text
    (configs / "rtr-us5.cfg").write_text(text.replace(" ip access-group acl_in in\n", ""))

    results = [f for f in pipeline.analyse(tmp_path, check_names=["policy_compliance"])
               if f["check"] == "policy_compliance"]

    assert "none" not in {f["status"] for f in results}
    assert {f["status"] for f in results} == {"error"}


@needs_batfish
def test_real_batfish_the_secure_fixture_still_passes():
    results = [f for f in pipeline.analyse(SECURE.parent.parent,
                                           check_names=["policy_compliance"])
               if f["check"] == "policy_compliance"]

    assert "error" not in {f["status"] for f in results}
