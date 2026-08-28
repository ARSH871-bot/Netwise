"""A check that DETECTS a problem must say `status="found"` (#209).

WHY THIS FILE EXISTS
    Everything else in this project rests on F-4 holding: the three-state
    dashboard, the amber "could not check" card, and the claim we make to the
    client that we never say we checked when we did not. All of it assumes a
    check that finds a problem SAYS SO.

    That assumption was defended for one check out of three. Measured by
    rewriting every real `status="found"` keyword argument to `"none"` --
    located with `ast`, so only live code was touched -- and running the suite:

        downgrade access_control              546 passed   NOTHING FAILED
        downgrade routing                     546 passed   NOTHING FAILED
        downgrade policy_compliance             1 failed
        downgrade ALL THREE                     1 failed

    With every check silently reporting real problems as "checked, nothing
    found", 545 of 546 tests still passed. A genuine vulnerability rendered as
    a green tick is F-4's worst possible shape, and nothing caught it.

WHY THE EXISTING `found` ASSERTIONS DID NOT CATCH IT
    The one that looks like it guards this is

        assert any(f["status"] == "found" for f in results)

    an `any()` over the COMBINED list from every check. It is satisfied by any
    one check, so it can never detect a specific check being downgraded -- and
    it survived all three being downgraded, because the findings it asserts on
    are literals built inside the test file rather than the product's output.

    So every test here asserts on ONE named check's own output.

NO BATFISH, NO OLLAMA, NO DOCKER
    Each check is driven by a fake session returning a crafted frame. These
    run everywhere, including on a machine with Docker stopped -- which
    matters, because a test that SKIPS is indistinguishable from one that
    passes in pytest's summary line.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List

import pandas as pd
import pytest

from analysis.checks import access_control, policy_compliance, routing


# ---------------------------------------------------------------------------
# A fake Batfish session: q.<question>(...).answer().frame() -> a real frame
# ---------------------------------------------------------------------------


class _Answer:
    def __init__(self, frame): self._frame = frame

    def frame(self): return self._frame


class _Question:
    def __init__(self, frame): self._frame = frame

    def answer(self): return _Answer(self._frame)


class _Q:
    """Serves a preset frame per question name.

    Raises on any question the test did not prepare, so a check quietly
    asking something else fails loudly instead of silently getting an empty
    frame and reporting "nothing found" -- which is the exact bug this file
    is about.
    """

    def __init__(self, frames: Dict[str, pd.DataFrame]):
        self._frames = frames

    def __getattr__(self, name):
        if name not in self._frames:
            raise AssertionError(
                f"the check asked an unprepared question: {name}(). Add a "
                f"frame for it, or this test is not exercising what it claims"
            )
        frame = self._frames[name]
        return lambda *args, **kwargs: _Question(frame)


class _FakeSession:
    def __init__(self, **frames):
        self.q = _Q(frames)


def _numbering():
    return itertools.count(1)


def _found(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in results if f["status"] == "found"]


# ---------------------------------------------------------------------------
# access_control -- four separate `found` sites, four separate tests
# ---------------------------------------------------------------------------


def test_access_control_reports_a_violated_policy_statement_as_found():
    """testFilters disagreeing with the policy is a PROBLEM, not a clean run."""
    statement = {
        "description": "DNS must be allowed",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {"dstIps": "10.10.10.5"},
        "expected": "PERMIT",
        "violation_summary": "DNS is blocked",
        "violation_severity": "medium",
    }
    frame = pd.DataFrame([{
        "Action": "DENY",                       # the opposite of expected
        "Line_Content": "deny ip any host 10.10.10.5",
    }])
    bf = _FakeSession(testFilters=frame)

    results = access_control._check_policy_statements(
        bf, _numbering(), [statement])

    assert _found(results), (
        "the config contradicts the policy and the check said nothing was "
        "found -- a real violation rendered as a clean result"
    )
    assert _found(results)[0]["summary"] == "DNS is blocked"


def test_access_control_reports_a_broken_guarantee_as_found():
    """searchFilters returning a flow is a counter-example, not silence."""
    guarantee = {
        "description": "no plaintext web out of the subnet",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {"srcIps": "10.10.10.0/24", "applications": ["http"]},
        "violation_summary": "Unencrypted web traffic is allowed out",
        "violation_severity": "high",
    }
    # A NON-EMPTY searchFilters result means the guarantee is broken.
    frame = pd.DataFrame([{
        "Flow": "10.10.10.9 -> 93.184.216.34:80",
        "Line_Content": "permit tcp 10.10.10.0 0.0.0.255 any eq 80",
        "Action": "PERMIT",
    }])
    bf = _FakeSession(searchFilters=frame)

    results = access_control._check_guarantees(bf, _numbering(), [guarantee])

    assert _found(results), (
        "searchFilters produced a counter-example -- a flow that violates a "
        "guarantee -- and the check reported no problem"
    )


def test_access_control_reports_a_dead_acl_rule_as_found():
    """A rule that can never fire is a finding, whatever its action."""
    frame = pd.DataFrame([{
        "Sources": ["rtr-us5: acl_in"],
        "Unreachable_Line": "deny tcp any host 10.10.10.42",
        "Unreachable_Line_Action": "DENY",
        "Blocking_Lines": ["permit ip any any"],
        "Reason": "BLOCKING_LINES",
    }])
    bf = _FakeSession(filterLineReachability=frame)

    results = access_control._check_dead_rules(bf, _numbering())

    assert _found(results), (
        "a DENY that can never fire lets through traffic somebody meant to "
        "block, and the check reported nothing found"
    )
    assert _found(results)[0]["severity"] == "high", (
        "a dead DENY is a security hole, not an availability annoyance"
    )


def test_access_control_reports_an_undefined_reference_as_found():
    """A config naming a structure that does not exist fails silently."""
    frame = pd.DataFrame([{
        "File_Name": "configs/rtr-us5.cfg",
        "Struct_Type": "ipv4 acl",
        "Ref_Name": "acl_guest_in",
        "Context": "interface ip access-group",
        "Lines": [12],
    }])
    bf = _FakeSession(undefinedReferences=frame)

    results = access_control._check_undefined_references(bf, _numbering())

    assert _found(results), (
        "the config references an ACL that is never defined -- a rule that "
        "silently does nothing -- and the check reported no problem"
    )


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------


class _Hop:
    def __init__(self, node): self.node = node


class _Trace:
    """The shape `_evaluate()` reads: a disposition and a list of hops."""

    def __init__(self, disposition, hops):
        self.disposition = disposition
        self.hops = [_Hop(h) for h in hops]


def test_routing_reports_unreachable_traffic_as_found(monkeypatch):
    """Traffic that must arrive and does not is a PROBLEM."""
    route = {
        "description": "hq must reach branch",
        "node": "rtr-hq",
        "src_ip": "10.1.1.1",
        "dst_ip": "10.2.2.2",
        "expected": "REACHABLE",
        "violation_summary": "hq cannot reach branch",
        "violation_severity": "high",
        "number": 1,
    }
    monkeypatch.setattr(routing, "ROUTES", [route])
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-hq"})

    frame = pd.DataFrame([{
        "Traces": [_Trace("NO_ROUTE", ["rtr-hq"])],
    }])
    bf = _FakeSession(traceroute=frame)

    results = routing.run(bf)

    assert _found(results), (
        "traffic the policy requires to arrive ended in NO_ROUTE, and the "
        "check reported nothing found"
    )
    assert _found(results)[0]["summary"] == "hq cannot reach branch"


# ---------------------------------------------------------------------------
# policy_compliance
# ---------------------------------------------------------------------------


def test_policy_compliance_reports_a_violated_rule_as_found(monkeypatch):
    """A rule the config breaks must be reported, not passed over."""
    rule = {
        "description": "finance must not be reachable",
        "node": "rtr-us5",
        "filter": "acl_in",
        "kind": "prohibition",   # forbidden traffic that IS allowed
        "queries": [{"dstIps": "10.20.0.5"}],
        "violation_summary": "finance host is reachable",
        "violation_severity": "high",
        "number": 1,
    }
    monkeypatch.setattr(policy_compliance, "POLICY_RULES", [rule])
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    # A non-empty hit list means the rule is violated. The shape is what
    # `_describe()` actually reads, so this exercises the real evidence text
    # rather than a stand-in that would break the moment it was used.
    hit = {
        "Flow": "10.10.10.9 -> 10.20.0.5:443",
        "Line_Content": "permit tcp any host 10.20.0.5",
    }
    monkeypatch.setattr(policy_compliance, "_search",
                        lambda bf, node, filt, action, headers: [hit])

    results = policy_compliance.run(_FakeSession())

    assert _found(results), (
        "the search found traffic the policy forbids, and the check reported "
        "no violation"
    )
    assert _found(results)[0]["summary"] == "finance host is reachable"


# ---------------------------------------------------------------------------
# The assertion shape itself, so this file cannot rot into the one it replaced
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_module", [access_control, routing,
                                          policy_compliance])
def test_every_check_module_still_has_a_found_path(check_module):
    """A check that can never say "found" cannot report a problem at all.

    Cheap, and it catches the case where somebody removes the last `found`
    site from a module entirely -- which the per-path tests above would also
    catch, but only by failing in a way that looks like a fixture problem.
    """
    import ast
    import inspect

    source = inspect.getsource(check_module)
    found_sites = [
        kw for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "status" and isinstance(kw.value, ast.Constant)
        and kw.value.value == "found"
    ]
    assert found_sites, (
        f"{check_module.__name__} has no `status=\"found\"` anywhere, so it "
        f"can never report a problem it detects"
    )
