"""
Netwise -- tests for policy_compliance's partial-check behaviour.

WHY THIS FILE EXISTS
    Issue #22, found in review of #18. `run()` wrapped a rule's whole query
    loop in ONE try, so a rule with several query arms behaved like this:

        arm A proves a violation
        arm B raises
        -> the violation is discarded; the user sees only "could not check"

    For a security tool that is the wrong trade. A PROVEN violation outranks
    the fact that a second query failed, and replacing it with "we don't know"
    reads as LESS alarming than the truth -- the same class of mistake as
    confusing status="none" with status="error".

    Only POL-2 has multiple arms today, so the blast radius is small. It grows
    with every multi-arm rule added, and multi-arm rules are the ones
    expressing "everything except X" -- which tend to be the interesting
    policies. A test is a better guard than remembering.

HOW THESE RUN WITHOUT BATFISH
    They replace policy_compliance._search with a fake, exactly as
    tests/test_routing_classification.py exercises _evaluate() with fake trace
    objects. The logic under test is the arm-isolation and id allocation in
    run(), not Batfish's query engine, so a live session would add minutes and
    prove nothing extra.

RUN
    pytest tests/ -v
"""

import pytest

from analysis.checks import policy_compliance


class _FakeBatfishError(Exception):
    """Stands in for the BatfishException a bad node/filter name produces."""


class _FakeRow(dict):
    """Enough of a pandas row for _describe() to format: it only indexes."""


def _hit(line="permit ip any any"):
    return _FakeRow(
        {"Flow": "start=rtr-us5 [10.10.10.0:49152->8.8.8.8:80 TCP (SYN)]",
         "Line_Content": line}
    )


@pytest.fixture
def two_arm_rule(monkeypatch):
    """Reduce the policy to ONE rule with TWO arms, so intent is unambiguous.

    POL-2 is the real two-arm rule, but pinning the test to the live policy
    would make it fail the day someone edits POL-2 for an unrelated reason.

    Also stubs `device_names` to say the rule's device IS present. run() now
    scopes rules to the devices in the snapshot, so without this every test
    here would take the "nothing applies to this config" path and prove nothing
    about arm isolation. Device scoping has its own tests in
    tests/test_device_scoping.py.
    """
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    rule = {
        "number": 2,
        "description": "The internal server is reachable only over HTTPS",
        "kind": "prohibition",
        "node": "rtr-us5",
        "filter": "acl_in",
        "severity": "high",
        "violation_summary": "The internal server accepts traffic other than HTTPS",
        "queries": [{"arm": "A"}, {"arm": "B"}],
    }
    monkeypatch.setattr(policy_compliance, "POLICY_RULES", [rule])
    return rule


def test_violation_survives_a_failing_arm(two_arm_rule):
    """THE ISSUE #22 REGRESSION: arm A proves it, arm B raises -> report BOTH."""

    def fake_search(bf, node, filter_name, action, headers):
        if headers["arm"] == "A":
            return [_hit()]
        raise _FakeBatfishError("Work terminated abnormally")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(policy_compliance, "_search", fake_search)
        results = policy_compliance.run(bf=None)

    by_status = {f["status"]: f for f in results}
    assert set(by_status) == {"found", "error"}, (
        "a proven violation must not be discarded because a later arm failed; "
        f"got {[f['status'] for f in results]}"
    )

    # The violation keeps the rule's own pinned id...
    assert by_status["found"]["id"] == "PC-002"
    assert by_status["found"]["severity"] == "high"
    # ...and the error takes the offset band, so the two cannot collide.
    assert by_status["error"]["id"] == "PC-052"


def test_the_two_findings_never_share_an_id(two_arm_rule):
    """Both findings come from one rule, so this is where a collision would start.

    duplicate_id_findings() in the pipeline would catch it, but catching it
    there means shipping a broken contract and reporting it -- better that the
    check simply never produces one.
    """

    def fake_search(bf, node, filter_name, action, headers):
        if headers["arm"] == "A":
            return [_hit()]
        raise _FakeBatfishError("boom")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(policy_compliance, "_search", fake_search)
        results = policy_compliance.run(bf=None)

    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids)), f"duplicate ids from one rule: {ids}"


def test_error_summary_says_partly_when_something_was_proved(two_arm_rule):
    """"Partly checked" and "could not check" are different claims to a reader."""

    def fake_search(bf, node, filter_name, action, headers):
        if headers["arm"] == "A":
            return [_hit()]
        raise _FakeBatfishError("boom")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(policy_compliance, "_search", fake_search)
        results = policy_compliance.run(bf=None)

    error = next(f for f in results if f["status"] == "error")
    assert "only partly checked" in error["summary"]
    # It must also say how much was lost, not just that something was.
    assert "1 of 2 queries" in error["evidence"]["detail"]


def test_all_arms_failing_still_reads_as_could_not_check(two_arm_rule):
    """With nothing proved, the wording stays the blunt one -- and no `found`."""

    def fake_search(bf, node, filter_name, action, headers):
        raise _FakeBatfishError("boom")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(policy_compliance, "_search", fake_search)
        results = policy_compliance.run(bf=None)

    assert [f["status"] for f in results] == ["error"]
    assert results[0]["summary"].startswith("Could not check policy rule")
    assert results[0]["id"] == "PC-052"


def test_a_rule_that_holds_on_every_arm_reports_all_clear(two_arm_rule):
    """Both arms run and find nothing -> status="none", never "error"."""

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(policy_compliance, "_search", lambda *a, **k: [])
        results = policy_compliance.run(bf=None)

    assert [f["status"] for f in results] == ["none"]
    assert results[0]["id"] == "PC-000"


def test_the_two_bands_cannot_overlap_or_reach_the_guards_id():
    """Violations and check-errors must stay disjoint, and clear of PC-999.

    This used to assert the error band stayed below PC-100, because
    change_impact owned PC-100..199. Amendment A-2 gave change_impact its own
    CH- prefix, so that boundary is gone -- but the arithmetic still has to
    hold WITHIN this check, which is what the offset is actually for.

    PC-999 is pipeline.duplicate_id_findings()'s own complaint id. Colliding
    with it would mean the guard against duplicate ids emitted a duplicate id.
    """
    numbers = [r["number"] for r in policy_compliance.POLICY_RULES]
    offset = policy_compliance.ERROR_NUMBER_OFFSET

    violations = set(numbers)
    errors = {n + offset for n in numbers}
    assert not violations & errors, "a rule's violation and error ids must differ"
    assert policy_compliance.SKIPPED_NUMBER not in violations | errors
    assert max(errors) < 999, "the error band must stay clear of the guard's PC-999"
