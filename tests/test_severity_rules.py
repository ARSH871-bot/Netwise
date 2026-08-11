"""The severity ruleset in docs/severity-rules.md, tested rule by rule.

Needs neither Batfish nor Docker: `risk` reads findings, never a config.

WHY THESE TESTS MATTER MORE THAN MOST
    `risk` is the only feature allowed to overwrite another feature's
    judgement. A bug here does not crash anything -- it quietly moves a real
    exposure down the page, which is the failure mode nobody notices in a demo
    and everybody notices in a breach. So the prohibitions are tested as
    explicitly as the rules.
"""

import pytest

from analysis.checks import risk


def a_finding(check, severity, detail="something happened", status="found", number=1):
    """A minimal F-1-shaped finding. Built by hand rather than through
    findings.make_finding() so a test can construct shapes the helpers would
    reject -- which is exactly what `risk` must survive."""
    return {
        "id": f"XX-{number:03d}",
        "check": check,
        "severity": severity,
        "device": "rtr-us5",
        "summary": "a finding",
        "evidence": {"detail": detail, "source": "rtr-us5:acl_in"},
        "status": status,
    }


# --- R-1: dead rules -------------------------------------------------------


def test_dead_rule_is_rated_low():
    f = a_finding("access_control", "high",
                  "Unreachable line: permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 eq 443")
    assert risk.severity_for(f) == "low"


def test_dead_rule_beats_the_blanket_permit_it_quotes():
    """R-1 before R-2, and this is the case that makes the order load-bearing.

    A dead-rule finding normally names the line that shadows it, and that line
    is very often the blanket permit. If R-2 ran first it would match the
    quoted BLOCKER and rate the dead rule high -- overstating a line that, by
    definition, can never match anything.
    """
    f = a_finding("access_control", "medium",
                  "Unreachable: permit tcp 10.10.10.0 host 10.20.0.5 eq 443 "
                  "-- blocked by: permit ip any any")
    assert risk.severity_for(f) == "low"


# --- R-2: blanket permits ---------------------------------------------------


def test_blanket_permit_is_rated_high():
    """The permit is the SUBJECT here -- the finding is about the line itself,
    with no attribution phrase making it the reason for something else."""
    f = a_finding("access_control", "low",
                  "The external interface permits everything: permit ip any any")
    assert risk.severity_for(f) == "high"


def test_blanket_permit_escalates_a_medium_from_another_check():
    """The point of a post-processor: one rule, applied across every check.

    Still the subject, just reported by a different check.
    """
    f = a_finding("policy_compliance", "medium",
                  "Filter acl_in ends with an unrestricted rule: permit ip any any")
    assert risk.severity_for(f) == "high"


# --- R-2: a CITATION is not the subject (the flattening bug) ----------------
#
# Measured on rtr-us5-insecure before this was fixed: all five findings end
# with a "decided by:"/"allowed by:" clause quoting the same `permit ip any
# any`, so R-2 fired on every one and 4 high + 1 medium collapsed to 5 high.
# None of those findings is ABOUT the permit -- they are five exposures that
# share one cause, and that cause is reported separately on its own finding.


def test_permit_cited_via_decided_by_does_not_promote():
    """`policy_compliance` and `access_control` both emit this form."""
    f = a_finding("policy_compliance", "medium",
                  "Flow start=rtr-us5 [10.10.10.0->8.8.8.8:80 TCP] is permitted "
                  "but policy forbids it. Decided by: permit ip any any")
    assert risk.severity_for(f) == "medium", "a cited permit must not promote"


def test_permit_cited_via_allowed_by_does_not_promote():
    """`access_control`'s searchFilters arm emits "allowed by:"."""
    f = a_finding("access_control", "medium",
                  "Example permitted flow: start=rtr-us5 "
                  "[10.10.10.0:49152->8.8.8.8:80 TCP (SYN)], allowed by: permit ip any any")
    assert risk.severity_for(f) == "medium", "a cited permit must not promote"


def test_attribution_matching_tolerates_spacing_and_case():
    """The producers are consistent today, but the rule should not depend on
    that -- it is matching prose, and prose drifts."""
    for detail in (
        "... is permitted. DECIDED BY:permit ip any any",
        "... is permitted. decided  by :  permit  ip  any  any",
        "... is permitted. Allowed By: permit ip any any",
    ):
        f = a_finding("policy_compliance", "medium", detail)
        assert risk.severity_for(f) == "medium", f"should not promote: {detail!r}"


def test_a_cited_permit_and_a_real_one_together_still_promotes():
    """If the evidence names the permit as the subject AND cites it as the
    reason, the subject wins. Suppression must not swallow a real mention."""
    f = a_finding("access_control", "medium",
                  "The filter ends with permit ip any any. "
                  "Decided by: permit ip any any")
    assert risk.severity_for(f) == "high"


# --- R-3: routing -----------------------------------------------------------


def test_routing_violation_is_downgraded_to_medium():
    """The one rule that routinely rates a finding LOWER than its check did."""
    f = a_finding("routing", "high", "Expected REACHABLE for a flow from 10.10.10.5")
    assert risk.severity_for(f) == "medium"


# --- R-4: default -----------------------------------------------------------


def test_unmatched_finding_keeps_its_checks_severity():
    f = a_finding("policy_compliance", "medium",
                  "Flow ... is permitted but policy forbids it. "
                  "Decided by: permit udp 10.0.0.0 0.255.255.255 any")
    assert risk.severity_for(f) == "medium"


# --- The prohibitions -------------------------------------------------------


@pytest.mark.parametrize("severity", ["high", "medium", "low"])
def test_error_findings_are_never_re_rated(severity):
    """Not "rated carefully" -- not rated at all.

    Evidence deliberately contains "permit ip any any", so R-2 WOULD fire if
    status were not checked first.
    """
    f = a_finding("access_control", severity,
                  "BatfishException: ... permit ip any any", status="error")
    assert risk.severity_for(f) == severity


def test_none_findings_are_never_re_rated():
    f = a_finding("routing", "low", "all reachable", status="none")
    assert risk.severity_for(f) == "low"


def test_refine_never_drops_a_finding():
    results = [
        a_finding("access_control", "high", "permit ip any any", number=1),
        a_finding("routing", "high", "no route", number=2),
        a_finding("policy_compliance", "low", "x", status="none", number=3),
        a_finding("access_control", "high", "y", status="error", number=4),
    ]
    out = risk.refine(results)
    assert len(out) == len(results)
    assert {f["id"] for f in out} == {f["id"] for f in results}


def test_refine_never_changes_status():
    results = [
        a_finding("routing", "high", "permit ip any any", status=s, number=i)
        for i, s in enumerate(("found", "none", "error"))
    ]
    before = {f["id"]: f["status"] for f in results}
    for f in risk.refine(results):
        assert f["status"] == before[f["id"]]


def test_refine_does_not_mutate_its_input():
    """The pipeline hands over copies, but relying on someone else's
    arrangement is how that arrangement quietly changes."""
    original = a_finding("access_control", "low", "permit ip any any")
    results = [original]
    risk.refine(results)
    assert original["severity"] == "low"


# --- Ordering ---------------------------------------------------------------


def test_refine_sorts_worst_first():
    results = [
        a_finding("policy_compliance", "low", "x", status="none", number=1),
        a_finding("access_control", "medium", "y", number=2),
        a_finding("access_control", "high", "z", status="error", number=3),
        a_finding("access_control", "high", "permit ip any any", number=4),
    ]
    out = risk.refine(results)
    assert [f["status"] for f in out] == ["error", "found", "found", "none"]
    found = [f for f in out if f["status"] == "found"]
    assert [f["severity"] for f in found] == ["high", "medium"]


def test_sort_is_stable_within_equal_rank():
    results = [
        a_finding("access_control", "high", "a", number=1),
        a_finding("policy_compliance", "high", "b", number=2),
        a_finding("access_control", "high", "c", number=3),
    ]
    out = risk.refine(results)
    assert [f["id"] for f in out] == ["XX-001", "XX-002", "XX-003"]


# --- Registration -----------------------------------------------------------


def test_risk_is_a_post_processor_and_not_a_check():
    """The shapes decision, asserted rather than trusted. Registering `risk` in
    CHECKS would hand it a Batfish session instead of the findings it exists to
    prioritise -- see docs/design/pipeline-feature-shapes.md."""
    from analysis import pipeline

    assert "risk" in pipeline.POST_PROCESSORS
    assert "risk" not in pipeline.CHECKS
    assert pipeline.POST_PROCESSORS["risk"] is risk.refine
