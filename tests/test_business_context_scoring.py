"""Tests for business-context escalation in `risk` (#87, risk side).

WHAT THIS PASS IS ALLOWED TO DO, AND THE FOUR PROPERTIES THAT BOUND IT
    `apply_business_context()` may make a finding on an asset the user
    singled out score one level worse. Everything else is a limit:

      1. AT MOST ONE LEVEL. `low` never becomes `high`. Criticality says
         the asset matters, not that the evidence says something worse.
      2. ESCALATION ONLY. No tier lowers anything.
      3. NO MATCH MEANS NO CHANGE, EXACTLY. This is the R-2 lesson
         restated: absence of information is not information. A context
         naming three critical servers says nothing at all about a fourth
         device, and treating "unlisted" as "unimportant" would invent a
         judgement the user never made.
      4. NEVER INVENTS A FINDING, never drops one, never touches one that
         is not status="found".

    Each has a mutation alongside it in the harness, because a guard
    nobody has watched fail is a guard nobody knows works.

WHY THIS IS A SEPARATE FILE FROM test_severity_rules.py
    R-1..R-4 all read only the finding they are handed, which is what
    makes them recomputable by hand. This pass takes a second input, and
    keeping its tests next to the ruleset's would blur exactly the line
    the implementation is at pains to keep.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import pytest

from analysis.business_context import BusinessContext, load_business_context
from analysis.checks.risk import (
    apply_business_context,
    refine,
    unusable_entries,
)


def _finding(**overrides):
    base = {
        "id": "AC-001",
        "check": "access_control",
        "severity": "medium",
        "device": "rtr-us5",
        "summary": "A rule allows traffic that policy forbids",
        "evidence": {"detail": "flow permitted", "source": "testFilters"},
        "status": "found",
    }
    base.update(overrides)
    return base


def _context(*entries):
    return load_business_context(list(entries))


CRITICAL_US5 = [{"device": "rtr-us5", "tier": "critical"}]


# ---------------------------------------------------------------------------
# 1. A critical device escalates -- by exactly one level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "before, after",
    [("low", "medium"), ("medium", "high")],
)
def test_a_critical_device_escalates_exactly_one_level(before, after):
    result = apply_business_context(
        [_finding(severity=before)], _context(*CRITICAL_US5)
    )

    assert result[0]["severity"] == after


def test_low_never_jumps_straight_to_high():
    """The property the one-level cap exists for, asserted on its own.

    Stated separately from the parametrised case above because it is the
    thing that would actually go wrong: a rewrite that "promotes critical
    findings to high" reads perfectly reasonably and silently discards the
    distinction between a dead rule and an open firewall on the same box.
    """
    result = apply_business_context([_finding(severity="low")], _context(*CRITICAL_US5))

    assert result[0]["severity"] == "medium"
    assert result[0]["severity"] != "high"


def test_a_finding_already_at_the_top_stays_there_and_does_not_wrap():
    """`high` is the top. There is no level above it to invent, and wrapping
    round to `low` would be the worst possible bug in a list read top-down."""
    result = apply_business_context([_finding(severity="high")], _context(*CRITICAL_US5))

    assert result[0]["severity"] == "high"


def test_escalating_the_top_severity_returns_a_whole_usable_finding():
    """The failure mode worth ruling out is an exception -- or a mangled
    finding -- on the most important item in the list.

    Written first as a bare call with no assertion, on the reasoning that
    "it raises or it does not". `test_suite_hygiene.py` rejected it, and
    correctly: a static scan cannot tell that from an abandoned
    placeholder, and the rule is only worth anything if it has no
    exceptions. Asserting the finding survives intact is the stronger test
    anyway.
    """
    result = apply_business_context(
        [_finding(severity="high")], _context(*CRITICAL_US5)
    )

    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["id"] == "AC-001"
    assert result[0]["evidence"]["source"] == "testFilters"


def test_a_severity_this_module_does_not_recognise_is_left_alone():
    """Not a severity F-1 permits, so it should not be edited into one.

    A pass that "escalates" an unknown value is guessing at a vocabulary it
    does not own.
    """
    result = apply_business_context(
        [_finding(severity="catastrophic")], _context(*CRITICAL_US5)
    )

    assert result[0]["severity"] == "catastrophic"


# ---------------------------------------------------------------------------
# 2. No match means no change -- exactly
# ---------------------------------------------------------------------------


def test_a_device_with_no_entry_is_untouched():
    """The R-2 lesson restated. Absence of context is not information.

    A context naming rtr-us5 says nothing whatsoever about sw-lab-1.
    """
    result = apply_business_context(
        [_finding(device="sw-lab-1", severity="medium")], _context(*CRITICAL_US5)
    )

    assert result[0]["severity"] == "medium"


def test_an_unmatched_finding_is_returned_completely_unchanged():
    """Not just the severity -- the whole finding.

    A pass that leaves the severity alone but quietly rewrites a summary or
    drops evidence would still be changing what the user reads.
    """
    original = _finding(device="sw-lab-1")
    result = apply_business_context([original], _context(*CRITICAL_US5))

    assert result[0] == original


def test_an_empty_context_changes_nothing():
    findings = [_finding(severity="medium"), _finding(id="AC-002", severity="low")]

    assert apply_business_context(findings, BusinessContext()) == findings


def test_no_context_at_all_changes_nothing():
    findings = [_finding(severity="medium")]

    assert apply_business_context(findings, None) == findings


@pytest.mark.parametrize("tier", ["important", "standard"])
def test_a_non_escalating_tier_leaves_the_severity_exactly_alone(tier):
    """`important` and `standard` are recorded but do not move a severity.

    Deliberate: with three severities and a one-level cap there is no room
    for `important` to mean something between `critical` and no change, and
    giving it +1 too would make the two tiers identical. Pinned here so
    changing it is a decision someone makes, not a default that slips in.
    """
    result = apply_business_context(
        [_finding(severity="medium")], _context({"device": "rtr-us5", "tier": tier})
    )

    assert result[0]["severity"] == "medium"


def test_no_tier_ever_lowers_a_severity():
    """Escalation only. `standard` does not mean safe -- it means the user
    did not single the asset out, and filing those findings lower would use
    a shrug as evidence."""
    for tier in ("critical", "important", "standard"):
        result = apply_business_context(
            [_finding(severity="high")], _context({"device": "rtr-us5", "tier": tier})
        )
        assert result[0]["severity"] == "high", tier


def test_a_device_name_matches_exactly_and_not_by_prefix():
    """"rtr-us5" must not match "rtr-us5-backup".

    Substring matching would escalate findings on a device the user never
    named, which is inventing a judgement rather than applying one.
    """
    result = apply_business_context(
        [_finding(device="rtr-us5-backup", severity="medium")],
        _context(*CRITICAL_US5),
    )

    assert result[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# 3. Only status="found" is ever touched
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["error", "none"])
def test_a_finding_that_is_not_found_is_never_escalated(status):
    """An unrunnable check is a blind spot whatever tier the device carries,
    and there is no severity worth editing on a blind spot. F-4."""
    result = apply_business_context(
        [_finding(status=status, severity="medium")], _context(*CRITICAL_US5)
    )

    assert result[0]["severity"] == "medium"


def test_the_unknown_device_sentinel_on_an_error_finding_is_not_escalated():
    """Checks emit `device="unknown"` on some error findings, and a user
    could legitimately have a device called that. The status guard is what
    stops the two meeting; this pins it."""
    result = apply_business_context(
        [_finding(device="unknown", status="error", severity="medium")],
        _context({"device": "unknown", "tier": "critical"}),
    )

    assert result[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# 4. Never invents or drops a finding
# ---------------------------------------------------------------------------


def test_every_finding_comes_back_and_no_new_one_appears():
    findings = [
        _finding(id="AC-001", device="rtr-us5"),
        _finding(id="RT-050", device="sw-lab-1", check="routing"),
        _finding(id="PC-001", device="rtr-us5", status="none", severity="low"),
    ]

    result = apply_business_context(findings, _context(*CRITICAL_US5))

    assert [f["id"] for f in result] == ["AC-001", "RT-050", "PC-001"]


def test_the_input_list_is_not_mutated():
    """The pipeline hands over copies, but a pass that mutates its input is
    only safe by someone else's arrangement."""
    findings = [_finding(severity="medium")]

    apply_business_context(findings, _context(*CRITICAL_US5))

    assert findings[0]["severity"] == "medium"


@pytest.mark.parametrize(
    "context",
    [None, BusinessContext(), load_business_context(CRITICAL_US5)],
    ids=["no-context", "empty-context", "real-context"],
)
def test_findings_are_always_copied_whichever_path_runs(context):
    """Identity, not just value -- and this test exists because a mutation
    survived without it.

    The empty-context short-circuit returned `list(results)`: equal to the
    input by value, but the SAME dict objects. So a caller editing a
    returned finding would corrupt its own input on the no-context path and
    not on the other, and every value-comparing test passed either way.
    Aliasing that depends on whether a file happened to be uploaded is the
    kind of difference that surfaces once, in production, as a severity
    nobody can reproduce.
    """
    findings = [_finding(severity="medium")]

    result = apply_business_context(findings, context)
    result[0]["severity"] = "tampered"

    assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Subnet entries: a real gap, and it must not be a silent one
# ---------------------------------------------------------------------------


def test_a_subnet_entry_does_not_match_a_device_name():
    """Deciding whether 10.10.10.0/24 IS rtr-us5 needs interface enumeration
    this project does not have -- `ai/query.py`'s limit, restated."""
    result = apply_business_context(
        [_finding(severity="medium")],
        _context({"subnet": "10.10.10.0/24", "tier": "critical"}),
    )

    assert result[0]["severity"] == "medium"


def test_an_unusable_subnet_entry_is_reported_rather_than_silently_ignored():
    """The dangerous version of that gap is the silent one: a user tags the
    finance VLAN by subnet, sees no change, and concludes it was applied."""
    notes = unusable_entries(
        _context({"subnet": "10.10.10.0/24", "tier": "critical", "description": "Finance VLAN"})
    )

    assert len(notes) == 1
    assert "Finance VLAN" in notes[0]
    assert "device name only" in notes[0]


def test_a_device_entry_produces_no_unusable_note():
    assert unusable_entries(_context(*CRITICAL_US5)) == []


# ---------------------------------------------------------------------------
# refine(): the wiring, and that today's behaviour is unchanged without one
# ---------------------------------------------------------------------------


def test_refine_without_a_context_behaves_exactly_as_before():
    """The default keeps POST_PROCESSORS' one-argument call intact, and with
    no context not one severity moves."""
    findings = [_finding(severity="medium"), _finding(id="AC-002", severity="low")]

    assert [f["severity"] for f in refine(findings)] == ["medium", "low"]


def test_refine_applies_the_context_when_given_one():
    result = refine([_finding(severity="medium")], _context(*CRITICAL_US5))

    assert result[0]["severity"] == "high"


def test_context_applies_to_the_settled_severity_not_the_checks_default():
    """Order is load-bearing.

    R-3 lowers a routing finding to `medium` whatever the check said. A
    routing finding on a critical device must therefore land on `high` --
    escalated from R-3's verdict. If the context ran first it would
    escalate the check's own `high`, cap there, and R-3 would then pull it
    back to `medium`: the same two rules, opposite answer, decided by line
    order rather than by anyone.
    """
    routing = _finding(id="RT-050", check="routing", severity="high")

    assert refine([routing])[0]["severity"] == "medium"
    assert refine([routing], _context(*CRITICAL_US5))[0]["severity"] == "high"


def test_escalation_changes_the_order_on_screen():
    """Escalation happens before the sort, so the list the user reads is
    ordered by the severities they are actually shown."""
    findings = [
        _finding(id="AC-002", device="sw-lab-1", severity="medium"),
        _finding(id="AC-001", device="rtr-us5", severity="medium"),
    ]

    assert [f["id"] for f in refine(findings)] == ["AC-002", "AC-001"]
    assert [f["id"] for f in refine(findings, _context(*CRITICAL_US5))] == [
        "AC-001",
        "AC-002",
    ]


def test_refine_still_returns_every_finding_with_a_context():
    findings = [
        _finding(id="AC-001", device="rtr-us5"),
        _finding(id="PC-001", device="rtr-us5", status="error", severity="low"),
    ]

    result = refine(findings, _context(*CRITICAL_US5))

    assert sorted(f["id"] for f in result) == ["AC-001", "PC-001"]
