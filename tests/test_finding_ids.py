"""
Netwise -- tests for the one promise findings make about themselves: unique ids.

WHY THIS FILE IS THE FIRST TEST IN THE PROJECT
    Every verification in Netwise so far has been done by hand -- running the
    pipeline and reading the output. That works until it doesn't. The ID
    collision these tests cover was in the code for days, survived a code
    review, and was only found when someone built a dashboard and looked at
    real data. A test would have caught it the moment it was written.

    US-16 lists "tested code" as a deliverable. This is the start of that.

RUN
    pytest tests/ -v

These tests need neither Batfish nor Docker: they exercise the guard directly
with hand-built finding lists, so they run in milliseconds.
"""

from analysis import findings
from analysis.pipeline import duplicate_id_findings


def a_finding(check: str, number: int, status: str = "found") -> dict:
    """Build one valid F-1 finding with a chosen check and number."""
    if status == "none":
        return findings.no_issues_finding(
            check=check, device="rtr-us5", summary="clean", detail="d", source="s"
        )
    if status == "error":
        return findings.error_finding(
            check=check, summary="could not run", detail="d", source="s", number=number
        )
    return findings.make_finding(
        check=check,
        severity="high",
        device="rtr-us5",
        summary="a problem",
        detail="d",
        source="s",
        status="found",
        number=number,
    )


def test_unique_ids_produce_no_complaint():
    results = [
        a_finding("access_control", 1),
        a_finding("access_control", 2),
        a_finding("routing", 1),
    ]
    assert duplicate_id_findings(results) == []


def test_the_real_bug_sentinel_collision_is_caught():
    """policy_compliance clean + change_impact errored: both emit PC-000.

    This is the exact pair found while building the dashboard. The dangerous
    half is the error -- if a consumer keys by id and drops it, the user is
    told policy compliance is clean and never learns change impact did not run.
    """
    results = [
        a_finding("policy_compliance", 0, status="none"),
        a_finding("change_impact", 0, status="error"),
    ]
    assert results[0]["id"] == "PC-000"
    assert results[1]["id"] == "PC-000"

    complaints = duplicate_id_findings(results)
    assert len(complaints) == 1
    assert complaints[0]["status"] == "error"
    assert "PC-000" in complaints[0]["evidence"]["detail"]
    assert "policy_compliance" in complaints[0]["evidence"]["detail"]
    assert "change_impact" in complaints[0]["evidence"]["detail"]


def test_real_findings_collide_too_not_just_sentinels():
    """The path a sentinel-only fix would miss: make_finding with the same number.

    policy_compliance and change_impact share the "PC" prefix, so their first
    real finding is PC-001 for both. There is no default to fix here -- number
    is a required argument.
    """
    results = [
        a_finding("policy_compliance", 1),
        a_finding("change_impact", 1),
    ]
    assert results[0]["id"] == results[1]["id"] == "PC-001"
    assert len(duplicate_id_findings(results)) == 1


def test_nothing_is_renumbered_or_dropped():
    """The guard reports; it must never silently repair.

    Quietly disambiguating would hide the defect, which is the behaviour we are
    trying to prevent.
    """
    results = [
        a_finding("policy_compliance", 1),
        a_finding("change_impact", 1),
    ]
    before = [dict(f) for f in results]
    duplicate_id_findings(results)
    assert results == before


def test_the_guards_own_finding_cannot_collide():
    """The guard uses 999, clear of sentinels (000) and of real numbering."""
    results = [
        a_finding("policy_compliance", 0, status="none"),
        a_finding("change_impact", 0, status="error"),
    ]
    complaint = duplicate_id_findings(results)[0]
    assert complaint["id"] not in {f["id"] for f in results}
    assert complaint["id"] == "PC-999"


def test_three_way_collision_is_reported_once():
    results = [
        a_finding("policy_compliance", 1),
        a_finding("change_impact", 1),
        a_finding("policy_compliance", 1),
    ]
    complaints = duplicate_id_findings(results)
    assert len(complaints) == 1


def test_guard_output_is_a_valid_f1_finding():
    """Whatever the guard emits still has to obey the contract it is defending."""
    results = [
        a_finding("policy_compliance", 1),
        a_finding("change_impact", 1),
    ]
    complaint = duplicate_id_findings(results)[0]
    assert set(complaint) == {
        "id",
        "check",
        "severity",
        "device",
        "summary",
        "evidence",
        "status",
    }
    assert set(complaint["evidence"]) == {"detail", "source"}
    assert complaint["check"] in findings.VALID_CHECKS
    assert complaint["severity"] in findings.VALID_SEVERITIES
    assert complaint["status"] in findings.VALID_STATUSES


# ---------------------------------------------------------------------------
# The early-return paths of analyse().
#
# These matter more than they look. When Batfish is unreachable -- the single
# most common operational failure -- analyse() returns one sentinel error per
# registered check WITHOUT running any of them. The duplicate-id guard was
# originally only applied to the happy path, so this, the likeliest failure,
# was the one case it did not cover.
# ---------------------------------------------------------------------------


def test_batfish_unreachable_still_guards_ids(monkeypatch):
    """Every check name in play + Batfish down -> the PC-000 pair is reported.

    Registers all five names from VALID_CHECKS to force the collision. That is
    test setup, not a claim about the architecture: `change_impact` will never
    be a CHECKS entry (see docs/design/pipeline-feature-shapes.md). The
    collision it exercises is still real, because change_impact findings still
    carry the `PC-` prefix and will meet policy_compliance findings wherever
    the two lists are shown together.
    """
    from analysis import pipeline

    # Register every check name. The functions are never called on this path,
    # because connect() fails first.
    monkeypatch.setattr(
        pipeline, "CHECKS", {name: (lambda bf: []) for name in findings.VALID_CHECKS}
    )

    # Simulate the failure rather than pointing at an unroutable address. Using
    # a real dead host makes this test wait out a TCP timeout -- measured at
    # ~80 seconds, which is how test suites stop being run.
    def refuse(host="localhost"):
        raise ConnectionError("Max retries exceeded: connection refused")

    monkeypatch.setattr(pipeline, "connect", refuse)
    results = pipeline.analyse("tests/fixtures/rtr-us5-secure")

    per_check = [f for f in results if f["summary"].startswith("Analysis could not run")]
    assert len(per_check) == len(findings.VALID_CHECKS), "one error per check"
    assert all(f["status"] == "error" for f in per_check)

    # The collision is present in the raw output...
    assert sorted(f["id"] for f in per_check).count("PC-000") == 2
    # ...and the guard reported it rather than letting it pass silently.
    complaints = [f for f in results if f["summary"].startswith("Internal error")]
    assert len(complaints) == 1
    assert "PC-000" in complaints[0]["evidence"]["detail"]


def test_unloadable_config_still_guards_ids(monkeypatch):
    """Same for the snapshot-load failure path, which also returns early."""
    from analysis import pipeline

    monkeypatch.setattr(
        pipeline, "CHECKS", {name: (lambda bf: []) for name in findings.VALID_CHECKS}
    )
    monkeypatch.setattr(pipeline, "connect", lambda host="localhost": object())

    results = pipeline.analyse("tests/fixtures/does-not-exist")

    assert any(f["summary"].startswith("Internal error") for f in results), (
        "the duplicate-id guard must run on this early-return path too"
    )
