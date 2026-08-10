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

import pytest

from analysis import findings
from analysis import pipeline
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


# ---------------------------------------------------------------------------
# evidence.detail must stay readable.
#
# A failed Batfish query raises an exception carrying the server's own log --
# measured at 5241 characters of work_item JSON, internal UUIDs and repeated
# "Loading configurations for NetworkSnapshot{...}" lines. That text is what
# the AI layer receives as its grounding and what the dashboard shows the
# client, so findings.describe_error() exists to condense it.
#
# It was applied unevenly: fixed in access_control and in analyse(), missed in
# run_check() and in policy_compliance, and only found by running the pipeline
# against a snapshot whose devices did not match. A grep is easy to forget; a
# test is not.
# ---------------------------------------------------------------------------


class _NoisyBatfishError(Exception):
    """Stands in for a real BatfishException, which carries the server log."""


_NOISY = "Work terminated abnormally\n" + (
    "Loading configurations for NetworkSnapshot{network=199dfd46}\n" * 60
)


def test_describe_error_keeps_the_actionable_first_line():
    text = findings.describe_error(_NoisyBatfishError(_NOISY))
    assert text == "_NoisyBatfishError: Work terminated abnormally"
    assert "\n" not in text
    assert "NetworkSnapshot" not in text


def test_describe_error_caps_a_long_single_line():
    text = findings.describe_error(_NoisyBatfishError("x" * 5000))
    assert len(text) <= 200


def test_a_crashing_check_does_not_leak_the_server_log(monkeypatch):
    """The run_check() crash path must condense, not interpolate.

    This is the exact site that was missed: analyse()'s early returns were
    fixed and this one was not, so a check that raised still put kilobytes of
    Java into a finding.
    """
    from analysis import pipeline

    def explodes(bf):
        raise _NoisyBatfishError(_NOISY)

    monkeypatch.setitem(pipeline.CHECKS, "access_control", explodes)
    results = pipeline.run_check(None, "access_control")

    assert len(results) == 1
    detail = results[0]["evidence"]["detail"]
    assert results[0]["status"] == "error"
    assert len(detail) <= 200, f"evidence.detail is {len(detail)} chars"
    assert "NetworkSnapshot" not in detail


# ---------------------------------------------------------------------------
# The post-processor stage.
#
# A post-processor sees the combined findings rather than a Batfish session --
# the second of the three shapes in docs/design/pipeline-feature-shapes.md.
# It may re-rate, re-order and annotate. It may NOT bury a blind spot or drop
# a finding, and those two limits were conditions of adopting the shape.
#
# They are tested rather than trusted. A rule that lives only in a document is
# a rule that holds until someone is in a hurry.
# ---------------------------------------------------------------------------


def _mixed_results():
    return [
        a_finding("access_control", 1),                      # AC-001 found/high
        a_finding("routing", 0, status="error"),             # RT-000 error/high
    ]


def test_no_post_processors_leaves_findings_untouched(monkeypatch):
    from analysis import pipeline

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {})
    results = _mixed_results()
    assert pipeline.run_post_processors([dict(f) for f in results]) == results


def test_a_post_processor_may_rerate_a_found_finding(monkeypatch):
    """Re-rating a real problem is exactly what risk prioritisation is for."""
    from analysis import pipeline

    def demote_found(results):
        for f in results:
            if f["status"] == "found":
                f["severity"] = "low"
        return results

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"risk": demote_found})
    out = pipeline.run_post_processors(_mixed_results())

    ac = next(f for f in out if f["id"] == "AC-001")
    assert ac["severity"] == "low", "a found finding may be re-rated freely"
    assert not any("downgraded" in f["summary"] for f in out)


def test_downgrading_an_error_finding_is_undone_and_reported(monkeypatch):
    """The carve-out: a blind spot must not be quietly filed below the fold."""
    from analysis import pipeline

    def bury_the_error(results):
        for f in results:
            if f["status"] == "error":
                f["severity"] = "low"
        return results

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"risk": bury_the_error})
    out = pipeline.run_post_processors(_mixed_results())

    rt = next(f for f in out if f["id"] == "RT-000")
    assert rt["severity"] == "high", "the error finding's severity must be restored"

    complaints = [f for f in out if "downgraded a blind spot" in f["summary"]]
    assert len(complaints) == 1
    assert complaints[0]["status"] == "error"
    assert "RT-000" in complaints[0]["evidence"]["detail"]


def test_dropping_a_finding_is_undone_and_reported(monkeypatch):
    """Removing a finding is the same lie as never producing it."""
    from analysis import pipeline

    monkeypatch.setattr(
        pipeline, "POST_PROCESSORS",
        {"risk": lambda results: [f for f in results if f["status"] != "error"]},
    )
    out = pipeline.run_post_processors(_mixed_results())

    assert any(f["id"] == "RT-000" for f in out), "the dropped finding must be restored"
    complaints = [f for f in out if "dropped a finding" in f["summary"]]
    assert len(complaints) == 1
    assert "RT-000" in complaints[0]["evidence"]["detail"]


def test_a_crashing_post_processor_becomes_an_error_finding(monkeypatch):
    """Same isolation the checks get: one stage failing must not lose the rest."""
    from analysis import pipeline

    def explodes(results):
        raise RuntimeError("boom\n" + "noise\n" * 50)

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"risk": explodes})
    out = pipeline.run_post_processors(_mixed_results())

    assert any(f["id"] == "AC-001" for f in out), "original findings survive"
    failure = next(f for f in out if "failed to run" in f["summary"])
    assert failure["status"] == "error"
    assert len(failure["evidence"]["detail"]) <= 200, "no server log in evidence.detail"


def test_a_post_processor_may_add_findings(monkeypatch):
    from analysis import pipeline

    def annotate(results):
        return results + [a_finding("risk", 1)]

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"risk": annotate})
    out = pipeline.run_post_processors(_mixed_results())
    assert any(f["id"] == "RK-001" for f in out)


# --- A post-processor registry key must be a valid F-1 check name (#75) ---------
#
# Both failure paths in run_post_processors() report a misbehaving
# post-processor with check=<registry key>, and F-1 rejects any check outside
# VALID_CHECKS. So the key is silently load-bearing. Found by Shubham while
# verifying the two guarantees before signing A-1.
#
# Latent today -- `risk` happens to be a valid check name -- but it failed in
# the worst possible place: while REPORTING that something else had gone
# wrong, out of an entry point documented never to raise operationally.


def test_a_valid_registry_key_still_works(monkeypatch):
    """The normal case must be untouched."""
    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"risk": lambda r: r})
    results = [a_finding("access_control", 1, "found")]
    assert [f["id"] for f in pipeline.run_post_processors(results)] == ["AC-001"]


def test_an_unregistered_key_fails_before_anything_runs(monkeypatch):
    """Not after, and not while reporting another failure.

    The post-processor here would raise if it were ever called. It must not
    be -- the names are checked first, so the failure is deterministic and
    happens at the same point every time rather than only on the error path.
    """
    def must_not_run(results):
        raise AssertionError("a post-processor ran before its name was checked")

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"evil": must_not_run})
    with pytest.raises(ValueError) as caught:
        pipeline.run_post_processors([a_finding("access_control", 1, "found")])

    message = str(caught.value)
    assert "evil" in message, "name the offending key"
    assert "risk" in message, "and list what would have been valid"


def test_the_error_path_no_longer_depends_on_the_key_being_valid(monkeypatch):
    """The original bug: a dropped finding triggers the restore path, which
    builds a finding with check=<key> and raised on an unregistered name --
    turning a contained fault into an uncaught ValueError from analyse()."""
    def drops_a_finding(results):
        return [f for f in results if f["id"] != "AC-002"]

    monkeypatch.setattr(pipeline, "POST_PROCESSORS", {"evil": drops_a_finding})
    with pytest.raises(ValueError) as caught:
        pipeline.run_post_processors(
            [a_finding("access_control", 1, "error"), a_finding("access_control", 2, "found")]
        )
    assert "POST_PROCESSORS keys" in str(caught.value), (
        "must fail on the registry name, not deep inside make_finding()"
    )
