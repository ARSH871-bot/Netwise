"""The F-4 guarantees, defended by tests rather than only by code.

WHY THIS FILE EXISTS
    Found by mutating each F-4 guarantee in turn and running the suite. Three
    of six survived -- enforced in code, noticed by nothing:

        status validation accepts anything             SURVIVED  304 passed
        check name validation accepts anything         SURVIVED  304 passed
        a check returning nothing is accepted as clean SURVIVED  304 passed

        a crashing check is silently dropped           caught
        post-processor may drop findings               caught
        duplicate ids no longer reported               caught

    A surviving mutation is not a bug today. It means a future refactor could
    delete the guarantee and every test would still pass -- which is how the
    two truncated guard tests survived for days, and how the `ruff` gate came
    to depend on an unstated condition.

    "304 tests pass" was a weaker claim standing in for "the safety guarantees
    are defended", and the gap between those two was three of the six things
    this project says it will never get wrong.

WHAT F-4 ACTUALLY PROMISES
    A failure must never disappear, and "we checked and found nothing" must
    never be confused with "we could not check". Everything below is one of
    those two sentences made testable.

A NOTE ON HOW THESE SWAP `CHECKS` ENTRIES
    Via `monkeypatch.setitem`, at @patelankeet2's suggestion on #128. The first
    version snapshotted the dict and restored it in a `finally`. He verified
    that was airtight -- captured `id(pipeline.CHECKS)` and its full contents
    before and after, same object, same references -- so this is not a bug fix.

    It is better anyway: pytest guarantees teardown however the test exits,
    including on an error raised before the `finally` is reached, and it is one
    mechanism rather than three copies of manual bookkeeping that each have to
    stay correct. `tests/test_finding_ids.py` already did it this way.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import pytest

from analysis import findings, pipeline


# ---------------------------------------------------------------------------
# 1. The F-1 field vocabulary is validated, not merely documented
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_status",
    ["", "ok", "clean", "FOUND", "none ", "warning", "pass", None, 0, True],
)
def test_an_invalid_status_is_rejected(bad_status):
    """`status` is the field F-4 rests on. If it can be anything, the
    distinction between "checked clean" and "could not check" is a convention
    rather than a contract, and a typo becomes a silent third state the
    dashboard has no branch for.

    `"FOUND"` and `"none "` are in the list deliberately: a case difference and
    a trailing space are what a real mistake looks like, not `"banana"`.
    """
    with pytest.raises(ValueError):
        findings.make_finding(
            check="access_control",
            severity="high",
            device="rtr-us5",
            summary="s",
            detail="d",
            source="s",
            status=bad_status,
            number=1,
        )


@pytest.mark.parametrize(
    "bad_check",
    ["", "acl", "Access_Control", "access-control", "risk_scoring", None, 7],
)
def test_an_invalid_check_name_is_rejected(bad_check):
    """The check name picks the ID prefix (`PREFIX_BY_CHECK`) and is what
    `run_post_processors()` reports a misbehaving stage under. An unvalidated
    name fails deep inside those, far from the cause -- which is exactly the
    failure #75 was about.
    """
    with pytest.raises(ValueError):
        findings.make_finding(
            check=bad_check,
            severity="high",
            device="rtr-us5",
            summary="s",
            detail="d",
            source="s",
            status="found",
            number=1,
        )


def test_every_valid_status_and_check_is_actually_accepted():
    """The other half. A validator that rejected everything would pass both
    tests above while making the contract unusable."""
    for status in findings.VALID_STATUSES:
        for check in findings.VALID_CHECKS:
            f = findings.make_finding(
                check=check,
                severity="low",
                device="d",
                summary="s",
                detail="d",
                source="s",
                status=status,
                number=1,
            )
            assert f["status"] == status
            assert f["check"] == check


# ---------------------------------------------------------------------------
# 2. A check that returns nothing must not read as clean
# ---------------------------------------------------------------------------


def test_a_check_returning_nothing_becomes_an_error_not_silence(monkeypatch):
    """The purest form of the F-4 failure, and it had no test.

    A check returning `[]` produces no card at all. The check simply vanishes
    from the results -- not errored, not clean, gone -- and the dashboard shows
    one fewer check with nothing saying so. `pipeline.py`'s own docstring calls
    this out: "We never return a short list that quietly omits the check that
    broke, because a missing check looks identical to a clean one."

    A check with nothing to report is supposed to say so with a
    `status="none"` finding. Returning `[]` is a bug in the check, and the
    pipeline turns it into a visible error rather than absorbing it.
    """
    monkeypatch.setitem(pipeline.CHECKS, "access_control", lambda bf: [])
    results = pipeline.run_check(None, "access_control")

    assert results, "a check returning [] produced NO finding -- it vanished"
    assert len(results) == 1
    assert results[0]["status"] == "error", (
        f"a check that returned nothing was reported as {results[0]['status']!r}; "
        "'none' would claim it ran and found nothing, which it did not say"
    )
    assert results[0]["check"] == "access_control", "the finding must name the check"


def test_a_check_returning_findings_is_left_alone(monkeypatch):
    """The guard must not fire on a healthy check, or it teaches people to
    return a dummy finding to silence it."""
    clean = findings.no_issues_finding(
        check="routing", device="d", summary="clean", detail="d", source="s"
    )
    monkeypatch.setitem(pipeline.CHECKS, "routing", lambda bf: [clean])
    results = pipeline.run_check(None, "routing")

    assert results == [clean]
    assert results[0]["status"] == "none"


def test_the_two_are_distinguishable_which_is_the_whole_point(monkeypatch):
    """F-4 in one assertion: a check that ran and found nothing, and a check
    that returned nothing, must not look the same to a consumer."""
    monkeypatch.setitem(pipeline.CHECKS, "routing", lambda bf: [
        findings.no_issues_finding(
            check="routing", device="d", summary="clean", detail="d", source="s"
        )
    ])
    ran_and_clean = pipeline.run_check(None, "routing")

    monkeypatch.setitem(pipeline.CHECKS, "routing", lambda bf: [])
    returned_nothing = pipeline.run_check(None, "routing")

    assert ran_and_clean[0]["status"] == "none"
    assert returned_nothing[0]["status"] == "error"
    assert ran_and_clean[0]["status"] != returned_nothing[0]["status"], (
        "'checked and found nothing' and 'could not check' collapsed into one "
        "state -- this is the failure F-4 exists to prevent"
    )
