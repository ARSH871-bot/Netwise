"""Netwise -- mock F-1 findings for building the dashboard against.

WHY THIS FILE EXISTS
    The dashboard has to be built before the other three checks land, so it
    needs findings to render. These are those findings: invented data in the
    real F-1 shape.

WHY THEY ARE BUILT WITH analysis.findings INSTEAD OF WRITTEN AS DICTS
    Because hand-written mock data drifts. If someone changes the contract in
    docs/finding-format.md and analysis/findings.py, a literal dict here would
    keep on looking fine while the dashboard quietly renders a shape the real
    pipeline no longer produces -- and we would not find out until the day we
    wire the two together.

    Building them through the same validators every real check uses means these
    mocks CANNOT be malformed. If the contract changes, this file raises on
    import, which is exactly when we want to hear about it.

WHAT THEY COVER
    Deliberately one of every case the dashboard has to render distinctly:

        found  / high    a real problem, serious
        found  / medium  a real problem, moderate
        found  / low     a real problem, minor
        none             a check that ran and found nothing   (green tick)
        error            a check that COULD NOT RUN           (amber warning)

    The last two are the point. See F-4 in docs/finding-format.md.

THE EVIDENCE IS REAL WHERE IT CAN BE
    Several of these quote the actual synthetic fixtures in tests/fixtures/, so
    the dashboard is rendering strings we genuinely produce rather than
    plausible-looking inventions. Nothing here describes a real network.

THE PC-000 COLLISION THIS FILE USED TO CARRY IS GONE -- A-2 FIXED IT

    This block used to say the opposite, in capitals: do not "fix" the PC-000
    collision here, because it was real. Two findings below shared one id --
    the policy_compliance "none" and the change_impact "error" -- because
    PREFIX_BY_CHECK in analysis/findings.py mapped BOTH checks to the prefix
    "PC" while both sentinels defaulted to number 0. Any real run where one of
    those checks was clean and the other errored produced two findings with the
    same id, and this file kept the pair on purpose so the defect stayed
    visible on screen.

    F-1 amendment A-2 (#102, merged 13 August) gave change_impact its own
    "CH-" prefix, so those two checks can no longer collide with each other at
    all. Nothing in this file changed: it builds every finding through the
    helpers in analysis/findings.py, so the new prefix arrived on its own. The
    ids these mocks emit today, which is the evidence for this comment:

        AC-001   PC-000   RT-001   CH-000   AC-002   RK-001
                 ^^^^^^            ^^^^^^
                 policy_compliance change_impact
                 "none"            "error"

    Six findings, six distinct ids, no duplicate in the list.

    Recorded rather than deleted, because the pair is cited by name elsewhere
    -- the note at the top of static/app.js, and the docstring of
    tests/test_findings_rendering.py, which was written against this pair and
    has since moved to one that collides WITHIN a single check. Someone
    following either of those references needs to find the answer here rather
    than a gap.

    THE DASHBOARD STILL DOES NOT KEY BY ID, and that is still correct -- see
    static/app.js for the reasoning. A-2 made two NAMED checks unable to
    collide; it did not make duplicate ids impossible, because uniqueness
    within a single check is still convention rather than structure.
"""

from typing import Any, Dict, List

from analysis import findings


def get_mock_findings() -> List[Dict[str, Any]]:
    """Return a list of F-1 findings covering every case the dashboard renders.

    Ordering here is deliberately messy -- unsorted, statuses interleaved --
    because the dashboard is responsible for grouping and ordering them, and a
    conveniently pre-sorted list would hide it if that logic were wrong.
    """
    return [
        # --- found / high -------------------------------------------------
        # Quotes tests/fixtures/rtr-us5-insecure: the specific HTTPS rule was
        # replaced with a blanket permit, so everything is allowed.
        findings.make_finding(
            check="access_control",
            severity="high",
            device="rtr-us5",
            summary="Unencrypted web traffic reaches the internal server",
            detail="Expected DENY but got PERMIT, decided by: permit ip any any",
            source="rtr-us5:acl_in",
            status="found",
            number=1,
        ),
        # --- none ---------------------------------------------------------
        # A check that RAN and found nothing. Good news. Must never look like
        # the error finding below.
        findings.no_issues_finding(
            check="policy_compliance",
            device="rtr-us5",
            summary="No issues found by policy compliance",
            detail="All 4 policy rules hold",
            source="rtr-us5",
        ),
        # --- found / medium -----------------------------------------------
        findings.make_finding(
            check="routing",
            severity="medium",
            device="rtr-us5",
            summary="Guest subnet has no return route to the finance VLAN",
            detail="Traceroute from 10.30.0.0/24 to 10.20.0.5 ends: NO_ROUTE",
            source="rtr-us5:GigabitEthernet0/1",
            status="found",
            number=1,
        ),
        # --- error ---------------------------------------------------------
        # A check that COULD NOT RUN. This is the one that must never be
        # mistaken for the "none" above. Note error_finding pins severity to
        # "high" on purpose -- a blind spot deserves attention -- which is
        # exactly why the dashboard must group by STATUS before severity.
        findings.error_finding(
            check="change_impact",
            device="rtr-us5",
            summary="Change impact check could not run: no baseline snapshot",
            detail=(
                "This check compares two snapshots and only one was loaded. "
                "Nothing was compared, so nothing can be said about the change."
            ),
            # analysis/change_impact.py, NOT analysis/checks/change_impact.py.
            # This said "checks/" until #140 landed the real file and made the
            # claim checkable. It was wrong twice over: the path did not exist,
            # and putting change_impact under checks/ asserts exactly what
            # analysis/checks/__init__.py forbids in capitals -- "DO NOT add
            # change_impact.py here or to CHECKS". A user-facing evidence
            # field is a bad place to contradict the architecture.
            source="analysis/change_impact.py",
        ),
        # --- found / low ----------------------------------------------------
        findings.make_finding(
            check="access_control",
            severity="low",
            device="rtr-us5",
            summary="ACL line can never match; an earlier line shadows it",
            detail=(
                "Unreachable: permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 "
                "eq 443 -- blocked by: permit ip any any"
            ),
            source="rtr-us5.cfg:21",
            status="found",
            number=2,
        ),
        # --- found / high, from the risk feature ----------------------------
        # ILLUSTRATIVE ONLY. Whether `risk` produces findings of its own, or
        # only re-rates the severity of other checks' findings, is the open
        # producer/post-processor question -- see the note in the response that
        # accompanied this file. The dashboard renders it identically either
        # way, because severity lives on the finding regardless of who set it.
        findings.make_finding(
            check="risk",
            severity="high",
            device="rtr-us5",
            summary="Internet-facing interface permits any source to any destination",
            detail="acl_in on GigabitEthernet0/0 (external) contains: permit ip any any",
            source="rtr-us5.cfg:21",
            status="found",
            number=1,
        ),
    ]
