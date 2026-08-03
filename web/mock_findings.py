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

>>> THE PC-000 COLLISION IS DELIBERATE -- DO NOT "FIX" IT HERE <<<

    Two findings below share the id PC-000: the policy_compliance "none" and
    the change_impact "error". That is not a mistake in this file. It is a real
    defect in the shared contract, which this mock data exists to keep visible:

        PREFIX_BY_CHECK in analysis/findings.py maps BOTH policy_compliance
        and change_impact to the prefix "PC", and both use SENTINEL_NUMBER = 0
        for their "nothing found" / "could not run" findings. So any real run
        where one of Shubham's two checks is clean and the other errors
        produces two findings with the same id.

    docs/finding-format.md calls id a "unique identifier", and
    analysis/findings.py says outright that the dashboard uses id as a key. If
    the dashboard did that, one of these two would be silently dropped -- and
    if the dropped one were the error, the user would see "policy compliance:
    all clear" with no indication that change impact never ran.

    The dashboard is written not to key by id (see the note at the top of
    static/app.js), so it survives. This pair is the case that proves it.
    Renumber these only once the contract itself makes ids unique.
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
            source="analysis/checks/change_impact.py",
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
