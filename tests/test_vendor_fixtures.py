"""Netwise is not a Cisco-IOS-only tool, and these fixtures prove it.

WHAT THIS IS FOR
    Until this file existed every fixture in this repository was Cisco IOS,
    so "we support one vendor" was true of our evidence even though it was
    not true of our engine. Measured by feeding Batfish hand-written configs
    on the version already pinned in requirements.txt, with no tuning:

        arista_eos.cfg    PASSED                   ['sw-arista']
        cisco_nxos.cfg    PASSED                   ['sw-nexus']
        juniper.conf      PASSED                   ['rtr-juniper']
        cisco_asa.cfg     PARTIALLY_UNRECOGNIZED   ['fw-asa']

    Three parse cleanly. The fourth is not a Batfish gap either (#320): #217
    already taught `analyse()` to run the checks on a partially-parsed
    config AND attach a loud "results may be incomplete" caveat, rather than
    discard the whole analysis over a few unrecognised lines. All four are
    wired into this file now -- the restriction was ours, not Batfish's, and
    it no longer is.

PARSING IS NOT THE CLAIM
    "Batfish parsed it" is much weaker than "Netwise finds real problems in
    it", and only the second is worth telling anyone. So each fixture carries
    a DELIBERATE, DOCUMENTED FAULT that a policy-free analysis must catch --
    policy-free because our policy statements name our own devices, so a
    fixture with a different device name can only be caught by the two
    analyses that need no policy.

    Measured end to end through the real pipeline:

        vendor-arista    AC-002  ACL rule never takes effect in GUEST_IN
        vendor-nxos      AC-002  Config refers to ipv4 acl 'FINANCE_IN'
                                 which is not defined
        vendor-juniper   AC-002  ACL rule never takes effect in BRANCH_IN
        vendor-asa       AC-002  ACL rule never takes effect in OUTSIDE_IN
                                 -- AND a parse-caveat finding in the same
                                 run (#320's own test below pins both at
                                 once, because "parses" and "produces a
                                 finding" are different claims and vendor-asa
                                 is the one fixture where they genuinely
                                 diverge)

TWO PARTS, AND WHY
    PART 1 needs nothing but Python. It asserts each fixture still exists and
    still contains the fault it claims to. Every other test in this suite runs
    without Batfish, and a fixture silently emptied or edited would otherwise
    only be caught on a machine that happens to have Docker running.

    PART 2 needs Batfish and SKIPS without it. That is unavoidable -- the
    claim being tested is "Batfish parses this vendor", which cannot be
    checked without Batfish. It is marked loudly because a skipped test is
    indistinguishable from a passing one in pytest's summary line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

#: Each vendor fixture, the file in it, and a string that must still be there.
#: The marker is chosen to be the ACTUAL FAULT, not a comment about it -- a
#: fixture whose fault was edited away would still carry its own explanation.
VENDORS = {
    "vendor-arista": (
        "sw-arista.cfg",
        "20 deny tcp 10.30.0.0/24 host 10.99.0.7 eq 445",
        "a dead DENY, shadowed by the permit above it",
    ),
    "vendor-nxos": (
        "sw-nexus.cfg",
        "ip access-group FINANCE_IN in",
        "an access-group naming an ACL that is never defined",
    ),
    "vendor-juniper": (
        "rtr-juniper.conf",
        "term block-smb",
        "a dead firewall term, shadowed by allow-all above it",
    ),
    "vendor-asa": (
        "fw-asa.cfg",
        "access-list OUTSIDE_IN extended deny tcp any host 10.60.0.9 eq 3389",
        "a dead deny, shadowed by the permit above it",
    ),
}


# ---------------------------------------------------------------------------
# PART 1 -- needs nothing but Python. Always runs.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vendor", sorted(VENDORS))
def test_the_vendor_fixture_exists_and_is_not_empty(vendor):
    filename = VENDORS[vendor][0]
    path = FIXTURES / vendor / "configs" / filename
    assert path.is_file(), (
        f"{path} is missing. Batfish reads every file under configs/, so a "
        f"fixture in the wrong place produces an EMPTY snapshot that analyses "
        f"cleanly -- the worst possible way for this to break"
    )
    assert path.stat().st_size > 100, "a truncated fixture proves nothing"


@pytest.mark.parametrize("vendor", sorted(VENDORS))
def test_the_vendor_fixture_still_contains_its_deliberate_fault(vendor):
    """The fault is the point of the fixture. Without it, the test is a no-op.

    Guards the shape where somebody "tidies" a fixture, removes the broken
    line, and the integration test below starts passing for the wrong reason
    -- finding nothing because there is nothing to find.
    """
    filename, marker, description = VENDORS[vendor]
    text = (FIXTURES / vendor / "configs" / filename).read_text(encoding="utf-8")
    assert marker in text, (
        f"{vendor} no longer contains its deliberate fault ({description}). "
        f"Expected to find {marker!r}. Restore it, or this fixture is testing "
        f"that we find nothing in a clean config"
    )


def test_we_have_more_than_one_vendor():
    """The claim itself, asserted once.

    Checked against the length of VENDORS itself rather than a hand-typed
    number (#320) -- a hardcoded `>= 3` kept being technically true after
    vendor-asa joined as the fourth, which is exactly how a number in this
    project quietly stops meaning what it once did. If this file ever
    shrinks to a single vendor, "Netwise is multi-vendor" has stopped being
    true of our evidence, and this still catches it.
    """
    present = [v for v in VENDORS if (FIXTURES / v).is_dir()]
    assert len(present) == len(VENDORS), (
        f"{len(present)} of {len(VENDORS)} declared vendor fixture(s) "
        f"present: {present}"
    )
    assert len(present) >= 3, (
        f"only {len(present)} vendor fixture(s) present: {present}"
    )


# ---------------------------------------------------------------------------
# PART 2 -- needs Batfish. SKIPS without it, and says so.
# ---------------------------------------------------------------------------


# The probe and the marker now live in tests/conftest.py. They were here
# first and were the only copy; tests/test_sample_network.py needed the same
# gate, and one shared copy is the alternative to two that drift.
from conftest import needs_batfish  # noqa: E402


@needs_batfish
@pytest.mark.parametrize("vendor", sorted(VENDORS))
def test_each_vendor_produces_a_real_finding_end_to_end(vendor):
    """Not "it parsed" -- an actual finding, from the actual pipeline.

    This is the whole point of the fixtures. A config that parses cleanly and
    produces nothing is indistinguishable from a config we cannot read, which
    is the F-4 confusion arriving one layer further out than usual.
    """
    from analysis import pipeline

    results = pipeline.analyse(
        str(FIXTURES / vendor), snapshot_name=vendor.replace("-", "_"))

    found = [f for f in results if f["status"] == "found"]
    assert found, (
        f"{vendor} carries a deliberate fault and the pipeline reported no "
        f"finding. Either Batfish stopped parsing this vendor, or the fault "
        f"was edited out of the fixture. Statuses seen: "
        f"{sorted({f['status'] for f in results})}"
    )


@needs_batfish
def test_vendor_asa_parses_only_partially_and_still_finds_something():
    """#320's actual claim, pinned directly rather than left implicit.

    The other three vendor fixtures parse cleanly (`PASSED`). vendor-asa is
    the one where "parses" and "produces a finding" genuinely come apart --
    Batfish reports it `PARTIALLY_UNRECOGNIZED` (see the module docstring's
    measurement), and #217 is what makes that survivable: the checks still
    run AND a loud caveat finding is attached, rather than either being
    silently dropped for the other.

    Both must be true in the SAME run, or this fixture is not proving what
    it claims to:

      - a genuine `status="found"` finding (the deliberate dead-rule fault
        -- Netwise still works on this vendor)
      - a `number == PARTIAL_PARSE_NUMBER` caveat finding (the honest
        admission that some lines went unread -- Netwise does not pretend
        it read everything)
    """
    from analysis import pipeline

    results = pipeline.analyse(
        str(FIXTURES / "vendor-asa"), snapshot_name="vendor_asa")

    found = [f for f in results if f["status"] == "found"]
    assert found, (
        "vendor-asa produced no status=\"found\" finding -- either Batfish "
        "stopped parsing it at all, or the fault was edited out"
    )

    caveat_id_suffix = f"-{pipeline.PARTIAL_PARSE_NUMBER:03d}"
    caveats = [f for f in results if f.get("id", "").endswith(caveat_id_suffix)]
    assert caveats, (
        "vendor-asa produced a finding but no partial-parse caveat -- "
        "either Batfish now parses it cleanly (update the module docstring "
        "and this test) or #217's caveat stopped firing, which would be a "
        "real regression: a user would be told nothing about the lines "
        "Batfish could not read"
    )
