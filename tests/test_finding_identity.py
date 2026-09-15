"""Is this the same problem as last time? (US-33, #325)

THE FINDINGS BELOW ARE REAL, NOT WRITTEN FOR THE TEST
    Each literal was produced by `analysis.pipeline.analyse()` against real
    Batfish on 15 September 2026 and pasted in verbatim by a script, so a
    test cannot pass because somebody wrote a convenient fixture. Copies,
    because the suite needs neither Batfish nor Ollama.

The acceptance criterion names the collision to measure against:
rtr-us5-insecure and rtr-us5-messy both emit AC-001 for different problems.
The harder case, found while designing this, is messy's AC-002 and AC-003:
identical in every field except `evidence.detail`.
"""

from __future__ import annotations

import copy

import pytest

from analysis import identity

# --- Real findings, verbatim ---------------------------------------------------
INSECURE_AC_001 = {'id': 'AC-001',
 'check': 'access_control',
 'severity': 'high',
 'device': 'rtr-us5',
 'summary': 'Unencrypted web traffic reaches the internal server',
 'evidence': {'detail': 'Expected DENY but got PERMIT, decided by: permit '
                        'ip any any',
              'source': 'rtr-us5:acl_in'},
 'status': 'found'}
INSECURE_AC_002 = {'id': 'AC-002',
 'check': 'access_control',
 'severity': 'high',
 'device': 'rtr-us5',
 'summary': 'Unencrypted web traffic is allowed out of the internal subnet',
 'evidence': {'detail': 'Example permitted flow: start=rtr-us5 '
                        '[10.10.10.0:49152->8.8.8.8:80 TCP (SYN)], allowed '
                        'by: permit ip any any',
              'source': 'rtr-us5:acl_in'},
 'status': 'found'}
MESSY_AC_001 = {'id': 'AC-001',
 'check': 'access_control',
 'severity': 'medium',
 'device': 'rtr-us5',
 'summary': 'DNS to the approved server is blocked, so name lookups will '
            'fail',
 'evidence': {'detail': 'Expected PERMIT but got DENY, decided by: deny   '
                        'ip 10.10.10.0 0.0.0.255 any',
              'source': 'rtr-us5:acl_in'},
 'status': 'found'}
MESSY_AC_002 = {'id': 'AC-002',
 'check': 'access_control',
 'severity': 'low',
 'device': 'rtr-us5',
 'summary': 'ACL rule never takes effect in acl_in',
 'evidence': {'detail': 'Unreachable line: permit udp 10.10.10.0 0.0.0.255 '
                        'host 218.8.104.58 eq domain (action PERMIT). '
                        'Blocked by: deny   ip 10.10.10.0 0.0.0.255 any. '
                        'Reason: BLOCKING_LINES',
              'source': 'rtr-us5: acl_in'},
 'status': 'found'}
MESSY_AC_003 = {'id': 'AC-003',
 'check': 'access_control',
 'severity': 'low',
 'device': 'rtr-us5',
 'summary': 'ACL rule never takes effect in acl_in',
 'evidence': {'detail': 'Unreachable line: permit tcp 10.10.10.0 0.0.0.255 '
                        'host 10.20.0.5 eq 443 (action PERMIT). Blocked '
                        'by: deny   ip 10.10.10.0 0.0.0.255 any. Reason: '
                        'BLOCKING_LINES',
              'source': 'rtr-us5: acl_in'},
 'status': 'found'}

MESSY_AC_004 = {'id': 'AC-004',
 'check': 'access_control',
 'severity': 'high',
 'device': 'rtr-us5',
 'summary': "Config refers to ipv4 acl 'acl_guest_in' which is not defined",
 'evidence': {'detail': 'Referenced as: interface incoming ip access-list. '
                        "The structure 'acl_guest_in' is never defined in "
                        'this snapshot.',
              'source': 'configs/rtr-us5.cfg:[37]'},
 'status': 'found'}


def _variant(finding, **changes):
    out = copy.deepcopy(finding)
    for key, value in changes.items():
        if key in ("source", "detail"):
            out["evidence"][key] = value
        else:
            out[key] = value
    return out


# --- id is not identity --------------------------------------------------------


def test_the_named_collision_gets_two_identities():
    """The acceptance criterion's own case: both are AC-001."""
    assert INSECURE_AC_001["id"] == MESSY_AC_001["id"] == "AC-001"
    assert identity.fingerprint(INSECURE_AC_001) != identity.fingerprint(MESSY_AC_001)


def test_two_dead_rules_differing_only_in_detail_stay_two():
    """The case that put `evidence.detail` into the fingerprint.

    Identical check, device, source and summary. A key without `detail`
    merges them, and fixing one dead rule would read as no change at all.
    """
    for field in ("check", "device", "summary"):
        assert MESSY_AC_002[field] == MESSY_AC_003[field]
    assert MESSY_AC_002["evidence"]["source"] == MESSY_AC_003["evidence"]["source"]
    assert identity.fingerprint(MESSY_AC_002) != identity.fingerprint(MESSY_AC_003)


def test_a_shared_structural_key_does_not_merge_different_problems():
    """Insecure AC-001 and AC-002: same check, device and source, different problems."""
    assert INSECURE_AC_001["evidence"]["source"] == INSECURE_AC_002["evidence"]["source"]
    assert identity.fingerprint(INSECURE_AC_001) != identity.fingerprint(INSECURE_AC_002)


# --- What must NOT change identity --------------------------------------------


@pytest.mark.parametrize("change", [
    {"id": "AC-099"},
    {"severity": "low"},
    {"status": "error"},
], ids=["id", "severity", "status"])
def test_fields_outside_the_problem_do_not_change_identity(change):
    """id is positional; severity is re-rated by risk; status is what a diff compares."""
    assert identity.fingerprint(_variant(INSECURE_AC_001, **change)) == \
        identity.fingerprint(INSECURE_AC_001)


def test_whitespace_in_source_does_not_change_identity():
    """The same check writes both "rtr-us5:acl_in" and "rtr-us5: acl_in"."""
    assert MESSY_AC_001["evidence"]["source"] == "rtr-us5:acl_in"
    assert MESSY_AC_002["evidence"]["source"] == "rtr-us5: acl_in"
    assert identity.fingerprint(_variant(MESSY_AC_001, source="rtr-us5: acl_in")) == \
        identity.fingerprint(MESSY_AC_001)


def test_case_and_spacing_in_prose_do_not_change_identity():
    shouted = _variant(INSECURE_AC_001,
                       summary="  " + INSECURE_AC_001["summary"].upper() + "  ")
    assert identity.fingerprint(shouted) == identity.fingerprint(INSECURE_AC_001)


# --- What MUST change identity --------------------------------------------------


@pytest.mark.parametrize("field, value", [
    ("check", "policy_compliance"),
    ("device", "rtr-other"),
    ("source", "rtr-us5:acl_out"),
    ("summary", "Something else entirely"),
    ("detail", "Unreachable line: permit tcp any any eq 22"),
])
def test_each_field_of_the_problem_changes_identity(field, value):
    assert identity.fingerprint(_variant(INSECURE_AC_001, **{field: value})) != \
        identity.fingerprint(INSECURE_AC_001)


def test_digits_are_not_normalised_away():
    """An IP or port is exactly what separates two real problems."""
    other_port = _variant(MESSY_AC_003, detail=MESSY_AC_003["evidence"]["detail"]
                          .replace("eq 443", "eq 444"))
    assert identity.fingerprint(other_port) != identity.fingerprint(MESSY_AC_003)


# --- compare() -----------------------------------------------------------------


def test_the_same_scan_twice_is_all_unchanged():
    scan = [INSECURE_AC_001, INSECURE_AC_002]
    result = identity.compare(scan, copy.deepcopy(scan))
    assert len(result["unchanged"]) == 2
    assert result["appeared"] == [] and result["disappeared"] == []


def test_ids_reshuffling_between_runs_is_still_unchanged():
    """access_control numbers positionally, so ids can swap on the same network."""
    before = [INSECURE_AC_001, INSECURE_AC_002]
    after = [_variant(INSECURE_AC_002, id="AC-001"), _variant(INSECURE_AC_001, id="AC-002")]
    result = identity.compare(before, after)
    assert len(result["unchanged"]) == 2
    assert result["appeared"] == [] and result["disappeared"] == []


def test_fixing_one_of_two_identical_looking_dead_rules_is_visible():
    """The failure a detail-free key would cause: one fix, reported as no change."""
    result = identity.compare([MESSY_AC_002, MESSY_AC_003], [MESSY_AC_003])
    assert result["disappeared"] == [MESSY_AC_002]
    assert result["unchanged"] == [MESSY_AC_003]
    assert result["appeared"] == []


def test_counts_are_honoured_not_collapsed():
    """Two copies before, one after: one unchanged, one disappeared -- not zero, not two."""
    result = identity.compare([INSECURE_AC_001, INSECURE_AC_001], [INSECURE_AC_001])
    assert len(result["unchanged"]) == 1
    assert len(result["disappeared"]) == 1


def test_one_appearing_and_one_disappearing_are_separate():
    result = identity.compare([INSECURE_AC_001], [MESSY_AC_001])
    assert result["disappeared"] == [INSECURE_AC_001]
    assert result["appeared"] == [MESSY_AC_001]


# --- Similarity is a hint, never a merge ----------------------------------------


REWORDED_BEFORE = {
    "id": "RT-001", "check": "routing", "severity": "high", "device": "rtr-hq",
    "summary": "The HQ network cannot reach the branch network; a route appears "
               "to be missing",
    "evidence": {"detail": "x", "source": "rtr-hq:10.20.20.5"}, "status": "found",
}
REWORDED_AFTER = _variant(REWORDED_BEFORE,
                          summary="The HQ network cannot reach the branch network")


def test_a_real_rewording_is_flagged_as_possibly_the_same():
    """Recovered from git: routing.py's violation_summary was shortened (6d7c769).

    Identity changes -- the text changed -- so it disappears and reappears. It is
    also flagged, so a reader is not told a problem vanished and another
    appeared when the wording merely moved.
    """
    result = identity.compare([REWORDED_BEFORE], [REWORDED_AFTER])
    assert result["disappeared"] == [REWORDED_BEFORE]
    assert result["appeared"] == [REWORDED_AFTER]
    assert len(result["possibly_same"]) == 1


def test_a_flag_never_removes_anything_from_appeared_or_disappeared():
    """THE ONE THAT MATTERS. A hint is not a verdict.

    Insecure AC-001 and AC-002 read 0.732 alike and ARE different problems.
    They get flagged -- correctly, for a person to judge -- and both stay
    exactly where they are.
    """
    result = identity.compare([INSECURE_AC_002], [INSECURE_AC_001])
    assert result["disappeared"] == [INSECURE_AC_002]
    assert result["appeared"] == [INSECURE_AC_001]
    assert result["unchanged"] == []
    (old, fresh, score), = result["possibly_same"]
    assert (old, fresh) == (INSECURE_AC_002, INSECURE_AC_001)
    assert score == pytest.approx(0.732, abs=0.001)


def test_dissimilar_findings_are_not_flagged():
    result = identity.compare([MESSY_AC_001], [INSECURE_AC_001])
    assert result["possibly_same"] == []


def test_different_devices_are_never_flagged_however_alike():
    elsewhere = _variant(INSECURE_AC_001, device="rtr-branch")
    result = identity.compare([INSECURE_AC_001], [elsewhere])
    assert result["possibly_same"] == []


def test_a_line_shift_is_flagged_not_merged():
    """The documented limit, measured end to end rather than asserted.

    Against real Batfish: deleting ONE bare `!` comment line from the top of
    rtr-us5-messy's config changed nothing about the network, and moved this
    undefined-reference finding's source from `[37]` to `[36]`:

        unchanged 6   disappeared 1 ([37])   appeared 1 ([36])
        possibly_same 1   similarity 1.0

    The same problem therefore reads as one disappeared and one appeared. That is
    the conservative failure -- two real problems are never merged into one
    -- and it is only acceptable because the pair is flagged for a person.
    If this test starts failing because the pair is NOT flagged, a harmless
    edit will look like a fix plus a regression with nothing to say so.
    """
    shifted = _variant(MESSY_AC_004, source="configs/rtr-us5.cfg:[36]")
    result = identity.compare([MESSY_AC_004], [shifted])
    assert result["disappeared"] == [MESSY_AC_004]
    assert result["appeared"] == [shifted]
    (old, fresh, score), = result["possibly_same"]
    assert score == 1.0


def test_the_keys_do_not_claim_fixed_or_introduced():
    """`resolved` and `new` were renamed because they overclaimed (#223 design).

    With Batfish down, a scan reports three errors; against a scan with five
    findings, the old `resolved` key held all five -- "fixed", when nobody
    looked. The keys now say only what compare() knows: what was reported.
    """
    result = identity.compare([INSECURE_AC_001], [])
    assert set(result) == {"unchanged", "appeared", "disappeared", "possibly_same"}
    assert "resolved" not in result and "new" not in result
