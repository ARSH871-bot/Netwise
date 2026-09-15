"""What changed since the last scan? (US-22, #315)

THE SCANS BELOW ARE REAL
    Each list was produced by `analysis.pipeline.analyse()` against real
    Batfish on 15 September 2026 and pasted in by a script, so no test can
    pass on a fixture written to suit it. The suite needs neither Batfish
    nor Ollama, hence copies.

    One exception, stated: INSECURE_BATFISH_UNREACHABLE comes from
    analyse()'s own unreachable-Batfish path with the connection refused
    in-process, rather than from stopping the container a third time. The
    code path and the check/device/status fields the diff reads are the
    same; only the error text differs. The run against a genuinely stopped
    container is recorded on the pull request.

THE CONTROL
    Every "nothing was resolved" assertion here would pass for a diff that
    never resolves anything. test_a_genuine_fix_is_resolved is what stops
    that: one dead rule really removed from a real config, reported as
    exactly one resolved.
"""

from __future__ import annotations

import pytest

from analysis import findings as F
from analysis import scan_diff as D

# --- Real scans, verbatim --------------------------------------------------------
INSECURE_UP = [{'id': 'RT-050',
  'check': 'routing',
  'severity': 'high',
  'device': 'unknown',
  'summary': '2 route assertion(s) could not be checked against this config',
  'evidence': {'detail': 'They are written about rtr-branch, rtr-hq, which '
                         'are not in this snapshot. Nothing is claimed about '
                         'them either way.',
               'source': 'analysis/checks/routing.py'},
  'status': 'error'},
 {'id': 'AC-001',
  'check': 'access_control',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': 'Unencrypted web traffic reaches the internal server',
  'evidence': {'detail': 'Expected DENY but got PERMIT, decided by: permit '
                         'ip any any',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'AC-002',
  'check': 'access_control',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': 'Unencrypted web traffic is allowed out of the internal subnet',
  'evidence': {'detail': 'Example permitted flow: start=rtr-us5 '
                         '[10.10.10.0:49152->8.8.8.8:80 TCP (SYN)], allowed '
                         'by: permit ip any any',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-001',
  'check': 'policy_compliance',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': 'The internal network can reach servers it should not',
  'evidence': {'detail': 'Flow start=rtr-us5 [10.10.10.0:49152->8.8.8.8:80 '
                         'TCP (SYN)] is permitted but policy requires it to '
                         'be DENIED. Decided by: permit ip any any [Rules '
                         "checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-002',
  'check': 'policy_compliance',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': 'The internal server accepts traffic other than HTTPS',
  'evidence': {'detail': 'Flow start=rtr-us5 '
                         '[10.10.10.0:49152->10.20.0.5:33434 UDP] is '
                         'permitted but policy requires it to be DENIED. '
                         'Decided by: permit ip any any (2 example flows '
                         "matched) [Rules checked: Netwise's built-in "
                         'example policy '
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-003',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'Traffic with a forged source address is permitted',
  'evidence': {'detail': 'Flow start=rtr-us5 [10.0.0.0:49152->8.8.8.8:80 TCP '
                         '(SYN)] is permitted but policy requires it to be '
                         'DENIED. Decided by: permit ip any any [Rules '
                         "checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'}]

MESSY_UP = [{'id': 'RT-050',
  'check': 'routing',
  'severity': 'high',
  'device': 'unknown',
  'summary': '2 route assertion(s) could not be checked against this config',
  'evidence': {'detail': 'They are written about rtr-branch, rtr-hq, which '
                         'are not in this snapshot. Nothing is claimed about '
                         'them either way.',
               'source': 'analysis/checks/routing.py'},
  'status': 'error'},
 {'id': 'AC-004',
  'check': 'access_control',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': "Config refers to ipv4 acl 'acl_guest_in' which is not defined",
  'evidence': {'detail': 'Referenced as: interface incoming ip access-list. '
                         "The structure 'acl_guest_in' is never defined in "
                         'this snapshot.',
               'source': 'configs/rtr-us5.cfg:[37]'},
  'status': 'found'},
 {'id': 'AC-001',
  'check': 'access_control',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'DNS to the approved server is blocked, so name lookups will '
             'fail',
  'evidence': {'detail': 'Expected PERMIT but got DENY, decided by: deny   '
                         'ip 10.10.10.0 0.0.0.255 any',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-004',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'DNS to the approved resolver is blocked, so name lookups fail',
  'evidence': {'detail': 'Flow start=rtr-us5 '
                         '[10.10.10.0:49152->218.8.104.58:53 UDP] is denied '
                         'but policy requires it to be PERMITTED. Decided '
                         'by: deny   ip 10.10.10.0 0.0.0.255 any [Rules '
                         "checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-005',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable',
  'evidence': {'detail': 'Flow start=rtr-us5 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip 10.10.10.0 0.0.0.255 any '
                         "[Rules checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'AC-002',
  'check': 'access_control',
  'severity': 'low',
  'device': 'rtr-us5',
  'summary': 'ACL rule never takes effect in acl_in',
  'evidence': {'detail': 'Unreachable line: permit udp 10.10.10.0 0.0.0.255 '
                         'host 218.8.104.58 eq domain (action PERMIT). '
                         'Blocked by: deny   ip 10.10.10.0 0.0.0.255 any. '
                         'Reason: BLOCKING_LINES',
               'source': 'rtr-us5: acl_in'},
  'status': 'found'},
 {'id': 'AC-003',
  'check': 'access_control',
  'severity': 'low',
  'device': 'rtr-us5',
  'summary': 'ACL rule never takes effect in acl_in',
  'evidence': {'detail': 'Unreachable line: permit tcp 10.10.10.0 0.0.0.255 '
                         'host 10.20.0.5 eq 443 (action PERMIT). Blocked by: '
                         'deny   ip 10.10.10.0 0.0.0.255 any. Reason: '
                         'BLOCKING_LINES',
               'source': 'rtr-us5: acl_in'},
  'status': 'found'}]

MESSY_ONE_DEAD_RULE_REMOVED = [{'id': 'RT-050',
  'check': 'routing',
  'severity': 'high',
  'device': 'unknown',
  'summary': '2 route assertion(s) could not be checked against this config',
  'evidence': {'detail': 'They are written about rtr-branch, rtr-hq, which '
                         'are not in this snapshot. Nothing is claimed about '
                         'them either way.',
               'source': 'analysis/checks/routing.py'},
  'status': 'error'},
 {'id': 'AC-003',
  'check': 'access_control',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': "Config refers to ipv4 acl 'acl_guest_in' which is not defined",
  'evidence': {'detail': 'Referenced as: interface incoming ip access-list. '
                         "The structure 'acl_guest_in' is never defined in "
                         'this snapshot.',
               'source': 'configs/rtr-us5.cfg:[37]'},
  'status': 'found'},
 {'id': 'AC-001',
  'check': 'access_control',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'DNS to the approved server is blocked, so name lookups will '
             'fail',
  'evidence': {'detail': 'Expected PERMIT but got DENY, decided by: deny   '
                         'ip 10.10.10.0 0.0.0.255 any',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-004',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'DNS to the approved resolver is blocked, so name lookups fail',
  'evidence': {'detail': 'Flow start=rtr-us5 '
                         '[10.10.10.0:49152->218.8.104.58:53 UDP] is denied '
                         'but policy requires it to be PERMITTED. Decided '
                         'by: deny   ip 10.10.10.0 0.0.0.255 any [Rules '
                         "checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'PC-005',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'rtr-us5',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable',
  'evidence': {'detail': 'Flow start=rtr-us5 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip 10.10.10.0 0.0.0.255 any '
                         "[Rules checked: Netwise's built-in example policy "
                         '(analysis/checks/policy_compliance.py) -- no '
                         'policy file was supplied.]',
               'source': 'rtr-us5:acl_in'},
  'status': 'found'},
 {'id': 'AC-002',
  'check': 'access_control',
  'severity': 'low',
  'device': 'rtr-us5',
  'summary': 'ACL rule never takes effect in acl_in',
  'evidence': {'detail': 'Unreachable line: permit tcp 10.10.10.0 0.0.0.255 '
                         'host 10.20.0.5 eq 443 (action PERMIT). Blocked by: '
                         'deny   ip 10.10.10.0 0.0.0.255 any. Reason: '
                         'BLOCKING_LINES',
               'source': 'rtr-us5: acl_in'},
  'status': 'found'}]

MULTIDEVICE_ONE_DEVICE_POLICY = [{'id': 'AC-001',
  'check': 'access_control',
  'severity': 'high',
  'device': 'rtr-us5',
  'summary': '3 access policy statement(s) could not be checked against this '
             'config',
  'evidence': {'detail': 'They are written about rtr-us5, which is not in '
                         'this snapshot. Nothing is claimed about them '
                         'either way. The analyses that need no policy -- '
                         'dead rules and undefined references -- still ran.',
               'source': 'analysis/checks/access_control.py'},
  'status': 'error'},
 {'id': 'PC-049',
  'check': 'policy_compliance',
  'severity': 'high',
  'device': 'unknown',
  'summary': '9 of 10 device(s) in this config are not covered by any policy '
             'rule',
  'evidence': {'detail': '5 rule(s) were checked, and only against '
                         'stranger-rtr-dev001. No rule says anything about '
                         'stranger-rtr-dev002, stranger-rtr-dev003, '
                         'stranger-rtr-dev004, stranger-rtr-dev005, '
                         'stranger-rtr-dev006, and 4 more. Nothing is '
                         'claimed about them either way. [Rules checked: the '
                         'policy file you supplied.]',
               'source': 'analysis/checks/policy_compliance.py'},
  'status': 'error'},
 {'id': 'RT-050',
  'check': 'routing',
  'severity': 'high',
  'device': 'unknown',
  'summary': '2 route assertion(s) could not be checked against this config',
  'evidence': {'detail': 'They are written about rtr-branch, rtr-hq, which '
                         'are not in this snapshot. Nothing is claimed about '
                         'them either way.',
               'source': 'analysis/checks/routing.py'},
  'status': 'error'},
 {'id': 'PC-003',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'stranger-rtr-dev001',
  'summary': 'Traffic with a forged source address is permitted',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.11.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'permitted but policy requires it to be DENIED. '
                         'Decided by: permit tcp 10.11.10.0 0.0.0.255 host '
                         '10.20.0.5 eq 443 [Rules checked: the policy file '
                         'you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'status': 'found'},
 {'id': 'PC-004',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'stranger-rtr-dev001',
  'summary': 'DNS to the approved resolver is blocked, so name lookups fail',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.10.10.0:49152->218.8.104.58:53 UDP] is denied '
                         'but policy requires it to be PERMITTED. Decided '
                         'by: deny   ip any any [Rules checked: the policy '
                         'file you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'status': 'found'},
 {'id': 'PC-005',
  'check': 'policy_compliance',
  'severity': 'medium',
  'device': 'stranger-rtr-dev001',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip any any [Rules checked: the '
                         'policy file you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'status': 'found'}]

INSECURE_BATFISH_UNREACHABLE = [{'id': 'AC-000',
  'check': 'access_control',
  'severity': 'high',
  'device': 'unknown',
  'summary': 'Analysis could not run: Batfish is not reachable',
  'evidence': {'detail': 'Batfish is not answering at None. Start it with: '
                         'docker start batfish   -- if that reports it '
                         'cannot reach the Docker daemon, start Docker '
                         'Desktop first, then run it again. (First time '
                         'only: docker run --name batfish -d -p 9996:9996 -p '
                         '9997:9997 batfish/allinone.) Underlying error: '
                         'ConnectionError: Batfish is not reachable',
               'source': 'tests\\fixtures\\rtr-us5-insecure'},
  'status': 'error'},
 {'id': 'PC-000',
  'check': 'policy_compliance',
  'severity': 'high',
  'device': 'unknown',
  'summary': 'Analysis could not run: Batfish is not reachable',
  'evidence': {'detail': 'Batfish is not answering at None. Start it with: '
                         'docker start batfish   -- if that reports it '
                         'cannot reach the Docker daemon, start Docker '
                         'Desktop first, then run it again. (First time '
                         'only: docker run --name batfish -d -p 9996:9996 -p '
                         '9997:9997 batfish/allinone.) Underlying error: '
                         'ConnectionError: Batfish is not reachable',
               'source': 'tests\\fixtures\\rtr-us5-insecure'},
  'status': 'error'},
 {'id': 'RT-000',
  'check': 'routing',
  'severity': 'high',
  'device': 'unknown',
  'summary': 'Analysis could not run: Batfish is not reachable',
  'evidence': {'detail': 'Batfish is not answering at None. Start it with: '
                         'docker start batfish   -- if that reports it '
                         'cannot reach the Docker daemon, start Docker '
                         'Desktop first, then run it again. (First time '
                         'only: docker run --name batfish -d -p 9996:9996 -p '
                         '9997:9997 batfish/allinone.) Underlying error: '
                         'ConnectionError: Batfish is not reachable',
               'source': 'tests\\fixtures\\rtr-us5-insecure'},
  'status': 'error'}]



def _found(scan):
    return [f for f in scan if f["status"] == "found"]


def _pairs(rows):
    return [(c, d) for c, d, *_ in rows]


# --- The one rule ------------------------------------------------------------------


def test_batfish_down_resolves_nothing():
    """The case the rule exists for: five findings, then nobody could look."""
    result = D.diff(D.make_scan(INSECURE_UP), D.make_scan(INSECURE_BATFISH_UNREACHABLE))
    assert result["resolved"] == []
    assert len(result["unverified"]) == 5
    assert all("could not check" in reason for _, reason in result["unverified"])


def test_batfish_down_names_the_checks_that_went_dark():
    result = D.diff(D.make_scan(INSECURE_UP), D.make_scan(INSECURE_BATFISH_UNREACHABLE))
    assert _pairs(result["newly_blind"]) == [
        ("access_control", "rtr-us5"), ("policy_compliance", "rtr-us5")]


def test_a_genuine_fix_is_resolved():
    """THE CONTROL. Without this every zero above proves nothing."""
    result = D.diff(D.make_scan(MESSY_UP), D.make_scan(MESSY_ONE_DEAD_RULE_REMOVED))
    assert len(result["resolved"]) == 1
    assert "eq domain" in result["resolved"][0]["evidence"]["detail"]
    assert result["unverified"] == [] and result["newly_blind"] == []
    assert len(result["unchanged"]) == 5


# --- The mirror ------------------------------------------------------------------


def test_recovery_introduces_nothing():
    """Batfish back up: the same five were there all along."""
    result = D.diff(D.make_scan(INSECURE_BATFISH_UNREACHABLE), D.make_scan(INSECURE_UP))
    assert result["new"] == []
    assert len(result["newly_visible"]) == 5
    assert result["newly_checked"] == [
        ("access_control", "rtr-us5"), ("policy_compliance", "rtr-us5")]


def test_a_finding_is_new_only_where_the_check_ran_before():
    earlier = D.make_scan([f for f in MESSY_UP if f["summary"] !=
                           "Config refers to ipv4 acl 'acl_guest_in' which is not defined"])
    result = D.diff(earlier, D.make_scan(MESSY_UP))
    assert len(result["new"]) == 1
    assert result["newly_visible"] == []


# --- Errors and sentinels are coverage, never problems ---------------------------


def test_error_findings_are_never_problems():
    """Found against a genuinely stopped Batfish: the first version filed the
    three "could not run" errors as newly visible problems, and their
    disappearance on recovery as fixes."""
    down = D.diff(D.make_scan(INSECURE_UP), D.make_scan(INSECURE_BATFISH_UNREACHABLE))
    up = D.diff(D.make_scan(INSECURE_BATFISH_UNREACHABLE), D.make_scan(INSECURE_UP))
    for bucket in ("resolved", "new", "unchanged"):
        assert all(f["status"] == "found" for f in down[bucket] + up[bucket])
    for bucket in ("unverified", "newly_visible"):
        assert all(f["status"] == "found" for f, _ in down[bucket] + up[bucket])


def test_a_none_sentinel_is_never_a_problem():
    clean = F.no_issues_finding(check="access_control", device="rtr-us5",
                                summary="No issues found by access control",
                                detail="All statements held.", source="x")
    result = D.diff(D.make_scan([clean]), D.make_scan([]))
    assert result["resolved"] == [] and result["unverified"] == []


# --- A gap beats a result for the same check -------------------------------------


def test_a_same_device_gap_beats_a_result_for_that_check():
    """Known from the code, not a fixture: per-item errors use device=node.

    Later, access_control still reports a dead rule on rtr-us5 -- so
    (access_control, rtr-us5) is "checked" -- but its policy statement could
    not run. The statement's finding vanishing is not a fix.
    """
    dns = next(f for f in MESSY_UP if f["summary"].startswith("DNS to the approved server"))
    dead_rule = next(f for f in MESSY_UP if "eq 443" in f["evidence"]["detail"])
    statement_failed = F.error_finding(
        check="access_control", device="rtr-us5",
        summary="Could not check: dns lookups to the approved dns server must be allowed",
        detail="Analysis could not run", source="rtr-us5:acl_in", number=90)
    result = D.diff(D.make_scan([dns, dead_rule]), D.make_scan([dead_rule, statement_failed]))
    assert result["resolved"] == []
    (finding, reason), = result["unverified"]
    assert finding is not None and "could not check" in reason


def test_an_unknown_device_gap_blocks_resolution_too():
    """Measured: a policy naming one device of multi-device-10's ten leaves a
    standing policy_compliance gap, device "unknown", beside real results on
    that one device. A problem there that vanishes is unverified, not fixed."""
    target = next(f for f in _found(MULTIDEVICE_ONE_DEVICE_POLICY)
                  if f["check"] == "policy_compliance")
    later = [f for f in MULTIDEVICE_ONE_DEVICE_POLICY if f is not target]
    result = D.diff(D.make_scan(MULTIDEVICE_ONE_DEVICE_POLICY), D.make_scan(later))
    assert result["resolved"] == []
    assert len(result["unverified"]) == 1
    assert "not covered" in result["unverified"][0][1]


# --- What else stops a claim ------------------------------------------------------


def test_a_policy_change_attributes_everything_to_the_policy():
    earlier = D.make_scan(MESSY_UP, policy_hash="a")
    later = D.make_scan(MESSY_ONE_DEAD_RULE_REMOVED, policy_hash="b")
    result = D.diff(earlier, later)
    assert result["resolved"] == [] and result["new"] == []
    assert all("policy changed" in r for _, r in result["unverified"])
    assert any("policy changed" in c for c in result["caveats"])


def test_an_absent_device_is_not_fixed_and_not_blind():
    earlier = D.make_scan(MESSY_UP, devices=["rtr-us5"])
    later = D.make_scan([], devices=[])
    result = D.diff(earlier, later)
    assert result["resolved"] == []
    assert all("not in the later snapshot" in r for _, r in result["unverified"])
    assert result["newly_blind"] == []


def test_conversion_skips_block_resolution():
    earlier = D.make_scan(MESSY_UP)
    later = D.make_scan(MESSY_ONE_DEAD_RULE_REMOVED, conversion_skips=["rule on wan"])
    result = D.diff(earlier, later)
    assert result["resolved"] == []
    assert "skipped pfSense rules" in result["unverified"][0][1]


def test_caveats_report_without_reclassifying():
    earlier = D.make_scan(MESSY_UP, netwise_build="aaa", config_fingerprint="same")
    later = D.make_scan(MESSY_ONE_DEAD_RULE_REMOVED, netwise_build="bbb",
                        config_fingerprint="same")
    result = D.diff(earlier, later)
    assert len(result["resolved"]) == 1
    assert any("Netwise itself changed" in c for c in result["caveats"])
    assert any("byte-identical" in c for c in result["caveats"])


# --- The row ----------------------------------------------------------------------


def test_make_scan_never_trusts_a_supplied_coverage_claim():
    lying = {"complete": True, "statement": "all good", "checked": [], "gaps": []}
    scan = D.make_scan(INSECURE_BATFISH_UNREACHABLE, coverage=lying)
    assert scan["coverage"]["complete"] is False
    assert len(scan["coverage"]["gaps"]) == 3


def test_a_scan_without_coverage_is_refused():
    with pytest.raises(ValueError):
        D.diff({"findings": []}, D.make_scan([]))
