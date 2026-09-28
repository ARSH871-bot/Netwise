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

    The three MD10_* lists were recorded the same way, re-recorded on 28
    September after #364 (all-clears now name their devices), on
    multi-device-10 with a policy naming one device: dev001, the same with
    dev001's config given the DNS permit its policy tests for, and dev002.
    They postdate PC-049 naming its devices, and access_control and routing
    reading a user policy (#353, #355) -- which is why they carry AC-002 and
    RT-00x findings that MULTIDEVICE_ONE_DEVICE_POLICY, from 15 September,
    does not. That older list is kept ON PURPOSE: its PC-049 names no
    devices, which is exactly a gap of unknown scope.

THE CONTROL
    Every "nothing was resolved" assertion here would pass for a diff that
    never resolves anything. test_a_genuine_fix_is_resolved is what stops
    that: one dead rule really removed from a real config, reported as
    exactly one resolved.
"""

from __future__ import annotations

import pytest

from analysis import coverage as C
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


MD10_DEV001_POLICY = [{'check': 'access_control',
  'device': 'rtr-us5',
  'evidence': {'detail': 'They are written about rtr-us5, which is not in this '
                         'snapshot. Nothing is claimed about them either way. '
                         'The analyses that need no policy -- dead rules and '
                         'undefined references -- still ran.',
               'source': 'affected devices: rtr-us5'},
  'id': 'AC-001',
  'severity': 'high',
  'status': 'error',
  'summary': '1 access policy statement(s) could not be checked against this '
             'config'},
 {'check': 'policy_compliance',
  'device': 'unknown',
  'evidence': {'detail': '5 rule(s) were checked, and only against '
                         'stranger-rtr-dev001. No rule says anything about '
                         'stranger-rtr-dev002, stranger-rtr-dev003, '
                         'stranger-rtr-dev004, stranger-rtr-dev005, '
                         'stranger-rtr-dev006, and 4 more. Nothing is claimed '
                         'about them either way. [Rules checked: the policy '
                         'file you supplied.]',
               'source': 'affected devices: stranger-rtr-dev002, '
                         'stranger-rtr-dev003, stranger-rtr-dev004, '
                         'stranger-rtr-dev005, stranger-rtr-dev006, '
                         'stranger-rtr-dev007, stranger-rtr-dev008, '
                         'stranger-rtr-dev009, stranger-rtr-us5'},
  'id': 'PC-049',
  'severity': 'high',
  'status': 'error',
  'summary': '9 of 10 device(s) in this config are not covered by any policy '
             'rule'},
 {'check': 'access_control',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Expected PERMIT but got DENY, decided by: deny   ip '
                         'any any',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'AC-002',
  'severity': 'medium',
  'status': 'found',
  'summary': 'DNS to the approved server is blocked, so name lookups will '
             'fail'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.11.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'permitted but policy requires it to be DENIED. '
                         'Decided by: permit tcp 10.11.10.0 0.0.0.255 host '
                         '10.20.0.5 eq 443 [Rules checked: the policy file you '
                         'supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'PC-003',
  'severity': 'medium',
  'status': 'found',
  'summary': 'Traffic with a forged source address is permitted'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.10.10.0:49152->218.8.104.58:53 UDP] is denied '
                         'but policy requires it to be PERMITTED. Decided by: '
                         'deny   ip any any [Rules checked: the policy file '
                         'you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'PC-004',
  'severity': 'medium',
  'status': 'found',
  'summary': 'DNS to the approved resolver is blocked, so name lookups fail'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip any any [Rules checked: the '
                         'policy file you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'PC-005',
  'severity': 'medium',
  'status': 'found',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.10.10.5 to '
                         '10.20.20.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev001',
               'source': 'stranger-rtr-dev001:10.20.20.5'},
  'id': 'RT-001',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The HQ network cannot reach the branch network'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.20.20.5 to '
                         '10.10.10.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev001',
               'source': 'stranger-rtr-dev001:10.10.10.5'},
  'id': 'RT-002',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The branch network cannot reach the HQ network'}]

MD10_DEV001_POLICY_DNS_FIXED = [{'check': 'access_control',
  'device': 'rtr-us5',
  'evidence': {'detail': 'They are written about rtr-us5, which is not in this '
                         'snapshot. Nothing is claimed about them either way. '
                         'The analyses that need no policy -- dead rules and '
                         'undefined references -- still ran.',
               'source': 'affected devices: rtr-us5'},
  'id': 'AC-001',
  'severity': 'high',
  'status': 'error',
  'summary': '1 access policy statement(s) could not be checked against this '
             'config'},
 {'check': 'policy_compliance',
  'device': 'unknown',
  'evidence': {'detail': '5 rule(s) were checked, and only against '
                         'stranger-rtr-dev001. No rule says anything about '
                         'stranger-rtr-dev002, stranger-rtr-dev003, '
                         'stranger-rtr-dev004, stranger-rtr-dev005, '
                         'stranger-rtr-dev006, and 4 more. Nothing is claimed '
                         'about them either way. [Rules checked: the policy '
                         'file you supplied.]',
               'source': 'affected devices: stranger-rtr-dev002, '
                         'stranger-rtr-dev003, stranger-rtr-dev004, '
                         'stranger-rtr-dev005, stranger-rtr-dev006, '
                         'stranger-rtr-dev007, stranger-rtr-dev008, '
                         'stranger-rtr-dev009, stranger-rtr-us5'},
  'id': 'PC-049',
  'severity': 'high',
  'status': 'error',
  'summary': '9 of 10 device(s) in this config are not covered by any policy '
             'rule'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.11.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'permitted but policy requires it to be DENIED. '
                         'Decided by: permit tcp 10.11.10.0 0.0.0.255 host '
                         '10.20.0.5 eq 443 [Rules checked: the policy file you '
                         'supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'PC-003',
  'severity': 'medium',
  'status': 'found',
  'summary': 'Traffic with a forged source address is permitted'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev001 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip any any [Rules checked: the '
                         'policy file you supplied.]',
               'source': 'stranger-rtr-dev001:acl_in'},
  'id': 'PC-005',
  'severity': 'medium',
  'status': 'found',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.10.10.5 to '
                         '10.20.20.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev001',
               'source': 'stranger-rtr-dev001:10.20.20.5'},
  'id': 'RT-001',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The HQ network cannot reach the branch network'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.20.20.5 to '
                         '10.10.10.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev001',
               'source': 'stranger-rtr-dev001:10.10.10.5'},
  'id': 'RT-002',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The branch network cannot reach the HQ network'},
 {'check': 'access_control',
  'device': 'stranger-rtr-dev001',
  'evidence': {'detail': '2 policy statement(s) hold, 0 guarantee(s) proven, '
                         'no dead rules, no undefined references on the '
                         'device(s) listed; other findings below are about '
                         'other devices',
               'source': 'affected devices: stranger-rtr-dev001'},
  'id': 'AC-000',
  'severity': 'low',
  'status': 'none',
  'summary': 'No issues found by access control'}]

MD10_DEV002_POLICY = [{'check': 'access_control',
  'device': 'rtr-us5',
  'evidence': {'detail': 'They are written about rtr-us5, which is not in this '
                         'snapshot. Nothing is claimed about them either way. '
                         'The analyses that need no policy -- dead rules and '
                         'undefined references -- still ran.',
               'source': 'affected devices: rtr-us5'},
  'id': 'AC-001',
  'severity': 'high',
  'status': 'error',
  'summary': '1 access policy statement(s) could not be checked against this '
             'config'},
 {'check': 'policy_compliance',
  'device': 'unknown',
  'evidence': {'detail': '5 rule(s) were checked, and only against '
                         'stranger-rtr-dev002. No rule says anything about '
                         'stranger-rtr-dev001, stranger-rtr-dev003, '
                         'stranger-rtr-dev004, stranger-rtr-dev005, '
                         'stranger-rtr-dev006, and 4 more. Nothing is claimed '
                         'about them either way. [Rules checked: the policy '
                         'file you supplied.]',
               'source': 'affected devices: stranger-rtr-dev001, '
                         'stranger-rtr-dev003, stranger-rtr-dev004, '
                         'stranger-rtr-dev005, stranger-rtr-dev006, '
                         'stranger-rtr-dev007, stranger-rtr-dev008, '
                         'stranger-rtr-dev009, stranger-rtr-us5'},
  'id': 'PC-049',
  'severity': 'high',
  'status': 'error',
  'summary': '9 of 10 device(s) in this config are not covered by any policy '
             'rule'},
 {'check': 'access_control',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Expected PERMIT but got DENY, decided by: deny   ip '
                         'any any',
               'source': 'stranger-rtr-dev002:acl_in'},
  'id': 'AC-002',
  'severity': 'medium',
  'status': 'found',
  'summary': 'DNS to the approved server is blocked, so name lookups will '
             'fail'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev002 '
                         '[10.12.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'permitted but policy requires it to be DENIED. '
                         'Decided by: permit tcp 10.12.10.0 0.0.0.255 host '
                         '10.20.0.5 eq 443 [Rules checked: the policy file you '
                         'supplied.]',
               'source': 'stranger-rtr-dev002:acl_in'},
  'id': 'PC-003',
  'severity': 'medium',
  'status': 'found',
  'summary': 'Traffic with a forged source address is permitted'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev002 '
                         '[10.10.10.0:49152->218.8.104.58:53 UDP] is denied '
                         'but policy requires it to be PERMITTED. Decided by: '
                         'deny   ip any any [Rules checked: the policy file '
                         'you supplied.]',
               'source': 'stranger-rtr-dev002:acl_in'},
  'id': 'PC-004',
  'severity': 'medium',
  'status': 'found',
  'summary': 'DNS to the approved resolver is blocked, so name lookups fail'},
 {'check': 'policy_compliance',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Flow start=stranger-rtr-dev002 '
                         '[10.10.10.0:49152->10.20.0.5:443 TCP (SYN)] is '
                         'denied but policy requires it to be PERMITTED. '
                         'Decided by: deny   ip any any [Rules checked: the '
                         'policy file you supplied.]',
               'source': 'stranger-rtr-dev002:acl_in'},
  'id': 'PC-005',
  'severity': 'medium',
  'status': 'found',
  'summary': 'HTTPS to the internal server is blocked, so the service is '
             'unreachable'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.10.10.5 to '
                         '10.20.20.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev002',
               'source': 'stranger-rtr-dev002:10.20.20.5'},
  'id': 'RT-001',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The HQ network cannot reach the branch network'},
 {'check': 'routing',
  'device': 'stranger-rtr-dev002',
  'evidence': {'detail': 'Expected REACHABLE for a flow from 10.20.20.5 to '
                         '10.10.10.5, but traceroute ended in NO_ROUTE. Path: '
                         'stranger-rtr-dev002',
               'source': 'stranger-rtr-dev002:10.10.10.5'},
  'id': 'RT-002',
  'severity': 'medium',
  'status': 'found',
  'summary': 'The branch network cannot reach the HQ network'}]



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


def test_an_unknown_scope_gap_blocks_resolution_too():
    """A gap on device "unknown" that does not say which devices it is about
    must be read as hiding every device for its check.

    Recorded 15 September, before PC-049 named its devices: its source was
    a file path, so its scope is unknown. A problem on dev001 that vanishes
    beside it is unverified, not fixed. This is still what any OTHER check's
    "unknown" gap gets today -- RT-050, "Analysis could not run".
    """
    target = next(f for f in _found(MULTIDEVICE_ONE_DEVICE_POLICY)
                  if f["check"] == "policy_compliance")
    later = [f for f in MULTIDEVICE_ONE_DEVICE_POLICY if f is not target]
    result = D.diff(D.make_scan(MULTIDEVICE_ONE_DEVICE_POLICY), D.make_scan(later))
    assert result["resolved"] == []
    assert len(result["unverified"]) == 1
    assert "not covered" in result["unverified"][0][1]


# --- A gap that names its devices hides only those (PC-049) ------------------------


def _pc049(scan):
    return next(f for f in scan if f["id"] == "PC-049")


def test_a_device_list_source_round_trips_sorted():
    source = C.device_list_source(["rtr-b", "rtr-a"])
    assert source == "affected devices: rtr-a, rtr-b"
    assert C.devices_in_source(source) == ["rtr-a", "rtr-b"]


@pytest.mark.parametrize("source", [
    "rtr-us5: acl_in",                        # access_control's own shape
    "rtr-branch, rtr-hq",                     # a clean sentinel's shape
    "analysis/checks/policy_compliance.py",   # PC-049 before this change
    "affected devices: ",                     # a list of nobody
    "",
    None,
])
def test_anything_else_is_not_a_device_list(source):
    """None means "not a list", so the gap keeps unknown scope. Reading any
    of these as a list would narrow a gap on a guess."""
    assert C.devices_in_source(source) is None


def test_pc049_lists_every_uncovered_device_in_its_source():
    """The detail stops at five names, for a reader. The source must not:
    it is what tells scan_diff a device is NOT in the gap."""
    card = _pc049(MD10_DEV001_POLICY)
    listed = C.devices_in_source(card["evidence"]["source"])
    assert listed is not None and len(listed) == 9
    assert "stranger-rtr-dev001" not in listed
    assert "and 4 more" in card["evidence"]["detail"]
    covers = [g["covers"] for g in D.make_scan(MD10_DEV001_POLICY)["coverage"]["gaps"]
              if g["check"] == "policy_compliance"]
    assert covers == [listed]


def test_a_genuine_fix_beside_an_open_pc049_is_resolved():
    """THE CASE THIS EXISTS FOR, recorded, not built. The config was fixed
    and the policy was not, while PC-049 stayed open about nine other
    devices. Before PC-049 named them, PC-004 here was unverified.

    AC-002 is the same fix. Until #364 it stayed unverified, and dev001 read
    as newly blind, because access_control said nothing at all about a clean
    device while it had an error elsewhere. It now emits an all-clear naming
    dev001, recorded above as AC-000, so both fixes resolve.
    """
    result = D.diff(D.make_scan(MD10_DEV001_POLICY, policy_hash="same"),
                    D.make_scan(MD10_DEV001_POLICY_DNS_FIXED, policy_hash="same"))
    assert sorted((f["id"], f["device"]) for f in result["resolved"]) == [
        ("AC-002", "stranger-rtr-dev001"), ("PC-004", "stranger-rtr-dev001")]
    assert result["unverified"] == []
    assert result["newly_blind"] == []


def test_a_device_that_becomes_uncovered_is_not_resolved():
    """The other direction, recorded. The policy moved from dev001 to dev002
    and NO policy_hash was stored, so the policy-change guard cannot fire.
    Every dev001 finding vanished; none of them was fixed."""
    result = D.diff(D.make_scan(MD10_DEV001_POLICY), D.make_scan(MD10_DEV002_POLICY))
    assert result["resolved"] == []
    reasons = {f["id"]: why for f, why in result["unverified"]
               if f["check"] == "policy_compliance"}
    assert sorted(reasons) == ["PC-003", "PC-004", "PC-005"]
    assert all("not covered" in why for why in reasons.values())


def test_a_listed_device_is_hidden_even_beside_a_result():
    """Constructed with the real helpers: a gap that LISTS dev001 hides it
    even though the same check has a result for dev001. PC-049 cannot
    produce that pairing -- a device it lists has no rules -- so the
    recorded tests above never reach this branch."""
    kept = next(f for f in MD10_DEV001_POLICY if f["id"] == "PC-003")
    gone = next(f for f in MD10_DEV001_POLICY if f["id"] == "PC-004")
    gap = F.error_finding(
        check="policy_compliance", device="unknown",
        summary="2 of 10 device(s) are not covered", detail="constructed",
        source=C.device_list_source(["stranger-rtr-dev001", "stranger-rtr-dev002"]),
        number=49)
    result = D.diff(D.make_scan([kept, gone]), D.make_scan([kept, gap]))
    assert result["resolved"] == []
    assert "not covered" in result["unverified"][0][1]


def test_a_gap_naming_one_device_hides_only_that_device():
    """Constructed with the real helpers. Per-item errors name the real
    device; that must not blind the same check on every other device."""
    kept = next(f for f in MD10_DEV001_POLICY if f["id"] == "PC-003")
    gone = next(f for f in MD10_DEV001_POLICY if f["id"] == "PC-004")
    elsewhere = F.error_finding(
        check="policy_compliance", device="stranger-rtr-dev002",
        summary="Could not check a rule on dev002", detail="constructed",
        source="stranger-rtr-dev002: acl_in", number=90)
    result = D.diff(D.make_scan([kept, gone]), D.make_scan([kept, elsewhere]))
    assert [f["id"] for f in result["resolved"]] == ["PC-004"]


def test_a_gap_with_no_covers_key_hides_every_device():
    """A gap stored before `covers` existed must never hide LESS than the
    rule it replaced. Built from a real scan with the key removed."""
    earlier = D.make_scan(MD10_DEV001_POLICY, policy_hash="same")
    later = D.make_scan(MD10_DEV001_POLICY_DNS_FIXED, policy_hash="same")
    for gap in later["coverage"]["gaps"]:
        del gap["covers"]
    result = D.diff(earlier, later)
    assert result["resolved"] == []


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


# --- #364: an all-clear names the devices it vouches for ---------------------------

def _f(status, device, source="x", check="access_control"):
    return {"id": "AC-001", "check": check, "severity": "high", "device": device,
            "summary": "s", "evidence": {"detail": "d", "source": source}, "status": status}


def test_a_finding_on_one_device_leaves_the_others_clean():
    results = [_f("found", "rtr-a"), _f("error", "rtr-b")]
    assert C.devices_still_clean(results, {"rtr-a", "rtr-b", "rtr-c"}) == ["rtr-c"]


def test_an_error_of_unknown_scope_vouches_for_nobody():
    """The rule #228 exists for: an error that may be about any device means
    no device can be called clean."""
    results = [_f("error", "unknown", source="analysis/checks/access_control.py")]
    assert C.devices_still_clean(results, {"rtr-a", "rtr-b"}) == []


def test_an_error_that_lists_its_devices_blocks_only_those():
    listed = C.device_list_source(["rtr-a", "rtr-z"])
    results = [_f("error", "unknown", source=listed)]
    assert C.devices_still_clean(results, {"rtr-a", "rtr-b"}) == ["rtr-b"]


def test_a_nothing_to_check_note_is_not_a_problem():
    note = _f("none", "n/a", source="the policy file you supplied")
    assert C.devices_still_clean([note], {"rtr-a"}) == ["rtr-a"]


def test_every_device_an_all_clear_lists_counts_as_checked():
    clean = _f("none", "rtr-a", source=C.device_list_source(["rtr-a", "rtr-b"]))
    checked = {r["device"] for r in C.summarise([clean])["checked"]}
    assert checked == {"rtr-a", "rtr-b"}
