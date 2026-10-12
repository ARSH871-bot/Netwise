"""Routing hygiene: facts Batfish reports with no policy at all.

Duplicate addresses, forwarding loops, BGP and OSPF sessions that cannot form.
The fake answers below have the exact columns real Batfish returned on
tests/fixtures/routing-faults (29 September); the last two tests run that
fixture through real Batfish and skip without it.
"""

import pandas as pd

from analysis import coverage
from analysis.checks import routing
from conftest import needs_batfish


class _Answer:
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _Q:
    def __init__(self, frames, raises):
        self._frames, self._raises = frames, raises

    def __getattr__(self, name):
        def ask(**_kwargs):
            if name in self._raises:
                raise RuntimeError("Batfish is not reachable")
            return _Answer(self._frames.get(name, pd.DataFrame()))
        return ask


class _Session:
    def __init__(self, raises=(), **frames):
        self.q = _Q(frames, set(raises))


class _Hop:
    def __init__(self, node):
        self.node = node


class _Trace:
    def __init__(self, nodes):
        self.hops = [_Hop(n) for n in nodes]


class _Flow:
    def __init__(self, ingress, dst):
        self.ingressNode, self.dstIp = ingress, dst


def _owner(node, ip, active=True, vrf="default", iface="Loopback0"):
    return {"Node": node, "VRF": vrf, "Interface": iface, "IP": ip, "Mask": "32", "Active": active}


def _bgp(node, local_as, local_ip, remote_as, remote_ip, status):
    return {"Node": node, "VRF": "default", "Local_AS": local_as, "Local_IP": local_ip,
            "Remote_AS": remote_as, "Remote_IP": remote_ip, "Configured_Status": status}


def _ospf(iface, ip, area, remote_iface, remote_ip, remote_area, status):
    return {"Interface": iface, "VRF": "default", "IP": ip, "Area": area,
            "Remote_Interface": remote_iface, "Remote_IP": remote_ip,
            "Remote_Area": remote_area, "Session_Status": status}


def _hygiene(**kwargs):
    return routing._routing_hygiene(_Session(**kwargs))


# --- Duplicate addresses -------------------------------------------------------

def test_a_duplicate_address_is_one_finding_naming_both_routers():
    frame = pd.DataFrame([_owner("rtr-c", "10.255.0.1"), _owner("rtr-a", "10.255.0.1")])
    (f,) = _hygiene(ipOwners=frame)
    assert f["summary"] == "10.255.0.1 is assigned to 2 interfaces"
    assert coverage.devices_in_source(f["evidence"]["source"]) == ["rtr-a", "rtr-c"]


def test_an_inactive_interface_does_not_make_a_duplicate():
    frame = pd.DataFrame([_owner("rtr-c", "10.255.0.1", active=False), _owner("rtr-a", "10.255.0.1")])
    assert _hygiene(ipOwners=frame) == []


def test_the_same_address_in_different_vrfs_is_not_a_duplicate():
    frame = pd.DataFrame([_owner("rtr-c", "10.9.9.9", vrf="red"), _owner("rtr-a", "10.9.9.9", vrf="blue")])
    assert _hygiene(ipOwners=frame) == []


# --- Forwarding loops ----------------------------------------------------------

def test_a_loop_is_one_finding_with_its_path():
    frame = pd.DataFrame([{"Flow": _Flow("rtr-a", "192.0.2.0"),
                           "Traces": [_Trace(["rtr-a", "rtr-b", "rtr-a"])], "TraceCount": 1}])
    (f,) = _hygiene(detectLoops=frame)
    assert "rtr-a -> rtr-b -> rtr-a" in f["evidence"]["detail"]
    assert coverage.devices_in_source(f["evidence"]["source"]) == ["rtr-a", "rtr-b"]


def test_the_same_loop_seen_from_both_routers_is_reported_once():
    frame = pd.DataFrame([
        {"Flow": _Flow("rtr-a", "192.0.2.0"), "Traces": [_Trace(["rtr-a", "rtr-b", "rtr-a"])], "TraceCount": 1},
        {"Flow": _Flow("rtr-b", "192.0.2.0"), "Traces": [_Trace(["rtr-b", "rtr-a", "rtr-b"])], "TraceCount": 1},
    ])
    assert len(_hygiene(detectLoops=frame)) == 1


# --- BGP -----------------------------------------------------------------------

def test_a_mismatched_bgp_pair_is_one_finding_quoting_both_sides():
    frame = pd.DataFrame([
        _bgp("rtr-a", 65001, "10.0.12.1", 65002, "10.0.12.2", "HALF_OPEN"),
        _bgp("rtr-b", 65003, "10.0.12.2", 65001, "10.0.12.1", "HALF_OPEN"),
    ])
    (f,) = _hygiene(bgpSessionCompatibility=frame)
    assert f["summary"] == "BGP session between rtr-a and rtr-b cannot come up"
    assert "expects AS 65002" in f["evidence"]["detail"] and "(AS 65003" in f["evidence"]["detail"]


def test_a_peer_outside_the_upload_is_not_a_fault():
    """UNKNOWN_REMOTE: typically an ISP. Could not see the other side is not
    the same as the two sides disagreeing."""
    frame = pd.DataFrame([_bgp("rtr-a", 65001, "203.0.113.1", 64500, "203.0.113.2", "UNKNOWN_REMOTE"),
                          _bgp("rtr-a", 65001, "10.0.12.1", 65002, "10.0.12.2", "UNIQUE_MATCH")])
    assert _hygiene(bgpSessionCompatibility=frame) == []


# --- OSPF ----------------------------------------------------------------------

def test_an_ospf_area_mismatch_is_one_finding():
    frame = pd.DataFrame([
        _ospf("rtr-a[Gi0/1]", "10.0.13.1", 0, "rtr-c[Gi0/0]", "10.0.13.2", 1, "AREA_MISMATCH"),
        _ospf("rtr-c[Gi0/0]", "10.0.13.2", 1, "rtr-a[Gi0/1]", "10.0.13.1", 0, "AREA_MISMATCH"),
    ])
    (f,) = _hygiene(ospfSessionCompatibility=frame)
    assert f["summary"] == "OSPF between rtr-a and rtr-c cannot form: area mismatch"


def test_an_established_ospf_session_is_not_reported():
    frame = pd.DataFrame([_ospf("rtr-a[Gi0/1]", "10.0.13.1", 0, "rtr-c[Gi0/0]", "10.0.13.2", 0, "ESTABLISHED")])
    assert _hygiene(ospfSessionCompatibility=frame) == []


# --- Failure, numbering, and the all-clear ---------------------------------------

def test_a_question_that_fails_is_an_error_not_silence():
    results = _hygiene(raises={"detectLoops"})
    (f,) = [r for r in results if r["status"] == "error"]
    assert f["summary"] == "Could not check for forwarding loops"


def test_hygiene_numbers_never_meet_route_assertion_numbers():
    """Checked against the numbers themselves, not against the constant: a
    test reading HYGIENE_FIRST_NUMBER passed when it was changed to 1, which
    is route assertion RT-001's own id."""
    frame = pd.DataFrame([_owner("rtr-c", "10.255.0.1"), _owner("rtr-a", "10.255.0.1")])
    (f,) = _hygiene(ipOwners=frame)
    taken = ({r["number"] for r in routing.ROUTES}
             | {0, routing.SKIPPED_NUMBER, routing.UNREAD_POLICY_NUMBER})
    assert int(f["id"].split("-")[1]) not in taken
    assert f["id"] == "RT-100"


def test_a_fault_between_two_routers_keeps_both_off_the_all_clear():
    """devices_still_clean: a finding naming rtr-a but listing rtr-c too must
    exclude both, or routing could vouch for rtr-c beside its own duplicate."""
    frame = pd.DataFrame([_owner("rtr-c", "10.255.0.1"), _owner("rtr-a", "10.255.0.1")])
    results = _hygiene(ipOwners=frame)
    assert coverage.devices_still_clean(results, {"rtr-a", "rtr-c", "rtr-z"}) == ["rtr-z"]


def test_hygiene_runs_on_every_path_through_run(monkeypatch):
    """Two early returns in run() would otherwise skip it: an empty routing
    section, and a snapshot whose devices could not be read."""
    marker = routing.findings.make_finding(
        check="routing", severity="medium", device="rtr-x", summary="MARKER",
        detail="d", source="s", status="found", number=150)
    monkeypatch.setattr(routing, "_routing_hygiene", lambda bf: [marker])

    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: None)
    assert marker in routing.run(bf=None), "devices unknown"

    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-x"})
    assert marker in routing.run(bf=None), "no assertion applies"

    monkeypatch.setattr(routing, "routes_in_use", lambda: ([], "your policy", True))
    assert marker in routing.run(bf=None), "empty routing section"


class _HoldingTraceFrame:
    empty = False
    iloc = [{"Traces": []}]


def test_a_hygiene_problem_keeps_its_router_off_routings_all_clear(monkeypatch):
    """Ordering: hygiene must join the results BEFORE the all-clear is
    computed. After it, routing would vouch for rtr-a as clean beside its own
    duplicate-address finding."""
    route = dict(routing.ROUTES[0], node="rtr-a")
    monkeypatch.setattr(routing, "routes_in_use", lambda: ([route], "test", True))
    monkeypatch.setattr(routing.snapshot, "device_names", lambda bf: {"rtr-a"})
    monkeypatch.setattr(routing, "_evaluate", lambda expected, traces: None)
    problem = routing.findings.make_finding(
        check="routing", severity="medium", device="rtr-a",
        summary="10.255.0.1 is assigned to 2 interfaces", detail="d",
        source=coverage.device_list_source(["rtr-a", "rtr-c"]), status="found", number=100)
    monkeypatch.setattr(routing, "_routing_hygiene", lambda bf: [problem])

    class Session:
        class q:  # noqa: N801
            @staticmethod
            def traceroute(**_kwargs):
                return _Answer(_HoldingTraceFrame())

    results = routing.run(Session())
    assert problem in results
    assert not [f for f in results if f["status"] == "none" and f["device"] != "n/a"], (
        "routing vouched for rtr-a beside a problem on rtr-a")


# --- The real fixture, real Batfish -----------------------------------------------

@needs_batfish
def test_routing_faults_reports_each_planted_fault_once():
    from analysis import pipeline

    results = pipeline.analyse("tests/fixtures/routing-faults", snapshot_name="routing_faults")
    found = sorted(f["summary"] for f in results if f["check"] == "routing" and f["status"] == "found")
    assert found == [
        "10.255.0.1 is assigned to 2 interfaces",
        "BGP session between rtr-a and rtr-b cannot come up",
        "OSPF between rtr-a and rtr-c cannot form: area mismatch",
        "Traffic to 192.0.2.0 loops between routers",
    ]


@needs_batfish
def test_a_clean_single_router_gets_no_hygiene_findings():
    """The control: a fixture with none of these faults must stay quiet."""
    from analysis import pipeline

    results = pipeline.analyse("tests/fixtures/rtr-us5-secure", snapshot_name="rtr_us5_secure_hyg")
    assert not [f for f in results if f["check"] == "routing" and f["id"] >= "RT-100"]
