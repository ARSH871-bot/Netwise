"""Filters that are defined but never applied (access_control).

No Batfish: a fake session answers unusedStructures and fileParseStatus with
the exact table shapes real Batfish returned on tests/fixtures/vendor-asa and
vendor-nxos (28 September).
"""

from itertools import count

import pandas as pd

from analysis.checks import access_control


class _Answer:
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _Session:
    def __init__(self, unused, parse_status, raises=False):
        outer = self

        class _Q:
            def unusedStructures(self):
                if outer.raises:
                    raise RuntimeError("Batfish is not reachable")
                return _Answer(pd.DataFrame(unused, columns=["Structure_Type", "Structure_Name", "Source_Lines"]))

            def fileParseStatus(self):
                return _Answer(pd.DataFrame(parse_status, columns=["File_Name", "Status", "File_Format", "Nodes"]))

        self.raises = raises
        self.q = _Q()


NXOS_UNUSED = [("extended ipv4 access-list", "SERVER_IN", "configs/sw-nexus.cfg:[9, 10, 11]")]
NXOS_STATUS = [("configs/sw-nexus.cfg", "PASSED", "CISCO_NX", ["sw-nexus"])]
ASA_UNUSED = [("class-map", "inspection_default", "configs/fw-asa.cfg:[34, 35]"),
              ("extended ipv4 access-list", "OUTSIDE_IN", "configs/fw-asa.cfg:[27, 28]")]
ASA_STATUS = [("configs/fw-asa.cfg", "PARTIALLY_UNRECOGNIZED", "CISCO_ASA", ["fw-asa"])]


def _run(session):
    return access_control._check_unused_filters(session, count(1))


def test_an_unused_filter_in_a_fully_parsed_file_is_a_finding():
    (f,) = _run(_Session(NXOS_UNUSED, NXOS_STATUS))
    assert f["status"] == "found" and f["device"] == "sw-nexus"
    assert f["summary"] == "Filter 'SERVER_IN' is defined but never applied"
    assert f["evidence"]["source"] == "configs/sw-nexus.cfg:[9, 10, 11]"


def test_a_partly_parsed_file_gets_could_not_tell_never_a_finding():
    """Measured on vendor-asa: Batfish called OUTSIDE_IN unused because the
    line that applies it was one it did not understand."""
    results = _run(_Session(ASA_UNUSED, ASA_STATUS))
    assert [f["status"] for f in results] == ["error"]
    assert results[0]["device"] == "fw-asa"
    assert "OUTSIDE_IN" in results[0]["evidence"]["detail"]
    assert "Nothing is claimed" in results[0]["evidence"]["detail"]


def test_structures_that_are_not_filters_are_ignored():
    unused = [("class-map", "inspection_default", "configs/sw-nexus.cfg:[34, 35]"),
              ("route-map", "RM_OLD", "configs/sw-nexus.cfg:[40]")]
    assert _run(_Session(unused, NXOS_STATUS)) == []


def test_a_juniper_firewall_filter_counts_as_a_filter():
    unused = [("firewall filter", "PROTECT_RE", "configs/edge.conf:[12, 13]")]
    status = [("configs/edge.conf", "PASSED", "JUNIPER", ["edge"])]
    (f,) = _run(_Session(unused, status))
    assert f["summary"] == "Filter 'PROTECT_RE' is defined but never applied"


def test_nothing_unused_is_nothing_reported():
    assert _run(_Session([], NXOS_STATUS)) == []


def test_a_batfish_failure_is_an_error_not_silence():
    (f,) = _run(_Session([], NXOS_STATUS, raises=True))
    assert f["status"] == "error" and "never applied" in f["summary"]


def test_run_includes_the_unused_filter_analysis(monkeypatch):
    """The only other test of this wiring needs Batfish, so on CI it skips --
    and deleting the call from run() then passed every test that ran there."""
    from analysis import findings as F

    monkeypatch.setattr(access_control.snapshot, "device_names", lambda bf: {"rtr-us5"})
    for fn in ("_check_policy_statements", "_check_guarantees"):
        monkeypatch.setattr(access_control, fn, lambda bf, n, items: [])
    for fn in ("_check_dead_rules", "_check_undefined_references"):
        monkeypatch.setattr(access_control, fn, lambda bf, n: [])
    marker = F.make_finding(check="access_control", severity="medium", device="rtr-us5",
                            summary="Filter 'MARKER' is defined but never applied",
                            detail="d", source="configs/r.cfg:[1]", status="found", number=90)
    monkeypatch.setattr(access_control, "_check_unused_filters", lambda bf, n: [marker])
    assert marker in access_control.run(bf=None)
