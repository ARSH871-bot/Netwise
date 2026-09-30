"""web/history.py -- saved scans (#223). No Batfish, no web server.

Each test gets its own SQLite file in pytest's tmp_path.
"""

import pytest

from analysis import scan_diff
from web.history import HistoryError, ScanHistory, valid_name


def _finding(status="found", device="rtr-us5", detail="permit ip any any"):
    return {"id": "AC-001", "check": "access_control", "severity": "high",
            "device": device, "summary": "s",
            "evidence": {"detail": detail, "source": "rtr-us5: acl_in"}, "status": status}


@pytest.fixture
def store(tmp_path):
    return ScanHistory(tmp_path / "history.sqlite3")


def test_a_saved_scan_comes_back_exactly(store):
    scan = scan_diff.make_scan([_finding()], devices=["rtr-us5"], policy_hash="p")
    saved = store.save("office", scan)
    latest = store.latest("office")
    assert latest["id"] == saved["id"] and latest["scan"] == scan
    assert saved["counts"] == {"found": 1, "none": 0, "error": 0}


def test_latest_is_the_most_recent_of_that_name_only(store):
    first = store.save("office", scan_diff.make_scan([_finding()]))
    store.save("lab", scan_diff.make_scan([]))
    second = store.save("office", scan_diff.make_scan([]))
    assert store.latest("office")["id"] == second["id"] != first["id"]
    assert store.latest("nowhere") is None


def test_the_list_is_newest_first_and_carries_no_findings(store):
    store.save("office", scan_diff.make_scan([_finding()]))
    store.save("lab", scan_diff.make_scan([]))
    listed = store.list()
    assert [row["name"] for row in listed] == ["lab", "office"]
    assert all("scan" not in row and "findings" not in row for row in listed)


@pytest.mark.parametrize("bad", ["", "   ", "-leading", "a" * 65, "office/../etc",
                                 "<script>", "name\nwith newline"])
def test_a_name_that_is_not_a_plain_label_is_refused(store, bad):
    with pytest.raises(HistoryError):
        store.save(bad, scan_diff.make_scan([]))


def test_a_name_is_trimmed_not_rejected_for_surrounding_spaces():
    assert valid_name("  Head Office 2  ") == "Head Office 2"


def test_delete_removes_one_and_reports_a_miss(store):
    kept = store.save("office", scan_diff.make_scan([]))
    gone = store.save("lab", scan_diff.make_scan([]))
    assert store.delete(gone["id"]) is True
    assert store.delete(gone["id"]) is False
    assert [row["id"] for row in store.list()] == [kept["id"]]


def test_delete_all_empties_it(store):
    store.save("office", scan_diff.make_scan([]))
    store.save("lab", scan_diff.make_scan([]))
    assert store.delete_all() == 2 and store.list() == []


def test_a_deleted_scan_is_gone_from_the_file_itself(store):
    """#344's "a delete that genuinely removes". A plain SQLite DELETE leaves
    the row's bytes in the file until the page is reused; a saved scan
    quotes config lines, so that would be deletion in name only."""
    marker = "permit tcp host 198.51.100.77 eq 31337"
    saved = store.save("office", scan_diff.make_scan([_finding(detail=marker)]))
    assert marker.encode() in store.path.read_bytes()      # control: it was written
    store.delete(saved["id"])
    assert marker.encode() not in store.path.read_bytes()
