"""Saved scans through the real endpoints (#223). No Batfish, no Ollama.

`analyse()` is replaced with a list the test controls, so each test can say
exactly what the earlier and later scans found. Uploading different bytes
between scans is what makes the web layer run the analysis again rather than
serve its cache, the same as for a real user.
"""

import pathlib

import pytest
from fastapi.testclient import TestClient

from analysis import findings as F
from web import main
from web.history import ScanHistory

CONFIG = next(pathlib.Path("tests/fixtures/rtr-us5-insecure/configs").glob("*.cfg")).read_bytes()


def _dead_rule():
    return F.make_finding(check="access_control", severity="low", device="rtr-us5",
                          summary="ACL rule never takes effect in acl_in",
                          detail="Unreachable line: permit udp any host 10.20.0.5 eq 53",
                          source="rtr-us5: acl_in", status="found", number=2)


def _clean():
    return F.no_issues_finding(check="access_control", device="rtr-us5",
                               summary="No issues found by access control",
                               detail="no dead rules", source="rtr-us5")


def _batfish_down():
    return F.error_finding(check="access_control",
                           summary="Analysis could not run: Batfish is not reachable",
                           detail="connection refused", source="tests")


@pytest.fixture
def world(monkeypatch, tmp_path):
    """A client, a private history file, and a switch for what analyse finds."""
    answer = {"findings": []}
    monkeypatch.setattr(main.analysis_pipeline, "analyse",
                        lambda *a, **k: [dict(f) for f in answer["findings"]])
    monkeypatch.setattr(main, "_attach_explanations", lambda results: results)
    monkeypatch.setattr(main, "_history", ScanHistory(tmp_path / "history.sqlite3"))
    main.reset_analysis_cache()
    client = TestClient(main.app)

    def scan(found, version=0):
        answer["findings"] = found
        body = CONFIG + (f"\n! revision {version}\n".encode() if version else b"")
        assert client.post("/api/upload", files={"file": ("r.cfg", body, "text/plain")}).status_code == 200
        client.get("/api/findings")

    return client, scan


def test_a_genuine_fix_is_reported_fixed(world):
    client, scan = world
    scan([_dead_rule()])
    assert client.post("/api/history", json={"name": "Head office"}).status_code == 200
    scan([_clean()], version=1)

    diff = client.get("/api/history/compare", params={"name": "Head office"}).json()
    assert [f["summary"] for f in diff["resolved"]] == ["ACL rule never takes effect in acl_in"]
    assert diff["unverified"] == [] and diff["newly_blind"] == []
    assert diff["saved"]["name"] == "Head office"


def test_batfish_down_later_resolves_nothing(world):
    """The case #223's design exists for: nobody looked, so nothing is fixed."""
    client, scan = world
    scan([_dead_rule()])
    client.post("/api/history", json={"name": "Head office"})
    scan([_batfish_down()], version=1)

    diff = client.get("/api/history/compare", params={"name": "Head office"}).json()
    assert diff["resolved"] == []
    (entry,) = diff["unverified"]
    assert "could not check" in entry["reason"]


def test_an_unreadable_record_of_skipped_rules_still_blocks_fixed(world, monkeypatch):
    """A skipped pfSense rule may be exactly why a problem vanished. If the
    record of what was skipped cannot be read, that is not the same as
    nothing having been skipped, so nothing may be called fixed."""
    client, scan = world
    scan([_dead_rule()])
    client.post("/api/history", json={"name": "Firewall"})
    monkeypatch.setattr(main, "_staged_pfsense_skips", lambda: None)
    scan([_clean()], version=1)
    diff = client.get("/api/history/compare", params={"name": "Firewall"}).json()
    assert diff["resolved"] == []
    assert "skipped pfSense rules" in diff["unverified"][0]["reason"]


def test_a_problem_that_appears_is_new(world):
    client, scan = world
    scan([_clean()])
    client.post("/api/history", json={"name": "Lab"})
    scan([_dead_rule()], version=1)
    diff = client.get("/api/history/compare", params={"name": "Lab"}).json()
    assert [f["device"] for f in diff["new"]] == ["rtr-us5"]


def test_nothing_is_saved_by_scanning(world):
    client, scan = world
    scan([_dead_rule()])
    assert client.get("/api/history").json() == {"scans": []}


def test_saving_before_any_scan_is_refused(world):
    client, _ = world
    response = client.post("/api/history", json={"name": "Head office"})
    assert response.status_code == 409 and "Scan Now" in response.json()["detail"]


def test_comparing_with_a_name_never_saved_is_refused(world):
    client, scan = world
    scan([_clean()])
    assert client.get("/api/history/compare", params={"name": "Nowhere"}).status_code == 404


def test_a_bad_name_is_refused_with_the_rule(world):
    client, scan = world
    scan([_clean()])
    response = client.post("/api/history", json={"name": "../etc"})
    assert response.status_code == 400 and "letters, digits" in response.json()["detail"]


def test_saved_scans_hold_findings_not_explanations(world, monkeypatch):
    """Explanations are attached for display. They are regenerable model
    output, not evidence, so a saved scan must not keep them."""
    client, scan = world

    def explain_in_place(results):
        for f in results:
            f["explanation"] = "model prose"
        return results
    monkeypatch.setattr(main, "_attach_explanations", explain_in_place)
    scan([_dead_rule()])
    # A second load is served from the cache, whose dicts the first load's
    # explanations were attached to in place -- the case that matters.
    client.get("/api/findings")
    client.post("/api/history", json={"name": "Head office"})
    saved = main._history.latest("Head office")["scan"]
    assert all(set(f) == set(main._F1_FIELDS) for f in saved["findings"])


def test_a_saved_sample_scan_stays_labelled_as_one(world):
    """#308's rule on a new surface: the sample network is invented, so a
    saved scan of it must say so wherever it is shown again."""
    client, _ = world
    client.post("/api/sample")
    client.get("/api/findings")
    saved = client.post("/api/history", json={"name": "Try it"}).json()
    assert saved["is_sample"] is True
    diff = client.get("/api/history/compare", params={"name": "Try it"}).json()
    assert diff["saved"]["is_sample"] is True and diff["current_is_sample"] is True


def test_delete_one_then_all(world):
    client, scan = world
    scan([_clean()])
    first = client.post("/api/history", json={"name": "A"}).json()
    client.post("/api/history", json={"name": "B"})
    assert client.delete(f"/api/history/{first['id']}").json() == {"deleted": 1}
    assert client.delete(f"/api/history/{first['id']}").status_code == 404
    assert client.delete("/api/history").json() == {"deleted": 1}
    assert client.get("/api/history").json() == {"scans": []}


def test_a_new_upload_not_yet_scanned_cannot_be_saved_or_compared(world):
    """The last scan belongs to the config it was computed from. Upload
    something else without scanning, and neither save nor compare may pair
    the old results with the new config."""
    client, scan = world
    scan([_clean()])
    client.post("/api/history", json={"name": "Lab"})
    client.post("/api/upload", files={"file": ("r.cfg", CONFIG + b"\n! edited\n", "text/plain")})
    assert client.post("/api/history", json={"name": "Lab"}).status_code == 409
    assert client.get("/api/history/compare", params={"name": "Lab"}).status_code == 409
