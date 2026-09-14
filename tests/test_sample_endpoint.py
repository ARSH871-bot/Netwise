"""POST /api/sample stages the bundled sample, and says that it did (#347).

The endpoint is the easy half. The half worth testing is the LABEL: a session
that loaded the sample must be recognisable as such everywhere a result is
rendered, including in a file that outlives the browser tab.

Why that matters more than it sounds. The findings a sample scan produces are
genuinely trustworthy -- real Batfish output about a real config file. That is
exactly what makes an unlabelled sample report dangerous: there is nothing
wrong with the analysis, only with the assumption that the network was
somebody's. A report downloaded on Monday and opened on Friday has no banner.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web import main


@pytest.fixture
def analysed(monkeypatch):
    """Analyse without going near Batfish, following test_session_isolation.

    NOT an optimisation. Requirement N-6 says the suite must run without the
    analysis engine, and these tests are about the sample LABEL rather than
    about analysis -- the finding content is irrelevant to every assertion
    below.

    The first draft of this file called the real pipeline. It passed, and
    took 57 minutes for nine tests, because three of them trigger a full
    Batfish scan each. A suite nobody can afford to run is a suite that stops
    being run.

    Reads the staged config at call time rather than returning a constant, so
    a test that staged the wrong file still fails.
    """

    def fake_analyse(snapshot_dir, snapshot_name=None, **kwargs):
        configs = Path(snapshot_dir) / "configs"
        staged = sorted(configs.glob("*"))
        text = staged[0].read_text(encoding="utf-8") if staged else "<none>"
        host = next((ln.split()[1] for ln in text.splitlines()
                     if ln.startswith("hostname ")), "<unknown>")
        return [{
            "id": "AC-001", "check": "access_control", "severity": "high",
            "device": host, "summary": f"stub finding for {host}",
            "evidence": {"detail": "stub", "source": "stub"}, "status": "found",
        }]

    monkeypatch.setattr(main.analysis_pipeline, "analyse", fake_analyse)
    monkeypatch.setattr(main, "_attach_explanations", lambda results: results)
    main.reset_analysis_cache()
    return fake_analyse


@pytest.fixture
def client():
    """One client is one session, matching the per-session storage model."""
    return TestClient(main.app)


# --- staging ------------------------------------------------------------------


def test_nothing_is_staged_before_the_sample_is_asked_for(client):
    """The empty first load #352 established. The sample must be a CHOICE."""
    assert client.get("/api/findings").json() == []


def test_loading_the_sample_stages_it(client):
    response = client.post("/api/sample")

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["is_sample"] is True


def test_the_message_says_invented_data_and_real_scan(client):
    """Both halves, because either alone is misleading.

    "Invented" on its own undersells it -- a visitor could reasonably assume
    the findings are canned too, which is the opposite of the truth and makes
    the demonstration worthless. "Real scan" on its own is the #352 problem.
    """
    message = client.post("/api/sample").json()["message"].lower()
    assert "invented" in message
    assert "real" in message


def test_it_stages_but_does_not_scan(client):
    """Same contract as /api/upload since #82: staging and analysing are two
    deliberate acts. The sample gets no shortcut the user's own file lacks."""
    client.post("/api/sample")
    # The findings endpoint is what runs the analysis; the POST above must not
    # have done it. Observable as the staged file existing before any scan.
    assert (main.configs_dir() / "device.cfg").is_file()


# --- the label ----------------------------------------------------------------


def test_the_session_is_marked_as_sample(client):
    client.post("/api/sample")
    assert main.sample_marker_path().is_file()


def test_the_downloaded_report_says_it_is_a_sample(client, analysed):
    """THE ASSERTION THIS FILE EXISTS FOR.

    A report outlives the tab. Without this, a saved sample report is
    indistinguishable from a real one -- and every finding in it is genuine,
    so nothing about reading it would raise a doubt.
    """
    client.post("/api/sample")
    client.get("/api/findings")

    html = client.get("/api/report?format=html").text

    assert "SAMPLE NETWORK" in html
    assert "invented demonstration data" in html


def test_a_real_upload_clears_the_sample_label(client):
    """A mislabel in the SAFE-LOOKING direction is still a mislabel.

    Leaving the marker after a real upload would print "this is sample data"
    over somebody's actual network, inviting them to disregard true findings.
    Same reasoning as clearing a stale policy or business context on upload.
    """
    client.post("/api/sample")
    assert main.sample_marker_path().is_file()

    client.post(
        "/api/upload",
        files={"file": ("mine.cfg", b"!\nhostname rtr-mine\n!\n", "text/plain")},
    )

    assert not main.sample_marker_path().is_file()


def test_a_real_upload_report_is_not_labelled_a_sample(client, analysed):
    """The end-to-end form of the test above, through the surface a user sees."""
    client.post("/api/sample")
    client.post(
        "/api/upload",
        files={"file": ("mine.cfg", b"!\nhostname rtr-mine\n!\n", "text/plain")},
    )
    client.get("/api/findings")

    html = client.get("/api/report?format=html").text

    assert "SAMPLE NETWORK" not in html


# --- isolation ----------------------------------------------------------------


def test_one_session_loading_the_sample_does_not_affect_another(analysed):
    """#242's rule, applied to the new endpoint rather than assumed from it.

    A module-level flag here would recreate exactly the defect session
    isolation was built to fix: one visitor clicking the sample changing what
    every other browser was analysing.
    """
    a, b = TestClient(main.app), TestClient(main.app)

    a.post("/api/sample")

    assert a.get("/api/findings").json() != []
    assert b.get("/api/findings").json() == []
