"""
Netwise -- tests for web/main.py's /api/propose endpoint (US-13, US-14).

WHY THESE TESTS EXIST
    The endpoint itself is a thin wrapper: gate on an upload existing, hand
    the request and the snapshot directory to ai.propose.propose_change(),
    attach explanations to whatever it returns in "impact". What's worth
    testing here is that the wrapper never turns an operational failure (no
    upload yet, propose_change() itself refusing) into an HTTP error -- it
    always returns propose_change()'s own shape -- and that it actually
    delegates rather than reimplementing any of propose_change()'s logic,
    same reasoning tests/test_web_ask_endpoint.py already gives for testing
    /api/ask this way.

RUN
    pytest tests/ -v
"""

from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)

GOOD_REQUEST = "block 10.10.10.5 to 10.20.0.5 on tcp/443 on rtr-us5"


def test_proposing_before_any_upload_is_refused(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    response = client.post("/api/propose", json={"request": GOOD_REQUEST})
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert body["request_understood"] is None
    assert body["proposed_change"] is None
    assert body["impact"] == []
    assert body["verified"] is False
    assert body["warning"] is False
    assert "Upload a config first" in body["answer"]


def test_a_missing_request_field_is_a_validation_error():
    """FastAPI/pydantic's own validation, not application logic -- confirms
    the request shape is actually enforced rather than silently accepting
    a malformed body."""
    response = client.post("/api/propose", json={})
    assert response.status_code == 422


def test_a_refusal_from_propose_change_passes_through_unchanged(monkeypatch):
    """The endpoint's own job ends at delegating -- confirmed by
    monkeypatching propose_change() directly and checking a refusal comes
    back exactly as given, rather than re-testing propose_change()'s own
    parsing logic here."""
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": None,
            "proposed_change": None,
            "impact": [],
            "verified": False,
            "warning": False,
            "grounded": False,
            "answer": "I could not find an action in the request.",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    response = client.post("/api/propose", json={"request": "gibberish"})

    assert response.status_code == 200
    assert response.json() == {
        "request_understood": None,
        "proposed_change": None,
        "impact": [],
        "verified": False,
        "warning": False,
        "grounded": False,
        "answer": "I could not find an action in the request.",
    }


def test_a_successful_proposal_delegates_to_propose_change_with_the_snapshot_dir(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)
    captured = {}

    def fake_propose_change(request, before_dir, host="localhost"):
        captured["request"] = request
        captured["before_dir"] = before_dir
        return {
            "request_understood": "On rtr-us5, add to 'acl_in' (at the top): deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
            "proposed_change": {
                "device": "rtr-us5", "filter": "acl_in",
                "line": "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
            },
            "impact": [],
            "verified": True,
            "warning": False,
            "grounded": True,
            "answer": "Generated and simulated: no detected effect.",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    response = client.post("/api/propose", json={"request": GOOD_REQUEST})

    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is True
    assert body["proposed_change"]["device"] == "rtr-us5"
    assert captured["request"] == GOOD_REQUEST
    assert captured["before_dir"] == main.SNAPSHOT_DIR


def test_impact_findings_with_status_found_get_an_explanation_attached(monkeypatch):
    """The whole reason for reusing _attach_explanations() rather than
    returning the raw impact list -- a warning naming the exact ACL lines
    is more useful read in plain English."""
    monkeypatch.setattr(main, "_uploaded", True)

    finding = {
        "id": "CH-001", "check": "change_impact", "severity": "high",
        "device": "rtr-us5", "summary": "A rule change opens traffic",
        "evidence": {"detail": "d", "source": "s"}, "status": "found",
    }

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": "...", "proposed_change": {"device": "rtr-us5", "filter": "acl_in", "line": "..."},
            "impact": [dict(finding)],
            "verified": True, "warning": True, "grounded": True,
            "answer": "Warning: ...",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    monkeypatch.setattr(
        main, "explain_with_source", lambda f: ("Plain-English summary.", "fallback")
    )
    response = client.post("/api/propose", json={"request": GOOD_REQUEST})

    body = response.json()
    assert body["impact"][0]["explanation"] == "Plain-English summary."
    assert body["impact"][0]["explanation_source"] == "fallback"


def test_an_explanation_failure_does_not_break_the_response(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)

    finding = {
        "id": "CH-001", "check": "change_impact", "severity": "high",
        "device": "rtr-us5", "summary": "A rule change opens traffic",
        "evidence": {"detail": "d", "source": "s"}, "status": "found",
    }

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": "...", "proposed_change": {"device": "rtr-us5", "filter": "acl_in", "line": "..."},
            "impact": [dict(finding)],
            "verified": True, "warning": True, "grounded": True,
            "answer": "Warning: ...",
        }

    def explode(finding):
        raise RuntimeError("Ollama is not reachable")

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    monkeypatch.setattr(main, "explain_with_source", explode)
    response = client.post("/api/propose", json={"request": GOOD_REQUEST})

    assert response.status_code == 200
    body = response.json()
    assert "explanation" not in body["impact"][0]
    assert body["grounded"] is True


def test_a_none_status_finding_in_impact_is_not_explained(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)

    finding = {
        "id": "CH-000", "check": "change_impact", "severity": "low",
        "device": "unknown", "summary": "No change detected",
        "evidence": {"detail": "d", "source": "s"}, "status": "none",
    }
    calls = []

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": "...", "proposed_change": {"device": "rtr-us5", "filter": "acl_in", "line": "..."},
            "impact": [dict(finding)],
            "verified": True, "warning": False, "grounded": True,
            "answer": "No detected effect.",
        }

    def tracked(f):
        calls.append(f)
        return ("should not be called", "model")

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    monkeypatch.setattr(main, "explain_with_source", tracked)
    response = client.post("/api/propose", json={"request": GOOD_REQUEST})

    assert calls == []
    assert "explanation" not in response.json()["impact"][0]


# ---------------------------------------------------------------------------
# /api/propose/download -- the strengthening: a downloadable proposed config
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# /api/propose/full-scan -- the recommended strengthening
# ---------------------------------------------------------------------------


def test_full_scan_before_any_upload_is_refused_not_a_500(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    response = client.post("/api/propose/full-scan", json={"request": GOOD_REQUEST})
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert body["proposed_change"] is None
    assert body["findings"] == []
    assert "Upload a config first" in body["answer"]


def test_full_scan_delegates_to_propose_and_scan_with_the_staged_policy(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)
    captured = {}
    sentinel_policy = object()

    def fake_propose_and_scan(request, before_dir, host="localhost", policy=None):
        captured["request"] = request
        captured["before_dir"] = before_dir
        captured["policy"] = policy
        return {
            "proposed_change": {"device": "rtr-us5", "filter": "acl_in", "line": "..."},
            "findings": [],
            "grounded": True,
            "answer": "Full scan of the proposed config for rtr-us5: 0 result(s)...",
        }

    monkeypatch.setattr(main, "propose_and_scan", fake_propose_and_scan)
    monkeypatch.setattr(main, "_staged_policy", lambda: sentinel_policy)
    response = client.post("/api/propose/full-scan", json={"request": GOOD_REQUEST})

    assert response.status_code == 200
    assert captured["request"] == GOOD_REQUEST
    assert captured["before_dir"] == main.SNAPSHOT_DIR
    assert captured["policy"] is sentinel_policy


def test_full_scan_findings_get_explanations_and_remediation_attached(monkeypatch):
    """The whole reason to reuse _attach_explanations()/_attach_remediation()
    rather than returning the raw pipeline output -- the same treatment a
    real upload's findings already get."""
    monkeypatch.setattr(main, "_uploaded", True)

    finding = {
        "id": "AC-001", "check": "access_control", "severity": "medium",
        "device": "rtr-us5", "summary": "found by the full scan",
        "evidence": {"detail": "d", "source": "s"}, "status": "found",
    }

    def fake_propose_and_scan(request, before_dir, host="localhost", policy=None):
        return {
            "proposed_change": {"device": "rtr-us5", "filter": "acl_in", "line": "..."},
            "findings": [dict(finding)],
            "grounded": True,
            "answer": "...",
        }

    monkeypatch.setattr(main, "propose_and_scan", fake_propose_and_scan)
    monkeypatch.setattr(
        main, "explain_with_source", lambda f: ("Plain-English summary.", "fallback")
    )
    response = client.post("/api/propose/full-scan", json={"request": GOOD_REQUEST})

    body = response.json()
    assert body["findings"][0]["explanation"] == "Plain-English summary."
    assert body["findings"][0]["explanation_source"] == "fallback"


def test_full_scan_refusal_passes_through_with_empty_findings(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_propose_and_scan(request, before_dir, host="localhost", policy=None):
        return {
            "proposed_change": None,
            "findings": [],
            "grounded": False,
            "answer": "I could not find an action in the request.",
        }

    monkeypatch.setattr(main, "propose_and_scan", fake_propose_and_scan)
    response = client.post("/api/propose/full-scan", json={"request": "gibberish"})

    assert response.status_code == 200
    body = response.json()
    assert body["proposed_change"] is None
    assert body["findings"] == []
    assert body["grounded"] is False


def test_download_before_any_upload_is_a_422(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    response = client.post("/api/propose/download", data={"request": GOOD_REQUEST})
    assert response.status_code == 422
    assert "Upload a config first" in response.json()["detail"]


def test_download_a_refused_request_is_a_422_not_a_file(monkeypatch):
    """A refused proposal must never come back as a 200 file whose content
    is quietly the refusal text with a .cfg extension attached."""
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": None, "proposed_change": None, "impact": [],
            "verified": False, "warning": False, "grounded": False,
            "answer": "I could not find the word \"to\" separating a source from a destination.",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    response = client.post("/api/propose/download", data={"request": "block youtube"})

    assert response.status_code == 422
    assert "separating a source" in response.json()["detail"]
    assert "Content-Disposition" not in response.headers


def test_a_successful_download_is_a_real_attachment(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": "...",
            "proposed_change": {
                "device": "rtr-us5", "filter": "acl_in",
                "line": "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
                "before_lines": [], "after_lines": [],
                "after_config_text": "! GENERATED BY NETWISE -- PROPOSED CHANGE, NOT APPLIED\nhostname rtr-us5\n",
            },
            "impact": [], "verified": True, "warning": False, "grounded": True,
            "answer": "Generated and simulated: no detected effect.",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    response = client.post("/api/propose/download", data={"request": GOOD_REQUEST})

    assert response.status_code == 200
    assert response.text == fake_propose_change("", "")["proposed_change"]["after_config_text"]
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert "rtr-us5" in disposition
    assert disposition.endswith('.cfg"')


def test_the_download_filename_never_collides_across_devices(monkeypatch):
    """Two devices proposed against in the same minute must not overwrite
    each other's downloaded file in a browser's downloads folder."""
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_propose_change(request, before_dir, host="localhost"):
        return {
            "request_understood": "...",
            "proposed_change": {
                "device": "rtr-branch", "filter": "acl_in", "line": "...",
                "before_lines": [], "after_lines": [],
                "after_config_text": "hostname rtr-branch\n",
            },
            "impact": [], "verified": True, "warning": False, "grounded": True,
            "answer": "...",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    response = client.post("/api/propose/download", data={"request": GOOD_REQUEST})

    assert "rtr-branch" in response.headers["content-disposition"]
    assert "rtr-us5" not in response.headers["content-disposition"]


def test_download_delegates_to_propose_change_with_the_same_arguments_as_the_json_endpoint(monkeypatch):
    """Same computation both endpoints share -- confirmed by capturing the
    call rather than trusting that it happens to look the same."""
    monkeypatch.setattr(main, "_uploaded", True)
    captured = {}

    def fake_propose_change(request, before_dir, host="localhost"):
        captured["request"] = request
        captured["before_dir"] = before_dir
        return {
            "request_understood": "...",
            "proposed_change": {
                "device": "rtr-us5", "filter": "acl_in", "line": "...",
                "before_lines": [], "after_lines": [],
                "after_config_text": "hostname rtr-us5\n",
            },
            "impact": [], "verified": True, "warning": False, "grounded": True,
            "answer": "...",
        }

    monkeypatch.setattr(main, "propose_change", fake_propose_change)
    client.post("/api/propose/download", data={"request": GOOD_REQUEST})

    assert captured["request"] == GOOD_REQUEST
    assert captured["before_dir"] == main.SNAPSHOT_DIR
