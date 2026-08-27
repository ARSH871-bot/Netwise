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
