"""
Netwise -- tests for web/main.py's /api/ask endpoint (US-11).

WHY THESE TESTS EXIST
    The endpoint itself is a thin wrapper: connect, load the snapshot, hand
    the question to ai.query.answer_question(). What's actually worth
    testing here is that the wrapper never turns an operational failure
    (no upload yet, Batfish unreachable, the snapshot won't load) into an
    HTTP error -- it always returns the same three-key shape
    answer_question() itself returns, monkeypatching
    web.main.analysis_pipeline.connect/load_snapshot so this runs without
    Batfish, the same reasoning tests/test_web_findings_explanation.py
    already gives for testing this file's other endpoint this way.

RUN
    pytest tests/ -v
"""

from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


def test_asking_before_any_upload_is_refused(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert body["question_understood"] is None
    assert "Upload a config first" in body["answer"]


def test_connect_failure_is_a_refusal_not_a_500(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)

    def explode():
        raise RuntimeError("Batfish is not running")

    monkeypatch.setattr(main.analysis_pipeline, "connect", explode)
    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert "Could not reach Batfish" in body["answer"]


def test_load_snapshot_failure_is_a_refusal_not_a_500(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(main.analysis_pipeline, "connect", lambda: object())

    def explode(bf, config_dir, network_name, snapshot_name):
        raise FileNotFoundError("no configs subfolder")

    monkeypatch.setattr(main.analysis_pipeline, "load_snapshot", explode)
    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert "Could not reach Batfish" in body["answer"]


def test_a_successful_connection_delegates_to_answer_question(monkeypatch):
    """The endpoint's own job ends at handing the question and a connected
    session to answer_question() -- confirmed by monkeypatching that
    function directly and checking its return value passes through
    unchanged, rather than re-testing answer_question()'s own logic here."""
    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(main.analysis_pipeline, "connect", lambda: "fake-session")
    monkeypatch.setattr(
        main.analysis_pipeline, "load_snapshot", lambda bf, c, n, s: None
    )

    captured = {}

    def fake_answer_question(question, bf):
        captured["question"] = question
        captured["bf"] = bf
        return {
            "question_understood": "Can rtr-us5 reach 10.20.0.5?",
            "answer": "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
            "grounded": True,
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question)
    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})

    assert response.status_code == 200
    assert response.json() == {
        "question_understood": "Can rtr-us5 reach 10.20.0.5?",
        "answer": "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
        "grounded": True,
    }
    assert captured["question"] == "Can rtr-us5 reach 10.20.0.5?"
    assert captured["bf"] == "fake-session"


def test_a_missing_question_field_is_a_validation_error():
    """FastAPI/pydantic's own validation, not application logic -- confirms
    the request shape is actually enforced rather than silently accepting
    a malformed body."""
    response = client.post("/api/ask", json={})
    assert response.status_code == 422
