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

    def fake_answer_question(question, bf, previous=None):
        captured["question"] = question
        captured["bf"] = bf
        captured["previous"] = previous
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


# ---------------------------------------------------------------------------
# Follow-up wiring (#318) -- ai.query.answer_question()'s own carry-forward
# LOGIC is already thoroughly tested in tests/test_query_translation.py with
# a real (fake) Batfish session. What's specific to THIS layer, and not
# covered there, is whether the endpoint correctly reads, stores, and
# isolates the per-session state between calls -- so answer_question()
# itself is faked here, the same way the existing test above fakes it,
# rather than re-proving the carry-forward logic a second time.
# ---------------------------------------------------------------------------


def _upload(c: TestClient, hostname: str):
    return c.post(
        "/api/upload",
        files={"file": (f"{hostname}.cfg", f"hostname {hostname}\n".encode(),
                        "text/plain")},
    )


def _stub_connection(monkeypatch):
    monkeypatch.setattr(main.analysis_pipeline, "connect", lambda: "fake-session")
    monkeypatch.setattr(
        main.analysis_pipeline, "load_snapshot", lambda bf, c, n, s: None
    )


def _fake_answer_question(question, bf, previous=None):
    """Reflects whether `previous` was passed, rather than doing any real
    resolution -- the fact under test here is what the ENDPOINT does with
    `previous`, not whether ai.query's own fallback logic is correct."""
    if previous is None:
        return {
            "question_understood": "first resolution",
            "answer": "fresh",
            "grounded": True,
            "resolved_entities": {
                "source_device": "rtr-us5",
                "destination_ip": "10.20.0.5",
                "destination_display": "10.20.0.5",
            },
        }
    return {
        "question_understood": f"follow-up using {previous['source_device']}",
        "answer": "carried forward",
        "grounded": True,
        "resolved_entities": previous,
    }


def test_a_follow_up_in_the_same_session_receives_the_previous_resolution(
        monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)
    _stub_connection(monkeypatch)
    monkeypatch.setattr(main, "answer_question", _fake_answer_question)

    first = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert first.json()["question_understood"] == "first resolution"

    second = client.post("/api/ask", json={"question": "Does it also reach that?"})
    assert second.json()["question_understood"] == "follow-up using rtr-us5"


def test_resolved_entities_never_reaches_the_http_response(monkeypatch):
    """The wire contract stays the three public keys -- the fourth key is
    a signal between this endpoint and answer_question(), not new API
    surface a client should ever see."""
    monkeypatch.setattr(main, "_uploaded", True)
    _stub_connection(monkeypatch)
    monkeypatch.setattr(main, "answer_question", _fake_answer_question)

    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert set(response.json().keys()) == {"question_understood", "answer", "grounded"}


def test_two_sessions_never_share_a_carried_forward_entity(monkeypatch):
    """Session A resolves a question; session B's follow-up-shaped question
    must be treated as a FIRST question, never silently answered using A's
    resolution. Same class of guarantee tests/test_session_isolation.py
    already establishes for uploads and the analysis cache."""
    monkeypatch.setattr(main, "_uploaded", True)
    _stub_connection(monkeypatch)
    monkeypatch.setattr(main, "answer_question", _fake_answer_question)

    a = TestClient(main.app)
    a_response = a.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert a_response.json()["question_understood"] == "first resolution"

    b = TestClient(main.app)
    b_response = b.post("/api/ask", json={"question": "Does it also reach that?"})
    assert b_response.json()["question_understood"] == "first resolution", (
        "a brand-new session's question was answered using another "
        "session's carried-forward entity"
    )


def test_uploading_a_new_config_clears_the_carried_forward_entity(monkeypatch):
    _stub_connection(monkeypatch)
    monkeypatch.setattr(main, "answer_question", _fake_answer_question)

    c = TestClient(main.app)
    _upload(c, "rtr-alpha")
    first = c.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})
    assert first.json()["question_understood"] == "first resolution"

    _upload(c, "rtr-beta")
    second = c.post("/api/ask", json={"question": "Does it also reach that?"})
    assert second.json()["question_understood"] == "first resolution", (
        "a new upload did not clear the previous network's carried-forward "
        "entity"
    )
