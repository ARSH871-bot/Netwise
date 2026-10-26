"""
Netwise -- tests for web/main.py's /api/ask endpoint (US-11, and #318's
chat-context persistence on top of it).

WHY THESE TESTS EXIST
    The endpoint itself is a thin wrapper: connect, load the snapshot, hand
    the question (and this session's remembered context) to
    ai.query.answer_question(), then persist whatever it returns. What's
    actually worth testing here is that the wrapper never turns an
    operational failure (no upload yet, Batfish unreachable, the snapshot
    won't load) into an HTTP error -- it always returns the same four-key
    shape answer_question() itself returns -- and that context genuinely
    round-trips through THIS session and never another one, monkeypatching
    web.main.analysis_pipeline.connect/load_snapshot so this runs without
    Batfish, the same reasoning tests/test_web_findings_explanation.py
    already gives for testing this file's other endpoint this way.

    The first four tests use one shared `client` and monkeypatch
    `main._uploaded` directly (a single-process override, see
    `_is_uploaded()`'s own docstring), the same pattern this file always
    has. The context-persistence tests need two REAL, separately-cookied
    sessions, so they build their own `TestClient` instances instead --
    see tests/test_session_isolation.py for why that distinction matters.

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
    """The endpoint's own job ends at handing the question, a connected
    session, and this session's stored context to answer_question() --
    confirmed by monkeypatching that function directly and checking its
    return value passes through unchanged, rather than re-testing
    answer_question()'s own logic here."""
    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(main.analysis_pipeline, "connect", lambda: "fake-session")
    monkeypatch.setattr(
        main.analysis_pipeline, "load_snapshot", lambda bf, c, n, s: None
    )

    captured = {}

    def fake_answer_question(question, bf, context=None):
        captured["question"] = question
        captured["bf"] = bf
        captured["context"] = context
        return {
            "question_understood": "Can rtr-us5 reach 10.20.0.5?",
            "answer": "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
            "grounded": True,
            "context": {
                "source_device": "rtr-us5",
                "destination_ip": "10.20.0.5",
                "destination_display": "10.20.0.5",
            },
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question)
    response = client.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.5?"})

    assert response.status_code == 200
    assert response.json() == {
        "question_understood": "Can rtr-us5 reach 10.20.0.5?",
        "answer": "Yes. Traffic from rtr-us5 reaches 10.20.0.5.",
        "grounded": True,
        "context": {
            "source_device": "rtr-us5",
            "destination_ip": "10.20.0.5",
            "destination_display": "10.20.0.5",
        },
    }
    assert captured["question"] == "Can rtr-us5 reach 10.20.0.5?"
    assert captured["bf"] == "fake-session"
    # A fresh session (no prior question in this test) has nothing stored.
    assert captured["context"] is None


def test_a_missing_question_field_is_a_validation_error():
    """FastAPI/pydantic's own validation, not application logic -- confirms
    the request shape is actually enforced rather than silently accepting
    a malformed body."""
    response = client.post("/api/ask", json={})
    assert response.status_code == 422


# --- #318 (US-25): context persists within a session, never across one ---------


def _stub_batfish_plumbing(monkeypatch):
    """Shared setup for the context-persistence tests below: a config is
    staged (a real upload, so a real session cookie gets set) and
    connect/load_snapshot are stubbed out so no real Batfish is needed."""
    monkeypatch.setattr(main.analysis_pipeline, "connect", lambda: "fake-session")
    monkeypatch.setattr(
        main.analysis_pipeline, "load_snapshot", lambda bf, c, n, s: None
    )


def test_context_returned_by_one_call_is_passed_into_the_next(monkeypatch):
    """Two calls on the SAME client (one cookie jar, one session) -- the
    second must receive exactly what the first returned as context,
    proving the round trip through `_chat_context`, not just that
    answer_question() itself can accept a context argument."""
    _stub_batfish_plumbing(monkeypatch)
    monkeypatch.setattr(main, "_uploaded", True)
    a = TestClient(main.app)

    captured_contexts = []

    def fake_answer_question(question, bf, context=None):
        captured_contexts.append(context)
        return {
            "question_understood": f"Can rtr-us5 reach 10.20.0.{len(captured_contexts)}?",
            "answer": "Yes.",
            "grounded": True,
            "context": {
                "source_device": "rtr-us5",
                "destination_ip": f"10.20.0.{len(captured_contexts)}",
                "destination_display": f"10.20.0.{len(captured_contexts)}",
            },
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question)

    a.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.1?"})
    a.post("/api/ask", json={"question": "What about 10.20.0.2 instead?"})

    assert captured_contexts[0] is None
    assert captured_contexts[1] == {
        "source_device": "rtr-us5",
        "destination_ip": "10.20.0.1",
        "destination_display": "10.20.0.1",
    }


def test_context_from_one_session_never_reaches_a_different_one(monkeypatch):
    """Two SEPARATE TestClient instances, each its own cookie jar -- a
    second browser must not inherit the first's remembered device, the
    same isolation guarantee test_session_isolation.py already proves for
    uploads and the analysis cache."""
    _stub_batfish_plumbing(monkeypatch)
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_answer_question(question, bf, context=None):
        return {
            "question_understood": "Can rtr-us5 reach 10.20.0.1?",
            "answer": "Yes.",
            "grounded": True,
            "context": {
                "source_device": "rtr-us5",
                "destination_ip": "10.20.0.1",
                "destination_display": "10.20.0.1",
            },
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question)

    a, b = TestClient(main.app), TestClient(main.app)
    a.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.1?"})

    captured_contexts = []

    def fake_answer_question_b(question, bf, context=None):
        captured_contexts.append(context)
        return {
            "question_understood": None,
            "answer": "refused",
            "grounded": False,
            "context": context,
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question_b)
    b.post("/api/ask", json={"question": "What about 10.20.0.2 instead?"})

    assert captured_contexts == [None]


def test_a_new_upload_clears_this_sessions_chat_context(monkeypatch):
    """Belt and braces over #82, the same shape
    test_analysis_cache.py::test_uploading_clears_the_analysis_cache
    already uses: content-keying/session-scoping already makes a stale
    device name unreachable from a DIFFERENT session, but the invariant
    should hold within the SAME session too -- a real upload must forget
    what was asked about the network it replaced.

    DOES NOT MONKEYPATCH `main.CONFIGS_DIR`. It is a PEP 562 dynamic
    property (`web/main.py`'s `__getattr__`, resolved fresh from the last
    active session on every access, not a real attribute) -- patching it
    freezes a stale snapshot in the module's `__dict__` that survives
    monkeypatch's own teardown and corrupts every later test that reads
    it, exactly the way `test_web_config_upload.py`'s tests do. This test
    does not need to touch it at all: it only ever asserts through the
    public `/api/ask` response, never the filesystem."""
    _stub_batfish_plumbing(monkeypatch)
    monkeypatch.setattr(main, "_uploaded", True)

    def fake_answer_question(question, bf, context=None):
        return {
            "question_understood": "Can rtr-us5 reach 10.20.0.1?",
            "answer": "Yes.",
            "grounded": True,
            "context": {
                "source_device": "rtr-us5",
                "destination_ip": "10.20.0.1",
                "destination_display": "10.20.0.1",
            },
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question)

    c = TestClient(main.app)
    c.post("/api/ask", json={"question": "Can rtr-us5 reach 10.20.0.1?"})
    c.post(
        "/api/upload",
        files={"file": ("device.cfg", b"hostname rtr-us5\n", "text/plain")},
    )

    captured_contexts = []

    def fake_answer_question_after_upload(question, bf, context=None):
        captured_contexts.append(context)
        return {
            "question_understood": None,
            "answer": "refused",
            "grounded": False,
            "context": context,
        }

    monkeypatch.setattr(main, "answer_question", fake_answer_question_after_upload)
    c.post("/api/ask", json={"question": "What about 10.20.0.2 instead?"})

    assert captured_contexts == [None]


def test_the_upload_endpoint_actually_discards_chat_context():
    """The wiring, not just the function -- same reasoning as
    test_analysis_cache.py::test_the_upload_endpoint_actually_calls_it. A
    discard function that exists and is never called from upload_config()
    is the same as no discard at all, and would test green against every
    unit test written against _discard_chat_context() alone."""
    import inspect

    source = inspect.getsource(main.upload_config)
    assert "_discard_chat_context()" in source, (
        "upload_config does not clear the chat context"
    )
