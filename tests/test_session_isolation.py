"""Two browsers must never see each other's scan (#242).

WHY A REAL CONCURRENT TEST AND NOT SEQUENTIAL CALLS
    Sequential calls prove almost nothing here. Upload A, read A, upload B,
    read B passes on the OLD code too -- the second upload simply overwrote
    the first, and each read happened to follow its own write. The bug was
    never "the wrong answer eventually"; it was "the wrong answer while
    someone else is using it".

    So these tests use TWO TestClient instances with interleaved and
    genuinely simultaneous requests. Each client keeps its own cookie jar,
    which is what makes it a second browser rather than a second call.

WHAT ISOLATION MEANS HERE, PRECISELY
    Not "eventually consistent". At no point may a request made by client A
    return anything derived from client B's upload -- not its findings, not
    its config name, not a cached list object it also holds.

    The three pieces of state that used to be shared, one test each:
      the staged config directory   (#242)
      the `_uploaded` flag          (#242)
      the analysis cache key        (#242, and #208's sharing half)

NO BATFISH. `analysis_pipeline.analyse` is replaced with a stub that reports
which config it was handed, so these tests are about the plumbing rather
than about the analysis -- and they run in CI.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web import main
from web.session import SESSION_COOKIE


def _finding(device: str, detail: str):
    return {
        "id": "AC-001",
        "check": "access_control",
        "severity": "high",
        "device": device,
        "summary": f"finding for {device}",
        "evidence": {"detail": detail, "source": "testFilters"},
        "status": "found",
    }


@pytest.fixture
def analysed(monkeypatch):
    """Report which config the caller staged, without going near Batfish.

    Reads the config off disk at call time, so a request that resolved the
    WRONG session's directory produces the wrong finding rather than
    failing -- which is the failure mode worth catching. A stub that
    ignored the path would pass even with the isolation removed.
    """

    def fake_analyse(snapshot_dir, snapshot_name=None, **kwargs):
        configs = Path(snapshot_dir) / "configs"
        staged = sorted(configs.glob("*"))
        text = staged[0].read_text(encoding="utf-8").strip() if staged else "<none>"
        return [_finding(text, f"analysed {text}")]

    monkeypatch.setattr(main.analysis_pipeline, "analyse", fake_analyse)
    monkeypatch.setattr(main, "_attach_explanations", lambda results: results)
    main.reset_analysis_cache()
    return fake_analyse


def _upload(client: TestClient, hostname: str):
    return client.post(
        "/api/upload",
        files={"file": ("device.cfg", f"hostname {hostname}\n".encode(), "text/plain")},
    )


def _devices(client: TestClient):
    return [f["device"] for f in client.get("/api/findings").json()]


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_two_clients_are_issued_different_sessions():
    a, b = TestClient(main.app), TestClient(main.app)
    a.get("/api/findings")
    b.get("/api/findings")

    assert a.cookies.get(SESSION_COOKIE)
    assert b.cookies.get(SESSION_COOKIE)
    assert a.cookies.get(SESSION_COOKIE) != b.cookies.get(SESSION_COOKIE)


def test_one_client_keeps_its_session_across_requests():
    """Otherwise every request is a new user and nothing is ever found."""
    a = TestClient(main.app)
    a.get("/api/findings")
    first = a.cookies.get(SESSION_COOKIE)
    a.get("/api/findings")

    assert a.cookies.get(SESSION_COOKIE) == first


def test_a_forged_session_cookie_is_discarded_not_used_as_a_path():
    """The cookie becomes a directory name, so a traversal attempt must be
    thrown away rather than escaped or repaired."""
    a = TestClient(main.app)
    # Sent as a raw header rather than through the cookie jar: httpx raises
    # CookieConflict when the jar holds two cookies of one name, and the
    # server is about to issue a replacement.
    response = a.get(
        "/api/findings",
        headers={"Cookie": f"{SESSION_COOKIE}=../../../../etc/passwd"},
    )

    issued = response.cookies.get(SESSION_COOKIE)
    assert issued, "a forged cookie must be replaced with a fresh id, not accepted"
    assert issued != "../../../../etc/passwd"
    assert "/" not in issued and "\\" not in issued and ".." not in issued

    # And nothing was created outside the sessions root.
    assert not (main.CONFIG_ROOT.parent / "etc").exists()


# ---------------------------------------------------------------------------
# THE ISOLATION ITSELF
# ---------------------------------------------------------------------------


def test_interleaved_uploads_never_cross(analysed):
    """The headline case, interleaved rather than sequential.

    A uploads, B uploads, THEN both read. On process-wide state B's upload
    has overwritten A's by the time A reads, so A sees B's config -- which
    is exactly what this asserts cannot happen.
    """
    a, b = TestClient(main.app), TestClient(main.app)

    assert _upload(a, "rtr-alpha").status_code == 200
    assert _upload(b, "rtr-beta").status_code == 200

    assert _devices(a) == ["hostname rtr-alpha"]
    assert _devices(b) == ["hostname rtr-beta"]


def test_neither_client_can_see_the_other_after_repeated_reads(analysed):
    """Re-reading must not drift into the other session via the cache."""
    a, b = TestClient(main.app), TestClient(main.app)
    _upload(a, "rtr-alpha")
    _upload(b, "rtr-beta")

    for _ in range(3):
        assert _devices(a) == ["hostname rtr-alpha"]
        assert _devices(b) == ["hostname rtr-beta"]


def test_genuinely_simultaneous_requests_stay_separate(analysed):
    """Two real threads, both in flight at once.

    The interleaved test above still runs one request at a time. This one
    holds both inside the app simultaneously, which is the only way to
    exercise a ContextVar actually being per-task rather than merely being
    set and reset in a tidy order.
    """
    a, b = TestClient(main.app), TestClient(main.app)
    _upload(a, "rtr-alpha")
    _upload(b, "rtr-beta")

    seen: dict[str, list] = {}
    barrier = threading.Barrier(2, timeout=30)

    def read(name, client):
        barrier.wait()          # neither proceeds until both are ready
        seen[name] = _devices(client)

    threads = [
        threading.Thread(target=read, args=("a", a)),
        threading.Thread(target=read, args=("b", b)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert seen["a"] == ["hostname rtr-alpha"]
    assert seen["b"] == ["hostname rtr-beta"]


def test_identical_configs_do_not_share_a_cache_entry(analysed):
    """#208's sharing half.

    Two sessions staging BYTE-IDENTICAL configs have identical content
    fingerprints. Keyed on content alone they would share one entry -- and
    the entry holds a list object, so they would share state, not merely a
    result.
    """
    a, b = TestClient(main.app), TestClient(main.app)
    _upload(a, "rtr-same")
    _upload(b, "rtr-same")

    key_a = _key_for(a)
    key_b = _key_for(b)

    assert key_a is not None and key_b is not None
    assert key_a != key_b, (
        "identical config bytes in two sessions must not collapse to one "
        "cache entry -- they would share the findings list object"
    )


def _key_for(client: TestClient) -> str:
    """The analysis key as computed for THAT client's session."""
    session_id = client.cookies.get(SESSION_COOKIE)
    from web.session import reset_current_session, set_current_session

    token = set_current_session(session_id)
    try:
        return main._analysis_key()
    finally:
        reset_current_session(token)


def test_one_session_uploading_does_not_put_others_into_the_uploaded_state(analysed):
    """`_uploaded` was one process-wide bool.

    A brand-new browser must NOT be shown a real analysis of a config it
    never sent, just because somebody else uploaded one.

    THE ASSERTION CHANGED WITH THE MOCKS, AND IS NOW STRICTER.
        This used to assert the fresh session got as many findings as
        `web/mock_findings.py` held. Those six fabricated findings were
        removed -- one of them a `status="none"` claiming policy compliance
        had run clean on a config nobody uploaded.

        So the fresh session now gets nothing at all, which is both the
        correct answer and a stronger one: "no findings" cannot leak
        another session's device, whereas "six findings" only happened not
        to.
    """
    a = TestClient(main.app)
    _upload(a, "rtr-alpha")

    fresh = TestClient(main.app)
    devices = _devices(fresh)

    assert devices != ["hostname rtr-alpha"]
    assert devices == [], (
        "a session that uploaded nothing was shown findings. Whatever they "
        "say, they were not measured from that session's configuration."
    )


def test_each_session_stages_into_its_own_directory(analysed):
    """The storage half, asserted on disk rather than through the API."""
    a, b = TestClient(main.app), TestClient(main.app)
    _upload(a, "rtr-alpha")
    _upload(b, "rtr-beta")

    dir_a = main.configs_dir(a.cookies.get(SESSION_COOKIE))
    dir_b = main.configs_dir(b.cookies.get(SESSION_COOKIE))

    assert dir_a != dir_b
    assert (dir_a / "device.cfg").read_text(encoding="utf-8").strip() == "hostname rtr-alpha"
    assert (dir_b / "device.cfg").read_text(encoding="utf-8").strip() == "hostname rtr-beta"


def test_a_policy_uploaded_by_one_session_is_not_staged_for_another(analysed):
    """The same separation for the other two staged files."""
    import json

    a, b = TestClient(main.app), TestClient(main.app)
    policy = {
        "device": "rtr-alpha",
        "policy_compliance": [
            {
                "description": "d",
                "filter": "acl_in",
                "kind": "prohibition",
                "queries": [],
                "violation_severity": "high",
                "violation_summary": "s",
            }
        ],
    }
    assert a.post(
        "/api/policy",
        files={"file": ("p.json", json.dumps(policy).encode(), "application/json")},
    ).status_code == 200
    b.get("/api/findings")

    assert main.policy_path(a.cookies.get(SESSION_COOKIE)).exists()
    assert not main.policy_path(b.cookies.get(SESSION_COOKIE)).exists()


# ---------------------------------------------------------------------------
# Single-session behaviour is unchanged
# ---------------------------------------------------------------------------


def test_a_single_client_behaves_exactly_as_before(analysed):
    """The whole point of the compatibility work: one user notices nothing.

    Upload, read, re-upload, read again -- the ordinary flow, with no
    second session anywhere near it.
    """
    a = TestClient(main.app)

    assert _devices(a) != ["hostname rtr-one"]      # mocks before any upload
    _upload(a, "rtr-one")
    assert _devices(a) == ["hostname rtr-one"]
    _upload(a, "rtr-two")
    assert _devices(a) == ["hostname rtr-two"]
