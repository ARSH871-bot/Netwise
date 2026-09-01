"""An uploaded policy must actually reach the checks (#181, gated on #182).

WHY A SEPARATE FILE FROM test_web_policy_upload.py
    That file tests the UPLOAD half: a policy is validated, staged, and
    rejected cleanly when it is malformed. Every one of its tests passed on
    a build where the staged policy was then read by nothing at all.

    That is the point. `/api/policy` was deliberately written to stage
    without installing, because how a policy reaches a check was an open
    team decision (#182). So "the upload works" and "the policy is applied"
    were two claims, and only the first was tested -- correctly, because
    only the first was true.

    This file tests the second. It is the other end of the join.

BREAKING BOTH ENDS
    A test that asserts `analyse()` was called with a policy proves the
    call exists. It does not prove a check reads it, and it would pass
    against a build where `rules_in_use()` ignored its input entirely.

    So these drive a REAL HTTP request through the REAL endpoint, stub only
    `analysis.pipeline._analyse` -- the innermost function, below the point
    where the policy is installed -- and then call the REAL
    `policy_compliance.rules_in_use()` from inside that stub. What is being
    asserted is what an actual check would actually see, at the moment it
    would actually see it.

NO BATFISH, NO OLLAMA
    `_analyse` is the only thing that touches Batfish, and it is exactly
    what is replaced.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from analysis import pipeline, policy
from analysis.checks import policy_compliance
from web import main

client = TestClient(main.app)


#: A policy naming a device that is NOT the one our built-in rules name, so
#: "the user's rules were used" cannot be confused with "ours happened to
#: match". Mirrors the shape tests/test_web_policy_upload.py stages.
USER_POLICY = {
    "device": "somebody-elses-router",
    "policy_compliance": [
        {
            "description": "the finance host must not be reachable",
            "kind": "must_deny",
            "filter": "acl_in",
            "node": "somebody-elses-router",
            "queries": [{"dstIps": "10.99.0.7", "ipProtocols": ["tcp"]}],
            "violation_severity": "high",
            "violation_summary": "finance host is reachable",
        }
    ],
}


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    """Isolate the staged config and policy, and never leak an active policy.

    An installed policy outliving a test would silently apply to the next
    one -- the same failure `analyse()` guards against with its `finally`.
    """
    snapshot = tmp_path / "current"
    (snapshot / "configs").mkdir(parents=True)
    # The functions, not the old constants -- see #242. Storage resolves
    # per session now, so a module attribute would be shadowed and the
    # redirect would silently do nothing.
    monkeypatch.setattr(main, "snapshot_dir", lambda session_id=None: snapshot)
    monkeypatch.setattr(
        main, "configs_dir", lambda session_id=None: snapshot / "configs"
    )
    monkeypatch.setattr(
        main, "policy_path", lambda session_id=None: snapshot / "policy.json"
    )
    monkeypatch.setattr(main, "_uploaded", False)
    main._forget_analysis() if hasattr(main, "_forget_analysis") else None
    policy.clear_active_policy()
    yield
    policy.clear_active_policy()


def _upload_config(text=b"hostname rtr-us5\n"):
    return client.post("/api/upload",
                       files={"file": ("device.cfg", text, "text/plain")})


def _upload_policy(body=None):
    payload = json.dumps(body if body is not None else USER_POLICY).encode()
    return client.post("/api/policy",
                       files={"file": ("policy.json", payload,
                                       "application/json")})


#: A result the analysis cache will actually STORE.
#:
#: This detail matters more than it looks. The first version of this file
#: returned `[]` from the stub, and `_analysis_is_worth_caching([])` is
#: False -- an all-error or empty result is deliberately never cached. So
#: nothing was ever stored, the stale-hit these tests exist to catch could
#: not physically occur, and two mutations of the real cache key survived
#: the whole suite:
#:
#:     key on the config only          586 passed   NOT CAUGHT
#:     drop the policy from the key    586 passed   NOT CAUGHT
#:
#: The tests were green and asserting nothing about caching. Found by
#: mutating the real `web/main.py`, not by reading it.
CACHEABLE_RESULT = [
    {
        "id": "PC-000",
        "check": "policy_compliance",
        "severity": "info",
        "device": "rtr-us5",
        "summary": "no policy violations found",
        "evidence": {"detail": "stub result", "source": "test"},
        "status": "none",
    }
]


def _capture_what_a_check_would_see(monkeypatch):
    """Replace only `_analyse`, and record what the REAL check would read.

    Returns a dict that fills in when /api/findings is hit. The stub returns
    a CACHEABLE result on purpose -- see CACHEABLE_RESULT above.
    """
    seen = {}

    def fake_analyse(*_args, **_kwargs):
        # This runs at exactly the moment a real check would run: after
        # analyse() has installed the policy, before it clears it.
        rules, label, user_supplied = policy_compliance.rules_in_use()
        seen["rules"] = rules
        seen["label"] = label
        seen["user_supplied"] = user_supplied
        seen["active"] = policy.active_policy()
        seen["calls"] = seen.get("calls", 0) + 1
        return [dict(f) for f in CACHEABLE_RESULT]

    monkeypatch.setattr(pipeline, "_analyse", fake_analyse)
    return seen


# ---------------------------------------------------------------------------
# The join, from both ends
# ---------------------------------------------------------------------------


def test_without_a_policy_a_check_reads_our_built_in_rules(monkeypatch):
    """The before state. If this ever fails, the fallback is broken."""
    seen = _capture_what_a_check_would_see(monkeypatch)
    _upload_config()

    client.get("/api/findings")

    assert seen["user_supplied"] is False
    assert seen["active"] is None
    assert seen["rules"], "our built-in rules must still be used"


def test_an_uploaded_policy_changes_what_the_check_actually_reads(monkeypatch):
    """The whole feature, asserted where it matters.

    Not "analyse() received a policy" -- what `rules_in_use()` returns, which
    is what the check itself branches on.
    """
    seen = _capture_what_a_check_would_see(monkeypatch)
    _upload_config()
    assert _upload_policy().status_code == 200

    client.get("/api/findings")

    assert seen["user_supplied"] is True, (
        "the check must be reading the USER's rules, not ours"
    )
    assert seen["active"] is not None
    summaries = [r.get("violation_summary") for r in seen["rules"]]
    assert "finance host is reachable" in summaries, (
        "these are the uploaded rules, not our built-in ones"
    )


def test_the_policy_is_cleared_again_after_the_request(monkeypatch):
    """An installed policy must not outlive the analysis that installed it."""
    _capture_what_a_check_would_see(monkeypatch)
    _upload_config()
    _upload_policy()

    client.get("/api/findings")

    assert policy.active_policy() is None, (
        "a policy left installed would apply to the NEXT analysis, of a "
        "different config -- analyse()'s finally exists to prevent this"
    )


# ---------------------------------------------------------------------------
# The cache, which is the half that makes the feature silently inert
# ---------------------------------------------------------------------------


def test_uploading_a_policy_does_not_serve_the_pre_policy_result(monkeypatch):
    """THE BUG THIS FEATURE WOULD HAVE SHIPPED WITH.

    `_snapshot_fingerprint()` hashes `configs/`. POLICY_PATH sits BESIDE
    that directory, not inside it, so the config fingerprint cannot see a
    policy at all.

    Wiring the policy into analyse() without widening the cache key gives:

        upload config, scan   -> analysed and cached under K
        upload policy, scan   -> same K, so the PRE-POLICY findings are
                                 served and the policy appears to do nothing

    The user would see "policy accepted" and findings computed without it,
    which is worse than the feature not existing.
    """
    seen = _capture_what_a_check_would_see(monkeypatch)
    _upload_config()

    client.get("/api/findings")
    assert seen["user_supplied"] is False
    assert seen["calls"] == 1

    # Prove the first result really was cached, or the rest of this test is
    # asserting nothing -- which is exactly how the first version of it
    # passed against a broken cache key.
    client.get("/api/findings")
    assert seen["calls"] == 1, (
        "the second request should have been a cache hit; if it re-ran, "
        "this test cannot detect a stale hit and proves nothing"
    )

    _upload_policy()
    client.get("/api/findings")

    assert seen["calls"] == 2, (
        "the analysis was served from cache and never re-ran -- the policy "
        "was accepted and silently ignored"
    )
    assert seen["user_supplied"] is True


def test_the_cache_key_distinguishes_absent_present_and_edited_policies():
    """Three states, three keys. Directly, without the HTTP layer."""
    main.CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    (main.CONFIGS_DIR / "device.cfg").write_bytes(b"hostname rtr-us5\n")

    without = main._analysis_key()

    main.POLICY_PATH.write_bytes(json.dumps(USER_POLICY).encode())
    with_policy = main._analysis_key()

    edited = dict(USER_POLICY, device="a-third-router")
    main.POLICY_PATH.write_bytes(json.dumps(edited).encode())
    after_edit = main._analysis_key()

    assert len({without, with_policy, after_edit}) == 3, (
        "absent, present and edited must each produce a different key, or "
        "one of them serves another's cached findings"
    )


def test_an_unreadable_config_directory_still_disables_the_cache(monkeypatch):
    """Half a key is not a key.

    If the config half cannot be fingerprinted the cache must stay off,
    rather than keying on the policy alone -- which would make every
    snapshot sharing that policy share one entry.
    """
    monkeypatch.setattr(main, "_snapshot_fingerprint", lambda _d: None)
    assert main._analysis_key() is None


# ---------------------------------------------------------------------------
# The degraded path
# ---------------------------------------------------------------------------


def test_a_policy_that_will_not_load_falls_back_rather_than_500ing(monkeypatch):
    """A file corrupted between upload and scan must not take the page down.

    `/api/policy` validates before staging, so this should be unreachable --
    but "should be unreachable" is not a reason for an endpoint to raise.
    """
    seen = _capture_what_a_check_would_see(monkeypatch)
    _upload_config()
    _upload_policy()
    main.POLICY_PATH.write_bytes(b"{ this is not json")

    response = client.get("/api/findings")

    assert response.status_code == 200
    assert seen["user_supplied"] is False, (
        "falling back to our rules is correct here -- and every finding "
        "says which rules it used, so this is not a silent substitution"
    )
