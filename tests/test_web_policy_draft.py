"""Downloading a policy drafted from the staged config (#326, US-34).

The drafting itself is tested in tests/test_draft_policy.py. This file tests
the join between it and the dashboard: that the endpoint drafts from THIS
session's staged config, hands back a file rather than applying anything,
says what it was drafted from, and fails with a reason rather than a 500.

The last test drives the whole path against real Batfish, including the
refusal the user meets if they upload the draft without deciding it.
"""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analysis import draft_policy
from conftest import needs_batfish
from web import main

client = TestClient(main.app)

FAKE_DRAFT = {
    "draft": {"summary": "1 rule(s) drafted; 0 item(s) not drafted, listed below.",
              "not_drafted": []},
    "policy_compliance": [{"description": "rtr-us5 acl_in line 1: permit ip any any"}],
}


@pytest.fixture(autouse=True)
def snapshot(tmp_path, monkeypatch):
    """A staged config in a temporary session folder, and nothing else."""
    root = tmp_path / "current"
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "rtr-us5.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")
    monkeypatch.setattr(main, "snapshot_dir", lambda session_id=None: root)
    monkeypatch.setattr(main, "configs_dir", lambda session_id=None: root / "configs")
    monkeypatch.setattr(main, "_uploaded", True)
    return root


def _fake_batfish(monkeypatch, fail=None):
    """Stub the three calls that need Batfish. Returns the paths loaded."""
    loaded = []

    def connect(*_args, **_kwargs):
        if fail is not None:
            raise fail
        return "a session"

    monkeypatch.setattr(main.analysis_pipeline, "connect", connect)
    monkeypatch.setattr(main.analysis_pipeline, "load_snapshot",
                        lambda bf, path, network, name: loaded.append(Path(path)))
    monkeypatch.setattr(draft_policy, "draft_policy", lambda bf: copy.deepcopy(FAKE_DRAFT))
    return loaded


def test_nothing_uploaded_is_refused_with_a_reason(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    monkeypatch.setattr(main, "_uploaded_sessions", set())
    response = client.get("/api/policy/draft")
    assert response.status_code == 409
    assert "Upload a config first" in response.json()["detail"]


def test_the_draft_downloads_as_a_json_attachment_drafted_from_this_sessions_config(
        monkeypatch, snapshot):
    loaded = _fake_batfish(monkeypatch)
    response = client.get("/api/policy/draft")
    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="netwise-draft-policy-')
    assert disposition.endswith('.json"')
    assert response.json()["policy_compliance"] == FAKE_DRAFT["policy_compliance"]
    assert loaded == [snapshot]


def test_the_draft_names_the_files_it_was_drafted_from(monkeypatch):
    """And says what that name IS. The dashboard stages an upload under its
    own name (device.cfg), never the client's, so every citation names a
    file the user never saw unless the draft says it is theirs. Found in a
    real browser on 30 September: the user uploaded rtr-us5.cfg and the
    draft cited configs/device.cfg:[24]."""
    _fake_batfish(monkeypatch)
    drafted_from = client.get("/api/policy/draft").json()["draft"]["drafted_from"]
    assert drafted_from.startswith("rtr-us5.cfg -- ")
    assert "the file you uploaded" in drafted_from
    # A converted PF Sense export is cited in the converted Cisco text.
    assert "PF Sense" in drafted_from and "not of your XML" in drafted_from


def test_a_draft_of_the_sample_network_says_so_in_the_file(monkeypatch, snapshot):
    """#347's rule: a file that outlives the tab must carry the label."""
    _fake_batfish(monkeypatch)
    (snapshot / "is-sample.marker").write_text("", encoding="utf-8")
    drafted_from = client.get("/api/policy/draft").json()["draft"]["drafted_from"]
    assert drafted_from.startswith("SAMPLE NETWORK")


def test_batfish_unreachable_is_a_503_carrying_the_reason(monkeypatch):
    _fake_batfish(monkeypatch, fail=ConnectionError("nothing is listening on localhost:9996"))
    response = client.get("/api/policy/draft")
    assert response.status_code == 503
    assert "nothing is listening on localhost:9996" in response.json()["detail"]


def test_drafting_stages_nothing_and_leaves_a_staged_policy_alone(monkeypatch, snapshot):
    """'Never applied automatically', at the web layer: the draft is handed
    to the user as a file. A policy already staged is not replaced."""
    _fake_batfish(monkeypatch)
    assert not main.policy_path().exists()
    client.get("/api/policy/draft")
    assert not main.policy_path().exists()

    main.policy_path().write_text('{"policy_compliance": []}', encoding="utf-8")
    client.get("/api/policy/draft")
    assert main.policy_path().read_text(encoding="utf-8") == '{"policy_compliance": []}'


@needs_batfish
def test_real_draft_is_refused_on_upload_until_decided(snapshot):
    """The whole path a user takes, against real Batfish: draft, upload it
    unedited and be refused, decide it, upload it and be accepted."""
    shutil.copy(Path(__file__).parent / "fixtures" / "rtr-us5-secure" / "configs" / "rtr-us5.cfg",
                snapshot / "configs" / "rtr-us5.cfg")
    draft = client.get("/api/policy/draft").json()
    assert len(draft["policy_compliance"]) == 2

    def upload(data):
        import json
        return client.post("/api/policy", files={
            "file": ("draft.json", json.dumps(data).encode("utf-8"), "application/json")})

    refused = upload(draft)
    assert refused.status_code == 400
    assert "not been reviewed" in refused.json()["detail"]
    assert "4 decision(s)" in refused.json()["detail"]

    draft.pop("draft")
    for rule in draft["policy_compliance"]:
        rule["kind"] = "requirement"
        rule["violation_severity"] = "medium"
    assert upload(draft).status_code == 200
