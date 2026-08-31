"""Tests for the redacted, structured audit-log boundary.

The important assertion is not that an event exists. It is that a distinctive
piece of uploaded configuration and its filename do not appear in *any* record
emitted while the real upload endpoint handles them.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

from web import main
from web.audit_log import LOGGER_NAME, event


@pytest.fixture
def isolated_staging(monkeypatch, tmp_path):
    snapshot = tmp_path / "current"
    monkeypatch.setattr(main, "CONFIG_ROOT", tmp_path)
    monkeypatch.setattr(main, "SNAPSHOT_DIR", snapshot)
    monkeypatch.setattr(main, "CONFIGS_DIR", snapshot / "configs")
    monkeypatch.setattr(main, "POLICY_PATH", snapshot / "policy.json")
    monkeypatch.setattr(
        main, "BUSINESS_CONTEXT_PATH", snapshot / "business-context.json"
    )
    monkeypatch.setattr(main, "_uploaded", False)


def test_real_upload_log_is_structured_and_contains_no_config_content(
    caplog, isolated_staging
):
    secret = "UNIQUE-CONFIG-SECRET-do-not-log"
    filename = f"customer-{secret}.cfg"
    body = f"hostname {secret}\n! {secret}\n".encode()
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)

    response = TestClient(main.app).post(
        "/api/upload", files={"file": (filename, body, "text/plain")}
    )

    assert response.status_code == 200, response.text
    records = [record.getMessage() for record in caplog.records if record.name == LOGGER_NAME]
    assert len(records) == 1
    assert secret not in "\n".join(records)
    assert json.loads(records[0]) == {
        "converted": False,
        "event": "config_upload_accepted",
        "extension": ".cfg",
        "size_bytes": len(body),
        "skipped_count": 0,
    }


def test_logger_refuses_an_attempt_to_add_config_text(caplog):
    secret = "UNIQUE-CONFIG-SECRET-do-not-log"
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)

    with pytest.raises(ValueError, match="unsafe or invalid"):
        event(
            "config_upload_accepted",
            extension=secret,
            size_bytes=1,
            converted=False,
            skipped_count=0,
        )

    assert secret not in "\n".join(record.getMessage() for record in caplog.records)


def test_logger_refuses_an_unknown_field_before_emitting(caplog):
    """Pin the closed schema itself, not only validation of known values."""
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)

    with pytest.raises(ValueError, match="fields must be exactly"):
        event(
            "config_upload_accepted",
            extension=".cfg",
            size_bytes=1,
            converted=False,
            skipped_count=0,
            filename="would-be-a-leak.cfg",
        )

    assert caplog.records == []
