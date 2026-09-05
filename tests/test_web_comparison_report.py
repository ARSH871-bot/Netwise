"""Netwise -- tests for POST /api/propose/comparison-report.

WHY THIS EXISTS
    Downloading a comparison must never re-run the scan it is downloading
    -- see the endpoint's own docstring for why (a full scan costs real
    seconds to minutes, and the browser already has the exact split it
    rendered on screen). So this endpoint takes already-computed data and
    only renders it; these tests exist to pin that the validation on that
    data is real, not decorative, and that a malformed payload is a 422
    naming what was wrong rather than a 500.

RUN
    pytest tests/ -v
"""

import json

from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)

INTRODUCED = [{
    "id": "AC-002", "check": "access_control", "severity": "high",
    "device": "rtr-us5", "status": "found", "summary": "A new problem",
    "evidence": {"detail": "permit ip any any", "source": "rtr-us5:acl_in"},
}]
RESOLVED = [{
    "id": "AC-001", "check": "access_control", "severity": "high",
    "device": "rtr-us5", "status": "found", "summary": "A fixed problem",
    "evidence": {"detail": "was: permit ip any any", "source": "rtr-us5:acl_in"},
}]


def _payload(**overrides):
    base = {
        "introduced": INTRODUCED,
        "resolved": RESOLVED,
        "unchanged_count": 3,
        "description": "block any to 10.20.0.5 on tcp/80 on rtr-us5",
    }
    base.update(overrides)
    return base


def test_html_download_is_a_real_attachment():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload()), "format": "html"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert disposition.endswith('.html"')
    assert "<!doctype html>" in response.text
    assert "block any to 10.20.0.5 on tcp/80 on rtr-us5" in response.text


def test_csv_download_is_a_real_attachment():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload()), "format": "csv"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert disposition.endswith('.csv"')
    assert "change_type" in response.text
    assert "AC-002" in response.text
    assert "AC-001" in response.text


def test_unknown_format_is_a_400():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload()), "format": "pdf"},
    )
    assert response.status_code == 400


def test_invalid_json_is_a_422_not_a_500():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": "not json at all {{{", "format": "html"},
    )
    assert response.status_code == 422
    assert "not valid JSON" in response.json()["detail"]


def test_json_that_is_not_an_object_is_a_422():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps([1, 2, 3]), "format": "html"},
    )
    assert response.status_code == 422


def test_missing_introduced_is_a_422():
    payload = _payload()
    del payload["introduced"]
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(payload), "format": "html"},
    )
    assert response.status_code == 422
    assert "introduced" in response.json()["detail"]


def test_introduced_not_a_list_of_dicts_is_a_422():
    response = client.post(
        "/api/propose/comparison-report",
        data={
            "findings_json": json.dumps(_payload(introduced=["not", "a", "dict"])),
            "format": "html",
        },
    )
    assert response.status_code == 422


def test_negative_unchanged_count_is_a_422():
    """A count that can never be negative in reality (there is no such
    thing as -1 unaffected findings) is still worth rejecting explicitly
    rather than rendering "unaffected: -1", which would look like a bug in
    the product rather than in the request."""
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(unchanged_count=-1)), "format": "html"},
    )
    assert response.status_code == 422


def test_a_bool_for_unchanged_count_is_rejected():
    """bool is a subclass of int in Python -- isinstance(True, int) is True
    -- so this guard has to reject it explicitly or a JSON `true` would
    silently render as the count 1."""
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(unchanged_count=True)), "format": "html"},
    )
    assert response.status_code == 422


def test_empty_description_is_a_422():
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(description="")), "format": "html"},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# introduced/resolved must be status="found" only (#298 review)
#
# The browser's own diffFindings() filters to status="found" before ever
# building this payload, but this is a real POST endpoint a request can
# still reach directly -- and the artefact this produces is what a reader
# keeps after the screen is gone. A status="none"/"error" finding here is a
# status TRANSITION, not a problem introduced or resolved, and rendering it
# under either heading is exactly the bug review caught in app.js.
# ---------------------------------------------------------------------------


def test_a_none_status_finding_in_resolved_is_a_422():
    """The exact shape @shubhamkataria2005 found: a check going clean is not
    the same claim as a problem being fixed."""
    resolved = [{
        "id": "PC-000", "check": "policy_compliance", "severity": "low",
        "device": "rtr-us5", "status": "none",
        "summary": "All 3 policy rules hold on rtr-us5",
        "evidence": {"detail": "3/3 rules satisfied", "source": "policy_compliance"},
    }]
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(resolved=resolved)), "format": "html"},
    )
    assert response.status_code == 422
    assert "status=\"found\"" in response.json()["detail"]


def test_an_error_status_finding_in_introduced_is_a_422():
    """The exact shape @ARSH871-bot found: a check going blind is not the
    same claim as a new problem being introduced."""
    introduced = [{
        "id": "PC-000", "check": "policy_compliance", "severity": "high",
        "device": "rtr-us5", "status": "error",
        "summary": "Could not check rtr-us5: the proposed ACL failed to parse",
        "evidence": {"detail": "parse error", "source": "policy_compliance"},
    }]
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(introduced=introduced)), "format": "html"},
    )
    assert response.status_code == 422
    assert "status=\"found\"" in response.json()["detail"]


def test_a_found_only_payload_still_succeeds():
    """The guard above must reject the bad shape without also rejecting the
    ordinary, correct one -- both introduced and resolved here are
    status="found", matching every real payload the browser now sends."""
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload()), "format": "html"},
    )
    assert response.status_code == 200


def test_hostile_evidence_survives_as_text_not_markup_in_the_html_download():
    hostile = [{
        "id": "AC-003", "check": "access_control", "severity": "high",
        "device": "rtr-us5", "status": "found",
        "summary": "<script>alert(1)</script>",
        "evidence": {"detail": "<script>alert(2)</script>", "source": "s"},
    }]
    response = client.post(
        "/api/propose/comparison-report",
        data={"findings_json": json.dumps(_payload(introduced=hostile)), "format": "html"},
    )
    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text
