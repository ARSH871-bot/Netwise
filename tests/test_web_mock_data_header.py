"""Netwise -- /api/findings marks mock data with a response header (#87-adjacent
UX gap, found while testing propose-a-change).

WHY THIS EXISTS
    Before this, nothing on the live dashboard ever said the findings shown
    before any upload are invented demo data rather than a real scan --
    only a downloaded report's subject line ever admitted it ("example
    findings (no upload yet)"), and nobody sees that before uploading
    anything. A first-time visitor could reasonably believe mock findings
    are a real result, which is exactly the kind of thing F-4 exists to
    prevent one layer up (findings themselves, not the fact that a whole
    response is invented).

WHY A HEADER, NOT A FIELD IN THE JSON BODY
    /api/findings returns a bare F-1 list, and every existing caller --
    download_report() calling it directly, the dashboard's own
    loadFindings() -- expects exactly that shape. A header carries the
    fact without changing what the body means.

RUN
    pytest tests/ -v
"""

from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


def test_mock_data_is_flagged_before_any_upload(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", False)
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.headers.get("x-netwise-mock-data") == "true"


def test_real_findings_carry_no_mock_header(monkeypatch):
    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(main, "_cached_analysis", lambda key: [])
    monkeypatch.setattr(main, "_remember_analysis", lambda key, results: None)
    monkeypatch.setattr(
        main.analysis_pipeline, "analyse", lambda *a, **k: []
    )

    response = client.get("/api/findings")

    assert response.status_code == 200
    assert "x-netwise-mock-data" not in response.headers


def test_get_findings_still_works_as_a_plain_python_call(monkeypatch):
    """download_report() calls get_findings() directly, with no Response for
    FastAPI to inject -- the whole reason the parameter defaults to None.
    A regression here would not show up in an HTTP test, only in a direct
    call exactly like the one that already exists in this file."""
    monkeypatch.setattr(main, "_uploaded", False)
    results = main.get_findings()
    assert isinstance(results, list)
    assert len(results) > 0
