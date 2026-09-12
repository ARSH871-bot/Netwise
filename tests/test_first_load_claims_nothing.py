"""A session that has uploaded nothing must claim nothing.

WHAT THIS REPLACES
    `/api/findings` used to serve six invented findings to every first-time
    visitor, from `web/mock_findings.py`. Measured against the running app
    before the change:

        GET /api/findings   (fresh session, nothing uploaded)   200
          AC-001  found  Unencrypted web traffic reaches the internal server
          PC-000  none   No issues found by policy compliance
          RT-001  found  Guest subnet has no return route to the finance VLAN
          CH-000  error  Change impact check could not run
          AC-002  found  ACL line can never match
          RK-001  found  Internet-facing interface permits any source to any

    `PC-000` is the one that matters. `status="none"` means *we ran that
    check and it found nothing*. Nobody had run anything. F-4 exists so that
    "checked and found nothing" and "could not check" never look alike; an
    invented `none` is a third thing that looks like the first, and it was on
    the first screen every user saw.

    There was a test file for the mocks. It tested their SHAPE -- that they
    were valid F-1, that ids did not collide -- and its docstring called them
    "the first thing every user sees". The shape was never the problem.

THE INVARIANT THIS FILE EXISTS FOR
    The fix returns an empty list, and both the frontend and any API client
    now depend on `[]` meaning exactly one thing: nothing has been uploaded.

    That is only safe while a REAL analysis can never return an empty list.
    It cannot -- every registered check contributes a found, none or error
    finding, and `_every_check_failed()` emits one per check even when
    Batfish is unreachable. But this project does not trust an invariant it
    has not pinned, so `test_a_real_analysis_is_never_empty` pins it.

    If someone later makes `analyse()` able to return `[]`, that test fails,
    and it fails before anyone ships a screen that reads "0 problems found"
    for a scan that did not happen.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from web import main


@pytest.fixture(autouse=True)
def not_uploaded(monkeypatch):
    """A brand-new visitor: no upload anywhere in this process."""
    monkeypatch.setattr(main, "_uploaded", False)
    monkeypatch.setattr(main, "_uploaded_sessions", set())
    yield


def _first_load() -> List[Dict[str, Any]]:
    response = TestClient(main.app).get("/api/findings")
    assert response.status_code == 200
    return response.json()


class TestNothingIsClaimed:
    def test_first_load_returns_no_findings_at_all(self):
        assert _first_load() == [], (
            "a session that uploaded nothing returned findings. Whatever they "
            "say, they were not measured from anybody's configuration."
        )

    def test_no_fabricated_clean_result(self):
        """The specific defect: an invented `status="none"`.

        This is the assertion that would have caught `PC-000`. A green tick
        nobody earned is worse than a false alarm -- a false alarm gets
        investigated.
        """
        assert not [f for f in _first_load() if f.get("status") == "none"], (
            "first load claimed a check ran and found nothing"
        )

    def test_no_fabricated_problem(self):
        assert not [f for f in _first_load() if f.get("status") == "found"], (
            "first load claimed a problem in a network nobody uploaded"
        )

    def test_the_mock_module_is_gone(self):
        """Deleted rather than left unimported.

        A module nothing imports is a module somebody re-imports. The
        fabricated findings should not be one edit away from returning.
        """
        with pytest.raises(ImportError):
            __import__("web.mock_findings")


class TestTheInvariantTheFixRestsOn:
    """`[]` must mean "nothing uploaded", and never "scanned, all clear"."""

    def test_a_real_analysis_is_never_empty(self, monkeypatch):
        """Even with every check failing, one finding per check is emitted.

        Batfish unreachable is the most common operational failure and the
        one most likely to produce an empty result by accident. If it ever
        does, `[]` becomes ambiguous and the frontend's "nothing uploaded
        yet" panel starts appearing after a scan that really ran.
        """
        from analysis import pipeline

        def refuse(host=None, **kwargs):
            raise ConnectionError("Batfish is not running")

        monkeypatch.setattr(pipeline, "connect", refuse)

        results = pipeline.analyse("tests/fixtures/rtr-us5-insecure")
        assert results, (
            "analyse() returned an empty list when Batfish was down. `[]` now "
            "means 'nothing uploaded' to both the frontend and any API "
            "client, so this would render a failed scan as a fresh session."
        )
        assert all(f["status"] == "error" for f in results), (
            "a failed analysis produced something other than error findings"
        )

    def test_every_registered_check_is_represented_when_nothing_runs(
            self, monkeypatch):
        """One finding per check, not one overall.

        A check absent from the results looks identical to one that passed.
        """
        from analysis import pipeline

        def refuse(host=None, **kwargs):
            raise ConnectionError("Batfish is not running")

        monkeypatch.setattr(pipeline, "connect", refuse)

        results = pipeline.analyse("tests/fixtures/rtr-us5-insecure")
        reported = {f["check"] for f in results}
        assert set(pipeline.CHECKS) <= reported, (
            f"checks missing from a failed run: "
            f"{sorted(set(pipeline.CHECKS) - reported)}"
        )
