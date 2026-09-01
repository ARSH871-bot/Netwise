"""
Netwise -- tests for web/main.py's _attach_remediation() (#221).

WHY THIS IS ITS OWN FILE, NOT AN ADDITION TO test_web_findings_explanation.py
    Same reasoning as tests/test_remediation_text.py: a different claim
    ("what would fix this" vs. "what does this mean"), tested against a
    genuinely different function, even though the two functions share a
    shape. Keeping them separate means a change to one's assumptions cannot
    silently affect the other's coverage.

THE ONE REAL DIFFERENCE FROM _attach_explanations()'s OWN TESTS
    explain_with_source() always returns a (text, source) pair -- explain()
    always has SOMETHING to say, worst case the finding's own summary
    restated. remediate_with_source() can return None outright, when no
    known evidence shape matched. So "a found finding whose evidence does
    not match a known shape" is its own case here, not covered by anything
    in the explanation tests: the two keys must simply be absent, the same
    outcome as a "none"/"error" finding, for a different reason.

RUN
    pytest tests/ -v
"""

from web import main


def _finding(status: str, **overrides) -> dict:
    base = {
        "id": "AC-001",
        "check": "access_control",
        "severity": "high",
        "device": "rtr-us5",
        "summary": "A finding",
        "evidence": {"detail": "some evidence", "source": "rtr-us5:acl_in"},
        "status": status,
    }
    base.update(overrides)
    return base


# --- Which findings get remediation text -------------------------------------


def test_a_found_finding_with_a_matching_shape_gets_remediation(monkeypatch):
    monkeypatch.setattr(
        main, "remediate_with_source", lambda finding: ("Change the rule.", "deterministic")
    )
    results = main._attach_remediation([_finding("found")])
    assert results[0]["remediation"] == "Change the rule."
    assert results[0]["remediation_source"] == "deterministic"


def test_a_found_finding_with_no_matching_shape_gets_neither_key(monkeypatch):
    """The real behaviour on most findings today, given the measured
    coverage in ai/explain.py's own section-1d comment -- not every found
    finding matches one of the three known shapes, and this must not
    manufacture a key for the ones that do not."""
    monkeypatch.setattr(main, "remediate_with_source", lambda finding: None)
    results = main._attach_remediation([_finding("found")])
    assert "remediation" not in results[0]
    assert "remediation_source" not in results[0]


def test_a_none_finding_is_never_asked_for_remediation(monkeypatch):
    calls = []
    monkeypatch.setattr(
        main, "remediate_with_source",
        lambda finding: (calls.append(finding), None)[1],
    )
    results = main._attach_remediation([_finding("none")])
    assert "remediation" not in results[0]
    assert calls == []


def test_an_error_finding_is_never_asked_for_remediation(monkeypatch):
    """No real Batfish output to ground a fix in -- same reasoning
    _attach_explanations() already applies to "error" findings."""
    calls = []
    monkeypatch.setattr(
        main, "remediate_with_source",
        lambda finding: (calls.append(finding), None)[1],
    )
    results = main._attach_remediation([_finding("error")])
    assert "remediation" not in results[0]
    assert calls == []


# --- Failure isolation --------------------------------------------------------
# remediate_with_source() is documented never to raise, but this boundary
# does not own that guarantee -- same reasoning _attach_explanations() tests
# this as if it could be wrong.


def test_a_failed_remediation_is_omitted_not_an_exception(monkeypatch):
    def explodes(finding):
        raise RuntimeError("regex blew up")

    monkeypatch.setattr(main, "remediate_with_source", explodes)
    results = main._attach_remediation([_finding("found")])
    assert results[0]["status"] == "found", "the finding itself must still be returned"
    assert "remediation" not in results[0]
    assert "remediation_source" not in results[0]


def test_one_failed_remediation_does_not_affect_the_others(monkeypatch):
    def maybe_explode(finding):
        if finding["id"] == "AC-001":
            raise RuntimeError("boom")
        return "a real fix", "deterministic"

    monkeypatch.setattr(main, "remediate_with_source", maybe_explode)
    results = main._attach_remediation(
        [_finding("found", id="AC-001"), _finding("found", id="AC-002")]
    )
    assert "remediation" not in results[0]
    assert results[1]["remediation"] == "a real fix"


# --- The response still validates as F-1, plus the two new keys --------------


def test_the_finding_itself_is_unchanged_apart_from_the_new_keys(monkeypatch):
    monkeypatch.setattr(
        main, "remediate_with_source", lambda finding: ("fix it", "deterministic")
    )
    finding = _finding("found")
    original = dict(finding)
    (result,) = main._attach_remediation([finding])
    for key, value in original.items():
        assert result[key] == value
    assert result["remediation"] == "fix it"
    assert result["remediation_source"] == "deterministic"


def test_does_not_mutate_the_caller_s_dicts():
    """Same #92b reasoning _attach_explanations() already carries: the
    caller's list may be the cached analyse() result, so the input must
    come out of this function exactly as it went in."""
    finding = _finding("found", evidence={
        "detail": "Expected DENY but got PERMIT, decided by: permit ip any any",
        "source": "rtr-us5:acl_in",
    })
    original = dict(finding)
    original_evidence = dict(finding["evidence"])

    main._attach_remediation([finding])

    assert finding == original
    assert finding["evidence"] == original_evidence
    assert "remediation" not in finding


# --- remediation_source ------------------------------------------------------


def test_a_deterministic_remediation_reports_deterministic_as_the_source(monkeypatch):
    monkeypatch.setattr(
        main, "remediate_with_source", lambda finding: ("text", "deterministic")
    )
    (result,) = main._attach_remediation([_finding("found")])
    assert result["remediation_source"] == "deterministic"


# --- The /api/findings endpoint itself ----------------------------------------


def test_mock_findings_are_never_given_remediation(monkeypatch):
    """Same reasoning as mock findings never being explained (#31): #221's
    remediation text is about a real finding from a real uploaded config,
    not fabricated demo data."""
    from fastapi.testclient import TestClient

    calls = []
    monkeypatch.setattr(
        main, "remediate_with_source",
        lambda finding: (calls.append(finding), None)[1],
    )
    monkeypatch.setattr(main, "_uploaded", False)

    client = TestClient(main.app)
    response = client.get("/api/findings")

    assert response.status_code == 200
    assert calls == []
    assert all("remediation" not in f for f in response.json())
    assert all("remediation_source" not in f for f in response.json())


def test_remediation_is_included_in_the_downstream_keys_list():
    """The actual report-stripping behaviour is tested where the mechanism
    lives -- tests/test_report_export.py's
    test_no_dashboard_only_text_leaks_into_either_format(), extended to also
    set remediation keys. A test here that monkeypatched
    remediate_with_source() and hit /api/report would be testing whether
    mock findings get remediation (they do not, see the test above), not
    whether the report strips it -- exactly the "a test named for a property
    it cannot observe" trap that existing test's own docstring already
    documents having fallen into once, for explanation."""
    assert "remediation" in main._DOWNSTREAM_KEYS
    assert "remediation_source" in main._DOWNSTREAM_KEYS
