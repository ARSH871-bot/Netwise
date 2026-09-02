"""
Netwise -- tests for web/main.py's _attach_explanations() (US-19 / #31).

WHY THESE TESTS EXIST
    _attach_explanations() is the seam between the AI layer and the
    dashboard: it decides which findings get a plain-English explanation,
    and what happens if generating one fails. Both are pure logic over a
    list of dicts -- no Batfish, no Ollama, no HTTP -- so they are tested
    directly here the same way every other pure-logic module in this repo
    is, by monkeypatching web.main.explain_with_source rather than needing
    a real model running.

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


# --- Which findings get explained -------------------------------------------


def test_a_found_finding_gets_an_explanation(monkeypatch):
    monkeypatch.setattr(
        main, "explain_with_source", lambda finding: ("A plain-English explanation.", "model")
    )
    results = main._attach_explanations([_finding("found")])
    assert results[0]["explanation"] == "A plain-English explanation."


def test_a_none_finding_is_not_explained(monkeypatch):
    """A "none" finding has nothing to explain beyond its own summary --
    static/app.js's rendering encodes the same rule for which cards get
    the slot at all, this keeps the two in agreement."""
    calls = []
    monkeypatch.setattr(
        main, "explain_with_source",
        lambda finding: (calls.append(finding), ("unused", "model"))[1],
    )
    results = main._attach_explanations([_finding("none")])
    assert "explanation" not in results[0]
    assert calls == []


def test_an_error_finding_is_not_explained(monkeypatch):
    """An "error" finding has no real Batfish output to ground an
    explanation in -- asking the model to write prose about a check that
    never ran is exactly the invented-network-behaviour failure CLAUDE.md
    constraint 2 forbids."""
    calls = []
    monkeypatch.setattr(
        main, "explain_with_source",
        lambda finding: (calls.append(finding), ("unused", "model"))[1],
    )
    results = main._attach_explanations([_finding("error")])
    assert "explanation" not in results[0]
    assert calls == []


# --- Failure isolation --------------------------------------------------------
# ai/explain.py's own module docstring guarantees explain_with_source() never
# raises, but this boundary does not own that guarantee, so it is tested here
# as if it could be wrong -- the same reasoning analysis.pipeline.run_check()
# already applies to one check's crash not breaking the other three, one
# layer out.


def test_a_failed_explanation_is_omitted_not_an_exception(monkeypatch):
    def explodes(finding):
        raise RuntimeError("Ollama said no")

    monkeypatch.setattr(main, "explain_with_source", explodes)
    results = main._attach_explanations([_finding("found")])
    assert results[0]["status"] == "found", "the finding itself must still be returned"
    assert "explanation" not in results[0]
    assert "explanation_source" not in results[0]


def test_one_failed_explanation_does_not_affect_the_others(monkeypatch):
    def maybe_explode(finding):
        if finding["id"] == "AC-001":
            raise RuntimeError("boom")
        return "a real explanation", "model"

    monkeypatch.setattr(main, "explain_with_source", maybe_explode)
    results = main._attach_explanations(
        [_finding("found", id="AC-001"), _finding("found", id="AC-002")]
    )
    assert "explanation" not in results[0]
    assert results[1]["explanation"] == "a real explanation"


# --- The response still validates as F-1, plus the two new keys --------------


def test_the_finding_itself_is_unchanged_apart_from_the_new_keys(monkeypatch):
    """_attach_explanations() must not touch any existing F-1 field -- the
    explanation and its source are additive, not a replacement for anything
    the pipeline already produced."""
    monkeypatch.setattr(main, "explain_with_source", lambda finding: ("explained", "model"))
    finding = _finding("found")
    original = dict(finding)
    (result,) = main._attach_explanations([finding])
    for key, value in original.items():
        assert result[key] == value
    assert result["explanation"] == "explained"
    assert result["explanation_source"] == "model"


# --- explanation_source (#109) ------------------------------------------------
# The dashboard's "AI explanation" byline is unconditional today, and had no
# way to tell a genuine model response apart from deterministic fallback
# text. This key is the fix, attached the same way "explanation" already is:
# downstream of F-1 validation, never a new field in the contract itself.


def test_a_model_explanation_reports_model_as_the_source(monkeypatch):
    monkeypatch.setattr(main, "explain_with_source", lambda finding: ("text", "model"))
    (result,) = main._attach_explanations([_finding("found")])
    assert result["explanation_source"] == "model"


def test_a_fallback_explanation_reports_fallback_as_the_source(monkeypatch):
    monkeypatch.setattr(main, "explain_with_source", lambda finding: ("text", "fallback"))
    (result,) = main._attach_explanations([_finding("found")])
    assert result["explanation_source"] == "fallback"


def test_a_refused_remote_model_is_explained_on_the_dashboard(monkeypatch):
    """The privacy guard is visible, not merely an invisible fallback."""
    monkeypatch.setattr(main, "explain_with_source", lambda finding: ("text", "fallback"))
    monkeypatch.setattr(
        main,
        "local_model_boundary_notice",
        lambda: "Local-model safety: Netwise did not send config-derived evidence.",
    )

    (result,) = main._attach_explanations([_finding("found")])

    assert result["explanation_notice"] == (
        "Local-model safety: Netwise did not send config-derived evidence."
    )


def test_a_model_explanation_has_no_remote_host_notice(monkeypatch):
    monkeypatch.setattr(main, "explain_with_source", lambda finding: ("text", "model"))
    monkeypatch.setattr(
        main,
        "local_model_boundary_notice",
        lambda: "this would be wrong on a model explanation",
    )

    (result,) = main._attach_explanations([_finding("found")])

    assert "explanation_notice" not in result


def test_a_none_finding_gets_neither_key(monkeypatch):
    calls = []
    monkeypatch.setattr(
        main, "explain_with_source",
        lambda finding: (calls.append(finding), ("unused", "model"))[1],
    )
    (result,) = main._attach_explanations([_finding("none")])
    assert "explanation" not in result
    assert "explanation_source" not in result


# --- The /api/findings endpoint itself ----------------------------------------


def test_mock_findings_are_never_explained(monkeypatch):
    """#31's acceptance criterion is about a real finding from a real
    uploaded config. Explaining fabricated demo data risks a viewer
    mistaking a rephrased invention for a rephrased fact -- exactly the
    distinction this project exists to keep clear."""
    from fastapi.testclient import TestClient

    calls = []
    monkeypatch.setattr(
        main, "explain_with_source",
        lambda finding: (calls.append(finding), ("unused", "model"))[1],
    )
    monkeypatch.setattr(main, "_uploaded", False)

    client = TestClient(main.app)
    response = client.get("/api/findings")

    assert response.status_code == 200
    assert calls == []
    assert all("explanation" not in f for f in response.json())
    assert all("explanation_source" not in f for f in response.json())
