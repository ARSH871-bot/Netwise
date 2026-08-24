"""tests/test_live_check.py -- tools/live_check.py

Same split as tests/test_preflight.py: the AGGREGATION logic (run(), the
exit code, the summary line) is pure and tested by monkeypatching CHECKS
with fakes; the individual checks that touch Batfish/Ollama are tested by
monkeypatching the real calls they make, so this file needs neither Docker
nor a running Batfish/Ollama -- the same guarantee the rest of the suite
gives (CLAUDE.md section 7b).

RUN
    pytest tests/test_live_check.py -v
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tools import live_check


# ---------------------------------------------------------------------------
# _by_status -- pure grouping logic
# ---------------------------------------------------------------------------


def test_by_status_groups_and_sorts_ids():
    findings = [
        {"id": "PC-002", "status": "found"},
        {"id": "AC-001", "status": "found"},
        {"id": "RT-050", "status": "error"},
    ]
    assert live_check._by_status(findings) == {
        "found": ["AC-001", "PC-002"],
        "error": ["RT-050"],
    }


def test_by_status_on_an_empty_list_is_an_empty_dict():
    assert live_check._by_status([]) == {}


# ---------------------------------------------------------------------------
# run() -- the aggregation logic, exercised with fakes (same pattern as
# test_preflight.py's _fake helper)
# ---------------------------------------------------------------------------


def _fake(label: str, status: str, detail: str = "detail"):
    return lambda: (label, status, detail)


def test_all_passing_is_success(monkeypatch, capsys):
    monkeypatch.setattr(
        live_check, "CHECKS",
        [_fake("A", live_check.PASS), _fake("B", live_check.PASS)],
    )

    assert live_check.run() == 0
    assert "PASSED -- every layer" in capsys.readouterr().out


def test_a_failing_check_exits_nonzero_and_is_named(monkeypatch, capsys):
    monkeypatch.setattr(
        live_check, "CHECKS",
        [_fake("A", live_check.PASS), _fake("Batfish connection", live_check.FAIL)],
    )

    code = live_check.run()
    out = capsys.readouterr().out

    assert code == 1
    assert "FAILED" in out
    assert "Batfish connection" in out, "must name which layer failed"


def test_a_failure_is_not_masked_by_healthy_ones(monkeypatch, capsys):
    """One bad layer among several good ones -- the failure mode a summary
    line can hide if it only counts, rather than lists, what failed."""
    monkeypatch.setattr(
        live_check, "CHECKS",
        [
            _fake("A", live_check.PASS),
            _fake("B", live_check.FAIL),
            _fake("C", live_check.PASS),
        ],
    )

    assert live_check.run() == 1
    assert "FAILED" in capsys.readouterr().out


def test_the_detail_is_printed_for_a_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        live_check, "CHECKS",
        [_fake("Pipeline (violating fixture)", live_check.FAIL,
               "expected AC-001 found, got nothing")],
    )

    live_check.run()

    assert "expected AC-001 found, got nothing" in capsys.readouterr().out


def test_every_check_is_registered_and_returns_the_documented_shape_of_name():
    """Not a live run -- just confirms CHECKS holds real callables with
    real names, so a typo in the registry list fails here rather than
    silently dropping a layer from the sweep."""
    names = [check.__name__ for check in live_check.CHECKS]
    assert names == [
        "check_batfish_connection",
        "check_pipeline_on_a_violating_fixture",
        "check_pipeline_on_a_clean_fixture",
        "check_explanation_layer",
        "check_query_layer",
    ]


# ---------------------------------------------------------------------------
# check_batfish_connection
# ---------------------------------------------------------------------------


def test_batfish_connection_passes_when_connect_and_load_succeed():
    with patch("analysis.pipeline.connect", return_value="fake-session"), \
         patch("analysis.pipeline.load_snapshot"):
        label, status, detail = live_check.check_batfish_connection()

    assert status == live_check.PASS
    assert "connected" in detail


def test_batfish_connection_fails_without_raising_when_connect_errors():
    with patch("analysis.pipeline.connect", side_effect=RuntimeError("refused")):
        label, status, detail = live_check.check_batfish_connection()

    assert status == live_check.FAIL
    assert "refused" in detail
    assert "preflight" in detail, "should point at the readiness tool, not just fail"


# ---------------------------------------------------------------------------
# check_pipeline_on_a_violating_fixture / check_pipeline_on_a_clean_fixture
# ---------------------------------------------------------------------------


def _findings(spec):
    """spec: {"found": ["AC-001", ...], "error": [...]}"""
    out = []
    for status, ids in spec.items():
        for finding_id in ids:
            out.append({"id": finding_id, "status": status})
    return out


def test_violating_fixture_passes_when_it_matches_the_measured_shape():
    with patch("analysis.pipeline.analyse",
               return_value=_findings(live_check.EXPECTED_INSECURE)):
        label, status, detail = live_check.check_pipeline_on_a_violating_fixture()

    assert status == live_check.PASS


def test_violating_fixture_fails_when_a_finding_goes_missing():
    """The exact regression this check exists to catch: a check that
    should find a real violation stops finding it."""
    fewer = {"found": ["AC-001", "AC-002", "PC-001", "PC-002"], "error": ["RT-050"]}
    with patch("analysis.pipeline.analyse", return_value=_findings(fewer)):
        label, status, detail = live_check.check_pipeline_on_a_violating_fixture()

    assert status == live_check.FAIL
    assert "PC-003" in detail or "expected" in detail


def test_violating_fixture_fails_without_raising_when_analyse_errors():
    with patch("analysis.pipeline.analyse", side_effect=RuntimeError("boom")):
        label, status, detail = live_check.check_pipeline_on_a_violating_fixture()

    assert status == live_check.FAIL
    assert "boom" in detail


def test_clean_fixture_passes_when_it_matches_the_measured_shape():
    with patch("analysis.pipeline.analyse",
               return_value=_findings(live_check.EXPECTED_SECURE)):
        label, status, detail = live_check.check_pipeline_on_a_clean_fixture()

    assert status == live_check.PASS


def test_clean_fixture_fails_when_it_reports_a_violation_it_should_not():
    """The other direction: a check that always reports a problem,
    regardless of the config, would pass the violating-fixture check and
    fail silently here if this test did not exist."""
    wrong = {"found": ["AC-001"], "none": ["PC-000"], "error": ["RT-050"]}
    with patch("analysis.pipeline.analyse", return_value=_findings(wrong)):
        label, status, detail = live_check.check_pipeline_on_a_clean_fixture()

    assert status == live_check.FAIL


# ---------------------------------------------------------------------------
# check_explanation_layer
# ---------------------------------------------------------------------------


def test_explanation_layer_passes_on_a_valid_model_or_fallback_result():
    found_findings = _findings({"found": ["AC-001"], "error": ["RT-050"]})
    with patch("analysis.pipeline.analyse", return_value=found_findings), \
         patch("ai.explain.explain_with_source", return_value=("some text", "fallback")):
        label, status, detail = live_check.check_explanation_layer()

    assert status == live_check.PASS
    assert "fallback" in detail


def test_explanation_layer_fails_without_raising_when_explain_raises():
    found_findings = _findings({"found": ["AC-001"], "error": ["RT-050"]})
    with patch("analysis.pipeline.analyse", return_value=found_findings), \
         patch("ai.explain.explain_with_source", side_effect=RuntimeError("model down")):
        label, status, detail = live_check.check_explanation_layer()

    assert status == live_check.FAIL
    assert "#52" in detail


@pytest.mark.parametrize(
    "bad_result",
    [("", "model"), ("text", "something-else"), (None, "fallback")],
)
def test_explanation_layer_fails_on_an_invalid_shape(bad_result):
    """#52's contract is a non-empty string and a real source label --
    an empty string or an unrecognised source is not "no explanation", it
    is a broken contract, and must not be reported as PASS."""
    found_findings = _findings({"found": ["AC-001"], "error": ["RT-050"]})
    with patch("analysis.pipeline.analyse", return_value=found_findings), \
         patch("ai.explain.explain_with_source", return_value=bad_result):
        label, status, detail = live_check.check_explanation_layer()

    assert status == live_check.FAIL


# ---------------------------------------------------------------------------
# check_query_layer
# ---------------------------------------------------------------------------


def _query_mocks(answerable, refused):
    return patch("ai.query.answer_question", side_effect=[answerable, refused])


def test_query_layer_passes_when_it_answers_and_refuses_correctly():
    answerable = {"question_understood": "Can rtr-us5 reach 10.20.0.5?",
                  "answer": "No.", "grounded": True}
    refused = {"question_understood": None, "answer": "refused", "grounded": False}

    with patch("analysis.pipeline.connect", return_value="fake"), \
         patch("analysis.pipeline.load_snapshot"), \
         _query_mocks(answerable, refused):
        label, status, detail = live_check.check_query_layer()

    assert status == live_check.PASS


def test_query_layer_fails_when_a_real_question_is_not_grounded():
    """The exact failure this exists to catch: the query layer silently
    stops grounding a well-formed, answerable question."""
    ungrounded = {"question_understood": "Can rtr-us5 reach 10.20.0.5?",
                  "answer": "could not check", "grounded": False}
    refused = {"question_understood": None, "answer": "refused", "grounded": False}

    with patch("analysis.pipeline.connect", return_value="fake"), \
         patch("analysis.pipeline.load_snapshot"), \
         _query_mocks(ungrounded, refused):
        label, status, detail = live_check.check_query_layer()

    assert status == live_check.FAIL
    assert "not grounded" in detail


def test_query_layer_fails_when_nonsense_is_not_refused():
    """The other direction: the query layer starts answering something it
    should refuse -- the more dangerous regression of the two (CLAUDE.md
    section 7c: a mistranslated question is worse than a wrong answer)."""
    answerable = {"question_understood": "Can rtr-us5 reach 10.20.0.5?",
                  "answer": "No.", "grounded": True}
    wrongly_answered = {"question_understood": "guessed something",
                         "answer": "sure, go ahead", "grounded": True}

    with patch("analysis.pipeline.connect", return_value="fake"), \
         patch("analysis.pipeline.load_snapshot"), \
         _query_mocks(answerable, wrongly_answered):
        label, status, detail = live_check.check_query_layer()

    assert status == live_check.FAIL
    assert "not refused" in detail


def test_query_layer_fails_without_raising_when_answer_question_errors():
    with patch("analysis.pipeline.connect", return_value="fake"), \
         patch("analysis.pipeline.load_snapshot"), \
         patch("ai.query.answer_question", side_effect=RuntimeError("down")):
        label, status, detail = live_check.check_query_layer()

    assert status == live_check.FAIL
    assert "down" in detail
