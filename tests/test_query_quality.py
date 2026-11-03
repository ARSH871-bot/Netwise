"""
Netwise -- tests for tools/query_quality.py (US-60, #393).

WHY THIS FILE EXISTS
    score_holdout() runs the REAL answer_question() against a FakeSession
    built fresh from each entry (see tools/query_quality.py's own docstring
    for why this is executed live rather than replaying a frozen capture --
    unlike #385's explanation held-out set, ai/query.py calls no model, so
    there is nothing here that varies run to run). Most of what is worth
    testing is the classification arithmetic itself (synthetic cases
    below), but the whole point of #393 is a number asserted in CI, so this
    file also pins the real committed holdout.json against the documented
    threshold -- the same "published number" pattern #385's own test file
    already uses.

    Needs neither Batfish nor Ollama: every FakeSession here is exactly
    the same fake tests/test_query_translation.py already drives
    answer_question() through.

RUN
    pytest tests/test_query_quality.py -v
"""

import pytest

from tools.query_quality import (
    QUERY_QUALITY_THRESHOLD,
    load_holdout,
    score_holdout,
)

# ---------------------------------------------------------------------------
# Synthetic cases -- drive score_holdout() with small, hand-built entry
# lists so each outcome is exercised on its own, not only together inside
# the much larger committed fixture.
# ---------------------------------------------------------------------------


def _entry(id_, question, outcome_expected, fake_session=None, **extra):
    return {
        "id": id_, "question": question, "outcome_expected": outcome_expected,
        "fake_session": fake_session or {}, **extra,
    }


def test_scoring_an_empty_set_raises_rather_than_returning_a_fake_zero():
    with pytest.raises(ValueError):
        score_holdout([])


def test_an_answered_correct_entry_that_matches_is_counted_as_such():
    entries = [_entry(
        "X1", "Can rtr-us5 reach 1.1.1.1?", "answered_correct",
        {"devices": ["rtr-us5"], "traceroute_frame_rows": [{"traces": [{"disposition": "ACCEPTED"}]}]},
        answer_starts_with="Yes.",
    )]
    score = score_holdout(entries)
    assert score["counts"]["answered_correct"] == 1
    assert score["counts"]["answered_wrong"] == 0


def test_an_answered_entry_that_does_not_match_is_answered_wrong():
    """The dangerous mismatch: the question WAS answered, but not the way
    the entry expected -- e.g. "No." when "Yes." was expected."""
    entries = [_entry(
        "X2", "Can rtr-us5 reach 1.1.1.1?", "answered_correct",
        {"devices": ["rtr-us5"], "traceroute_frame_rows": [{"traces": [{"disposition": "DENIED_IN", "hops": ["rtr-us5"]}]}]},
        answer_starts_with="Yes.",
    )]
    score = score_holdout(entries)
    assert score["counts"]["answered_wrong"] == 1


def test_a_refusal_when_an_answer_was_expected_is_its_own_bucket():
    entries = [_entry(
        "X3", "Can rtr-us5 reach 1.1.1.1?", "answered_correct",
        {"devices": ["rtr-us5"], "traceroute_frame_rows": []},
    )]
    score = score_holdout(entries)
    assert score["counts"]["refused_but_should_answer"] == 1
    assert score["counts"]["answered_wrong"] == 0


def test_a_correct_refusal_is_counted_as_such():
    entries = [_entry(
        "X4", "Can the guest network reach 1.1.1.1?", "refused_correctly",
        {"devices": ["rtr-us5"]},
    )]
    score = score_holdout(entries)
    assert score["counts"]["refused_correctly"] == 1


def test_answering_when_a_refusal_was_expected_is_answered_wrong_regardless_of_text():
    """The gap this test exists to pin: an entry with no answer_contains/
    answer_starts_with set (nothing to text-match against) must still land
    in the dangerous bucket if the code answers when it should have
    refused -- not fall through to answered_correct by default."""
    entries = [_entry(
        "X5", "Can rtr-us5 reach 1.1.1.1?", "refused_correctly",
        {"devices": ["rtr-us5"], "traceroute_frame_rows": [{"traces": [{"disposition": "ACCEPTED"}]}]},
    )]
    score = score_holdout(entries)
    assert score["counts"]["answered_wrong"] == 1
    assert score["counts"]["answered_correct"] == 0


def test_counts_accumulate_across_multiple_entries():
    entries = [
        _entry("A", "Are there any dead rules?", "answered_correct",
               {"devices": ["rtr-us5"], "whole_snapshot_frame_rows": []}, answer_starts_with="No"),
        _entry("B", "", "refused_correctly", {}),
    ]
    score = score_holdout(entries)
    assert score["n_entries"] == 2
    assert score["counts"]["answered_correct"] == 1
    assert score["counts"]["refused_correctly"] == 1


def test_mismatches_are_named_in_the_details_not_only_counted():
    entries = [_entry(
        "X6", "Can rtr-us5 reach 1.1.1.1?", "answered_correct",
        {"devices": ["rtr-us5"], "traceroute_frame_rows": [{"traces": [{"disposition": "DENIED_IN", "hops": ["rtr-us5"]}]}]},
        answer_starts_with="Yes.",
    )]
    score = score_holdout(entries)
    [detail] = score["details"]
    assert detail["id"] == "X6"
    assert detail["expected"] == "answered_correct"
    assert detail["actual"] == "answered_wrong"


# ---------------------------------------------------------------------------
# The committed fixture -- a published number, asserted against real output
# ---------------------------------------------------------------------------


def test_the_committed_holdout_set_loads():
    entries = load_holdout()
    assert len(entries) >= 20
    assert {e["id"] for e in entries} >= {f"Q{n:02d}" for n in range(1, 21)}


def test_the_committed_holdout_set_has_zero_answered_wrong():
    """The CI gate (#393's acceptance criterion): answering confidently and
    wrongly about a firewall is the one failure this whole project exists
    to avoid, so the threshold is a floor of zero, never a budget."""
    score = score_holdout(load_holdout())
    assert score["counts"]["answered_wrong"] <= QUERY_QUALITY_THRESHOLD["max_answered_wrong"], (
        score["details"]
    )


def test_the_committed_holdout_set_has_no_unexplained_mismatches():
    """Every entry's actual outcome must equal what it claims to expect --
    a mismatch anywhere here means either the fixture's own expectation is
    wrong, or real behaviour drifted from it, and either way the published
    counts above would be misleading without this check."""
    score = score_holdout(load_holdout())
    mismatches = [d for d in score["details"] if d["expected"] != d["actual"]]
    assert mismatches == []


def test_the_committed_holdout_set_pins_the_70_regression():
    """Q05 names the #70 bug by id in the fixture itself -- confirm it is
    still there and still answered_correct, not quietly dropped."""
    entries = load_holdout()
    q05 = next(e for e in entries if e["id"] == "Q05")
    assert "10.20.20.0/24" in q05["question"]
    score = score_holdout([q05])
    assert score["counts"]["answered_correct"] == 1
