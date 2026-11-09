"""
Netwise -- tests for tools/explanation_quality.py (US-55, #346).

WHY THIS FILE EXISTS
    score_holdout() is pure arithmetic, so most of what is worth testing is
    the arithmetic itself (synthetic cases below) -- but the whole POINT of
    #346 is a published number, and a test that only exercises synthetic
    data would never notice if the committed fixture itself drifted or the
    threshold stopped holding. So this file also pins the real committed
    holdout.json and asserts its score against the documented threshold
    (see docs/evaluation.md Part 4 and ai/explain.py's
    EXPLANATION_QUALITY_THRESHOLD), the same way other "published number"
    tests in this project assert on real output rather than a mock.

    Needs neither Batfish nor Ollama -- the holdout set is a frozen capture,
    not a live generation.

RUN
    pytest tests/test_explanation_quality.py -v
"""

import pytest

from tools.explanation_quality import (
    EXPLANATION_QUALITY_THRESHOLD,
    current_modelfile_sha256,
    current_prompt_sha256,
    load_holdout,
    load_holdout_metadata,
    score_holdout,
)

# ---------------------------------------------------------------------------
# Synthetic cases -- the real fixture currently has exactly one rater per
# finding, which would never catch a bug in averaging MULTIPLE raters'
# scores for the same finding. These exercise that path directly.
# ---------------------------------------------------------------------------


def _finding(fid, accuracy_usefulness_pairs, source="model"):
    return {
        "id": fid,
        "captured_explanation_source": source,
        "ratings": [
            {"rater": f"r{i}", "accuracy": acc, "usefulness": use}
            for i, (acc, use) in enumerate(accuracy_usefulness_pairs)
        ],
    }


def test_score_averages_multiple_raters_on_one_finding():
    findings = [_finding("X-001", [(5, 5), (3, 1)])]
    score = score_holdout(findings)
    assert score["mean_accuracy"] == 4.0
    assert score["mean_usefulness"] == 3.0
    assert score["min_accuracy"] == 3
    assert score["min_usefulness"] == 1
    assert score["n_findings"] == 1
    assert score["n_ratings"] == 2


def test_score_averages_across_multiple_findings():
    findings = [
        _finding("X-001", [(5, 5)]),
        _finding("X-002", [(1, 1)]),
    ]
    score = score_holdout(findings)
    assert score["mean_accuracy"] == 3.0
    assert score["min_accuracy"] == 1
    assert score["n_findings"] == 2
    assert score["n_ratings"] == 2


def test_per_finding_breakdown_reports_each_findings_own_mean():
    findings = [
        _finding("GOOD", [(5, 5)]),
        _finding("BAD", [(1, 2)]),
    ]
    score = score_holdout(findings)
    by_id = {row["id"]: row for row in score["per_finding"]}
    assert by_id["GOOD"]["mean_accuracy"] == 5.0
    assert by_id["BAD"]["mean_accuracy"] == 1.0
    assert by_id["BAD"]["n_ratings"] == 1


def test_scoring_an_empty_set_raises_rather_than_returning_a_fake_zero():
    """An empty mean is not a score of zero -- it is not a score at all.
    Same F-4 distinction the product itself enforces (never/error), applied
    to this measurement tool."""
    with pytest.raises(ValueError):
        score_holdout([])


# ---------------------------------------------------------------------------
# Fallback captures must never count toward the model score (found in
# review, @ARSH871-bot). A fallback-sourced explanation cannot be wrong by
# construction, so a set with no model output at all must not be able to
# pass the threshold that exists to judge the MODEL.
# ---------------------------------------------------------------------------


def test_a_holdout_set_of_only_fallback_entries_cannot_be_scored():
    """THE CASE THE REVIEW NAMED DIRECTLY: five perfect fallback ratings
    must not produce a passing model score -- there is no model score to
    produce, and this must say so loudly rather than quietly report 5.0."""
    findings = [
        _finding("X-001", [(5, 5)], source="fallback"),
        _finding("X-002", [(5, 5)], source="fallback"),
    ]
    with pytest.raises(ValueError):
        score_holdout(findings)


def test_fallback_entries_are_reported_separately_not_blended_in():
    findings = [
        _finding("MODEL-ONE", [(3, 3)], source="model"),
        _finding("FALLBACK-ONE", [(5, 5)], source="fallback"),
    ]
    score = score_holdout(findings)
    # The headline numbers are the model entry alone.
    assert score["n_findings"] == 1
    assert score["mean_accuracy"] == 3.0
    assert {row["id"] for row in score["per_finding"]} == {"MODEL-ONE"}
    # The fallback entry exists in its own section, not folded in.
    assert score["fallback"]["n_findings"] == 1
    assert score["fallback"]["mean_accuracy"] == 5.0
    assert {row["id"] for row in score["fallback"]["per_finding"]} == {"FALLBACK-ONE"}


def test_a_set_with_no_fallback_entries_has_no_fallback_key():
    findings = [_finding("MODEL-ONE", [(5, 5)], source="model")]
    score = score_holdout(findings)
    assert "fallback" not in score


def test_a_missing_source_field_is_treated_as_not_model():
    """Defensive: an older or malformed record with no
    captured_explanation_source at all must not be silently scored as if
    it were model-written -- it lands in the fallback bucket, same as any
    other non-"model" value."""
    findings = [{"id": "X-001", "ratings": [{"rater": "r", "accuracy": 5, "usefulness": 5}]}]
    with pytest.raises(ValueError):
        score_holdout(findings)


# ---------------------------------------------------------------------------
# The real, committed held-out set -- the published number itself.
# ---------------------------------------------------------------------------


def test_the_committed_holdout_set_loads():
    findings = load_holdout()
    assert len(findings) == 5
    assert {f["id"] for f in findings} == {
        "RT-050", "AC-001", "PC-001", "AC-002", "PC-005",
    }


def test_the_published_score_matches_the_committed_ratings():
    """Pins the current, real number -- MODEL-WRITTEN entries only (RT-050
    is fallback-sourced and reported separately, see
    tools/explanation_quality.py's score_holdout() docstring). A change
    here means either the holdout set or its ratings changed -- re-measure
    deliberately (docs/evaluation.md Part 4), don't just update this
    assertion to make it pass.

    Re-measured again (9 November) after review found the raw-ACL-syntax
    wording traded one misdescription for another (#401 review,
    @shubhamkataria2005) -- #385's guard flagged AC-002 as stale the
    moment the fix changed its prompt. AC-002 moved from 5/4 to 5/5; see
    docs/evaluation.md Part 4 for the dated note."""
    score = score_holdout(load_holdout())
    assert score["n_findings"] == 4
    assert score["n_ratings"] == 4
    assert score["mean_accuracy"] == pytest.approx(5.0)
    assert score["min_accuracy"] == 5
    assert score["mean_usefulness"] == pytest.approx(4.0)
    assert score["min_usefulness"] == 3
    assert {row["id"] for row in score["per_finding"]} == {
        "AC-001", "PC-001", "AC-002", "PC-005",
    }


def test_rt_050_is_reported_as_fallback_not_scored_against_the_threshold():
    """RT-050 is status="error" (never shown an explanation in the real
    app -- see web/main.py's attachment loop) AND fallback-sourced (cannot
    be wrong by construction). Both are reasons it must not count toward
    whether the MODEL clears the threshold."""
    score = score_holdout(load_holdout())
    assert "RT-050" not in {row["id"] for row in score["per_finding"]}
    assert score["fallback"]["n_findings"] == 1
    assert score["fallback"]["per_finding"][0]["id"] == "RT-050"


def test_the_low_scoring_finding_is_identifiable_in_the_breakdown():
    """AC-002's accuracy=2 (#384) was the breakdown's original reason to
    exist -- a defect the blended mean would have hidden. #401 fixed that
    defect and re-captured AC-002 at 5/4 (see the test above), so every
    finding now ties at accuracy=5 and there is no accuracy outlier left
    to find. The breakdown's job is unchanged, only which finding it
    surfaces: PC-005's usefulness=3 is now the lowest figure in the set,
    a readability nit already noted in docs/evaluation.md's own table
    (its first sentence asks the reader to resolve an apparent
    contradiction before it resolves itself), not a filed defect -- the
    point of this test is that the breakdown still finds it rather than
    averaging it away, whatever its current cause."""
    score = score_holdout(load_holdout())
    by_id = {row["id"]: row for row in score["per_finding"]}
    assert by_id["AC-002"]["mean_accuracy"] == 5.0
    assert by_id["PC-005"]["mean_usefulness"] == 3.0
    assert min(row["mean_usefulness"] for row in score["per_finding"]) == 3.0


def test_current_mean_quality_meets_the_documented_threshold():
    """The headline, aggregate decision point: see
    EXPLANATION_QUALITY_THRESHOLD's own docstring and docs/evaluation.md
    Part 4 for what crossing this means and why it is a documented,
    manually-reviewed decision rather than a runtime auto-disable."""
    score = score_holdout(load_holdout())
    assert score["mean_accuracy"] >= EXPLANATION_QUALITY_THRESHOLD["mean_accuracy"]
    assert score["mean_usefulness"] >= EXPLANATION_QUALITY_THRESHOLD["mean_usefulness"]


# ---------------------------------------------------------------------------
# Staleness (#346 review, @ARSH871-bot, non-blocking but addressed here).
# Nothing made the published score go stale when the model that produced
# it changes -- appending one line to ai/Modelfile left this whole file
# green, 8 of 8, with no live model call involved anywhere. This is the
# guard: the held-out set records what it was captured against, and this
# test fails loudly, not silently, the moment that stops matching.
# ---------------------------------------------------------------------------


def test_the_holdout_set_is_captured_against_the_current_modelfile():
    recorded = load_holdout_metadata()["modelfile_sha256"]
    live = current_modelfile_sha256()
    assert recorded == live, (
        "ai/Modelfile has changed since this held-out set was captured "
        "(recorded sha256 no longer matches). The published score no "
        "longer reflects what the model currently produces -- re-capture "
        "and re-rate the held-out set (see docs/evaluation.md Part 4's "
        "method), do not just update the recorded hash to silence this."
    )


def test_current_modelfile_sha256_actually_hashes_the_file_not_a_constant(tmp_path):
    """#385 review nit, @shubhamkataria2005: nothing proved this function
    reads the file rather than returning a hard-coded value, since every
    other test only compares it against the one real Modelfile it was
    already going to match."""
    import hashlib

    probe = tmp_path / "Modelfile"
    probe.write_text("a probe Modelfile that is not the real one\n", encoding="utf-8")
    expected = hashlib.sha256(probe.read_bytes()).hexdigest()
    assert current_modelfile_sha256(probe) == expected

    probe.write_text("a DIFFERENT probe Modelfile\n", encoding="utf-8")
    assert current_modelfile_sha256(probe) != expected, (
        "changing the file's content must change the hash -- a constant "
        "would pass the first assertion and fail to change here"
    )


def test_each_model_written_entry_is_captured_against_the_current_prompt():
    """#385 review, @shubhamkataria2005: the Modelfile hash above cannot
    see a change to _build_prompt() itself -- measured, with #401 merged
    on top of this set, all tests still passed even though #401 rewrites
    the computed fact for AC-002, this set's own #384 capture. One prompt
    hash per finding, so a change to one computed-fact function marks only
    the findings whose own prompt actually moved, not the whole set."""
    stale = []
    for finding in load_holdout():
        if finding["captured_explanation_source"] != "model":
            continue
        live = current_prompt_sha256(finding["finding"])
        if live != finding["captured_prompt_sha256"]:
            stale.append(finding["id"])
    assert not stale, (
        f"these held-out entries were captured against a prompt "
        f"_build_prompt() no longer builds: {stale}. The published rating "
        f"for each one now describes text the product would not actually "
        f"send -- re-capture and re-rate those entries (see "
        f"docs/evaluation.md Part 4's method), do not just update the "
        f"recorded hash to silence this."
    )
