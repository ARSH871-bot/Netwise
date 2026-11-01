"""`classify()` must refuse to guess "Parses cleanly" (found by review,
@ARSH871-bot, #320).

WHY THIS FILE EXISTS, SEPARATELY FROM test_vendor_support_table_doc.py
    That file's freshness check needs real Batfish and real fixtures, so it
    SKIPS in CI -- stated plainly in its own docstring, because a measured
    claim cannot be verified without what it measures. This file tests a
    narrower thing that needs neither: the RULE `classify()` applies once
    it already has `analyse()`'s return value. Batfish is replaced with a
    monkeypatched `analysis.pipeline.analyse`, so this runs everywhere,
    including CI.

THE DEFECT THIS PINS
    The first version of `classify()` recognised failure by exactly one
    fatal-parse summary and one partial-parse id suffix. Anything else fell
    through to "Parses cleanly" -- including `analyse()`'s two OTHER
    "could not run" shapes (an unreachable Batfish, a config that could not
    be loaded at all). Measured with a genuine load failure: every check
    returned "Analysis could not run: the config could not be loaded", and
    the old `classify()` wrote "Parses cleanly" for it. F-4, in the most
    public document this project has.

    Every fixture committed today classifies correctly regardless of this
    fix, since none of them exercises this path -- the defect was in what
    the generator would write for the NEXT vendor added, not in the table
    as it stands. That is exactly why a test is worth more than the four
    rows currently being right.

RUN
    pytest tests/ -v
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from analysis import pipeline as real_pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "tools" / "make_vendor_support_table.py"


def _generator():
    """Import the script by path -- tools/ is not a package on sys.path."""
    spec = importlib.util.spec_from_file_location("_vendor_table_classify", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_vendor_table_classify"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    if not GENERATOR.exists():          # pragma: no cover - the file is tracked
        pytest.skip("generator not present")
    return _generator()


@pytest.fixture
def fake_analyse(monkeypatch):
    """classify() does `from analysis import pipeline` INSIDE the function
    body, so patching the real analysis.pipeline module (not gen.pipeline,
    which does not exist as a module-level name) is what actually reaches
    it -- both names are the same module object either way."""
    def install(results):
        monkeypatch.setattr(real_pipeline, "analyse", lambda *a, **k: results)
    return install


def _error_finding(summary: str, check: str = "access_control") -> dict:
    """The exact shape analyse()'s crash-isolation path produces -- see
    analysis/findings.py:error_finding(). Built directly with the real
    helper below rather than a hand-typed dict, so this test cannot drift
    from what error_finding() actually returns."""
    from analysis import findings
    return findings.error_finding(
        check=check, summary=summary, detail="stub", source="stub",
    )


@pytest.mark.parametrize("summary", [
    "Analysis could not run: Batfish is not reachable",
    "Analysis could not run: the config could not be loaded",
    "Analysis could not run: parse status could not be read",
])
def test_an_unrecognised_could_not_run_result_raises_rather_than_guesses(
        gen, fake_analyse, summary):
    """THE ONE ARSH'S REVIEW FOUND, for each of the three shapes
    classify() did not recognise. None of these may fall through to
    "Parses cleanly" -- the generator must refuse to write the row."""
    fake_analyse([_error_finding(summary)])
    with pytest.raises(RuntimeError, match="could not look at it"):
        gen.classify("vendor-does-not-matter")


def test_the_recognised_fatal_parse_summary_still_classifies_as_does_not_parse(
        gen, fake_analyse):
    """The one "could not run" shape classify() DOES already recognise
    must keep working -- this is the regression guard for the fix above,
    not the fix itself."""
    fake_analyse([_error_finding(
        "Analysis could not run: the config did not fully parse")])
    result = gen.classify("vendor-does-not-matter")
    assert result["parses"] == "Does not parse"


def test_a_partial_parse_result_still_classifies_correctly(gen, fake_analyse):
    caveat_id = f"AC-{real_pipeline.PARTIAL_PARSE_NUMBER:03d}"
    fake_analyse([{**_error_finding("Results may be incomplete"),
                   "id": caveat_id}])
    result = gen.classify("vendor-does-not-matter")
    assert result["parses"] == "Parses partially"


def test_a_clean_result_with_a_finding_still_classifies_correctly(gen, fake_analyse):
    fake_analyse([{
        "id": "AC-001", "check": "access_control", "severity": "high",
        "device": "dev", "summary": "a real problem",
        "evidence": {"detail": "d", "source": "s"}, "status": "found",
    }])
    result = gen.classify("vendor-does-not-matter")
    assert result["parses"] == "Parses cleanly"
    assert result["produces_finding"] is True


# ---------------------------------------------------------------------------
# splice_into_readme()'s corrupted-marker guard (not blocking, @ARSH871-bot)
# ---------------------------------------------------------------------------


def test_marker_end_before_marker_start_raises_rather_than_duplicates(
        gen, monkeypatch, tmp_path):
    """Points gen.README at a throwaway file rather than the real README.md
    -- this test corrupts its input on purpose, and the real doc must never
    be at risk of that, whatever this test does or how it fails."""
    corrupted = tmp_path / "README.md"
    corrupted.write_text(
        f"before {gen.MARKER_END} middle {gen.MARKER_START} after\n"
        "All live under `tests/fixtures/`.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gen, "README", corrupted)

    with pytest.raises(RuntimeError, match="appears before"):
        gen.splice_into_readme("new section\n")
