"""`docs/design/phase-3-backlog.md` must be what the generator produces.

WHY THIS FILE EXISTS
    The document says, in its own last section, that it cannot disagree with
    the GitHub issues because both are generated from one source. That claim
    is only true while nobody hand-edits the document. Nothing enforced it,
    which made it exactly the kind of sentence this project keeps writing and
    then falsifying -- a described practice standing in for a performed one.

    So the claim is checked instead of asserted.

WHY THIS IS NOT #267
    #267 is the reason to be careful here. `docs/traceability.md` carries
    per-file test counts, so a CI check on it would be red every time anybody
    adds a test -- permanently red, and therefore ignored.

    This document carries no count that `main` can move. Its content is a
    function of the story list and the recorded issue numbers, both of which
    live in files in this repository. It changes when somebody edits the
    generator, and at no other time. That is what makes the check stable
    rather than noise.

WHAT FAILURE MEANS
    Either the document was edited by hand -- regenerate it and put the change
    in the generator instead -- or the generator changed and the document was
    not regenerated. Both are the same defect and both have the same fix:

        python -m tools.make_phase3_backlog doc

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "tools" / "make_phase3_backlog.py"
DOCUMENT = REPO_ROOT / "docs" / "design" / "phase-3-backlog.md"


def _generator():
    """Import the script by path -- tools/ is not a package on sys.path."""
    spec = importlib.util.spec_from_file_location("_phase3", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_phase3"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    if not GENERATOR.exists():          # pragma: no cover - the file is tracked
        pytest.skip("generator not present")
    return _generator()


def test_document_matches_the_generator(gen):
    """The committed document is byte-identical to a fresh generation."""
    on_disk = DOCUMENT.read_text(encoding="utf-8")
    assert on_disk == gen.document(), (
        "docs/design/phase-3-backlog.md is not what the generator produces. "
        "Run: python -m tools.make_phase3_backlog doc"
    )


def test_every_story_has_an_issue_number(gen):
    """A backlog row with no issue behind it is a plan, not work."""
    import json

    numbers = json.loads(gen.NUMBERS.read_text(encoding="utf-8"))
    every = {row[0] for row in gen.STORIES} | {e[0] for e in gen.EXISTING}
    assert set(numbers) == every, (
        f"stories with no issue: {sorted(every - set(numbers))}; "
        f"issues with no story: {sorted(set(numbers) - every)}"
    )


def test_story_ids_are_unique(gen):
    """Two stories sharing an id is the duplicate-`id` bug in a backlog."""
    ids = [row[0] for row in gen.STORIES] + [e[0] for e in gen.EXISTING]
    assert len(ids) == len(set(ids)), "duplicate story id"


def test_every_story_is_assigned_to_a_real_member(gen):
    """Nothing here is owned by nobody -- that is how a backlog rots."""
    members = {gen.A, gen.N, gen.S, gen.K}
    for row in gen.STORIES:
        assert row[5] in members, f"{row[0]} assigned to {row[5]!r}"


def test_every_story_states_why_it_is_in_the_milestone(gen):
    """A story with no argument behind it is a wish, and gets cut."""
    for row in gen.STORIES:
        assert row[3], f"{row[0]} has no acceptance criteria"
        assert len(row[4].split()) >= 12, f"{row[0]} has no real rationale"
