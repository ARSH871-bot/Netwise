"""README.md's vendor support table must be what the generator produces
(#320).

WHY THIS FILE EXISTS
    Same reasoning as tests/test_phase3_backlog_doc.py, applied to a spliced
    section rather than a whole document: a claim that "this is generated"
    is only true while nobody hand-edits the result. Nothing enforced that
    for the vendor table, which is exactly the shape this project keeps
    finding elsewhere -- a described practice standing in for a performed
    one.

WHY THIS NEEDS BATFISH, UNLIKE test_phase3_backlog_doc.py
    The phase-3 backlog is built from a story list and recorded issue
    numbers, both static files in this repository -- nothing it reads can
    change without a commit. The vendor table's claims are different in
    kind: "parses cleanly" and "produces a finding" are measured by running
    the real pipeline against Batfish. That cannot be checked without
    Batfish, so this SKIPS without it, loudly, the same way
    tests/test_vendor_fixtures.py's own Part 2 already does. Part of the
    generator's docstring is a promise this test is not making in CI.

WHY THIS IS NOT ANOTHER #267
    #267 is the reason to be careful here. docs/traceability.md carries a
    per-file test COUNT, so a diff-check on it is red every time anyone
    adds a test anywhere -- permanently red, and therefore ignored. The
    vendor table carries no such moving number. Its inputs are four fixed
    fixtures' parse status and whether each produces a finding, none of
    which drifts when an unrelated test is added elsewhere. It changes when
    a fixture changes, a vendor is added, or the generator itself changes,
    and at no other time -- which is what makes this check worth having
    rather than noise to be silenced.

WHAT FAILURE MEANS
    Either README.md's vendor table was edited by hand -- regenerate it and
    put the change in the generator instead -- or a fixture or the pipeline
    changed and the table was not regenerated. Both are the same defect and
    both have the same fix:

        python -m tools.make_vendor_support_table

RUN
    pytest tests/ -v
"""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "tools" / "make_vendor_support_table.py"
README = REPO_ROOT / "README.md"


def _batfish_is_up(host: str = "localhost", port: int = 9996,
                    timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


needs_batfish = pytest.mark.skipif(
    not _batfish_is_up(),
    reason=(
        "Batfish is not reachable on localhost:9996. This table's claims "
        "are measured by running the real pipeline, which cannot be "
        "checked without Batfish -- see the module docstring."
    ),
)


def _generator():
    """Import the script by path -- tools/ is not a package on sys.path."""
    spec = importlib.util.spec_from_file_location("_vendor_table", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_vendor_table"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    if not GENERATOR.exists():          # pragma: no cover - the file is tracked
        pytest.skip("generator not present")
    return _generator()


def _spliced_block(text: str, gen) -> str:
    """The exact slice between (and including) this generator's markers."""
    start = text.index(gen.MARKER_START)
    end = text.index(gen.MARKER_END) + len(gen.MARKER_END)
    return text[start:end]


@needs_batfish
def test_the_table_in_readme_matches_the_generator(gen):
    """The committed slice is byte-identical to a fresh generation."""
    on_disk = README.read_text(encoding="utf-8")
    assert gen.MARKER_START in on_disk and gen.MARKER_END in on_disk, (
        "README.md has no vendor support table markers at all -- run: "
        "python -m tools.make_vendor_support_table"
    )
    committed_slice = _spliced_block(on_disk, gen)
    fresh_slice = gen.table_section().rstrip("\n")
    assert committed_slice == fresh_slice, (
        "README.md's vendor support table is not what the generator "
        "produces right now. Run: python -m tools.make_vendor_support_table"
    )


@needs_batfish
def test_splicing_touches_nothing_outside_the_markers(gen):
    """The generator must not be able to disturb the rest of the file.

    Regenerates in memory against the file currently on disk and asserts
    everything OUTSIDE the marked block is untouched -- the property the
    whole splice-rather-than-own design depends on.
    """
    before = README.read_text(encoding="utf-8")
    after = gen.splice_into_readme(gen.table_section())

    before_prefix = before[:before.index(gen.MARKER_START)]
    after_prefix = after[:after.index(gen.MARKER_START)]
    assert before_prefix == after_prefix, "content before the markers moved"

    before_suffix = before[before.index(gen.MARKER_END) + len(gen.MARKER_END):]
    after_suffix = after[after.index(gen.MARKER_END) + len(gen.MARKER_END):]
    assert before_suffix == after_suffix, "content after the markers moved"


@needs_batfish
def test_parses_and_produces_a_finding_are_reported_separately(gen):
    """THE ACCEPTANCE CRITERION, pinned directly.

    #320 asks for a table that "distinguishes parses from produces
    findings, because tests/test_vendor_fixtures.py is emphatic that these
    are different claims". Asserted here as a real property of the
    generated table, not just of its surrounding prose: the header names
    both as separate columns, and at least one vendor's row shows them
    genuinely diverging (vendor-asa: parses only partially, still produces
    a finding) -- so the distinction is demonstrated, not only claimed.
    """
    block = gen.table_section()
    assert "| Vendor | Parses | Produces a finding |" in block, (
        "the two claims are not rendered as separate table columns"
    )

    rows = [gen.classify(v) for v in gen._vendor_fixtures()]
    partial_and_found = [
        r for r in rows
        if r["parses"] == "Parses partially" and r["produces_finding"]
    ]
    assert partial_and_found, (
        "no fixture demonstrates the two claims actually diverging -- "
        "expected vendor-asa to parse only partially and still produce a "
        "finding"
    )


@needs_batfish
def test_every_vendor_fixture_on_disk_has_a_row(gen):
    """A vendor fixture with no row in the table is exactly the gap #320
    exists to close -- checked here rather than trusted."""
    block = gen.table_section()
    for vendor in gen._vendor_fixtures():
        display = gen.DISPLAY_NAMES.get(vendor, vendor)
        assert display in block, f"{vendor} ({display}) has no row in the table"
