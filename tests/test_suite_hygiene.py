"""Tests about the test suite itself.

WHY THIS FILE EXISTS
    On 11 August two of the most important tests in this repository were
    found to be asserting nothing at all:

        test_hostname_with_an_embedded_newline_raises          (#53, injection)
        test_a_specific_deny_before_a_broader_permit_...       (#47/#58, rule order)

    Both built their input and then ended. The function bodies had been
    truncated during a conflict resolution, the assertions removed with them,
    and the suite went green for days. They guarded the two most serious bugs
    this project has found.

    Nothing caught it. `pytest` cannot: a test that does nothing passes. The
    reviewers could not: the diff that broke them was a rebase resolution
    nobody re-read line by line. It surfaced only because a linter flagged an
    unused local variable, which is a lucky way to find it.

    This is the project's recurring failure family -- a weaker claim standing
    in for a stronger one -- appearing in the tests themselves. "The suite is
    green" stood in for "the behaviour is checked".

THE RULE
    Every test must be able to fail. A test with no assertion and no
    `pytest.raises` cannot, so it is not a test.

    This does not prove a test checks the RIGHT thing -- nothing automated
    can. It proves each one checks something, which is the floor that was
    missing.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent

# A test may prove itself by asserting, by expecting a raise, or by being
# explicitly skipped. Anything else has no way to report a failure.
_PROOF_NODES = (ast.Assert,)
_PROOF_CALLS = ("pytest.raises", "pytest.warns", "pytest.skip", "pytest.fail")


def _test_functions(tree: ast.AST, source: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            yield node, ast.get_source_segment(source, node) or ""


def _python_test_files():
    return sorted(p for p in TESTS_DIR.glob("test_*.py") if p.name != Path(__file__).name)


@pytest.mark.parametrize(
    "path", _python_test_files(), ids=lambda p: p.name
)
def test_every_test_can_fail(path: Path):
    """No test may assert nothing.

    The failure this catches is silent by construction: the suite stays green,
    the count does not drop, and the only visible symptom is an unused local
    variable -- which is how it was actually found.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    toothless = []
    for node, segment in _test_functions(tree, source):
        has_assert = any(isinstance(n, _PROOF_NODES) for n in ast.walk(node))
        has_call = any(call in segment for call in _PROOF_CALLS)
        if not has_assert and not has_call:
            toothless.append(f"{path.name}:{node.lineno} {node.name}")

    assert not toothless, (
        "these tests assert nothing and therefore cannot fail:\n  "
        + "\n  ".join(toothless)
        + "\n\nA test with no assertion and no pytest.raises() is not a test. "
        "If it is a placeholder, mark it with pytest.skip so that is visible."
    )


def test_this_guard_would_actually_catch_a_toothless_test(tmp_path: Path):
    """The guard mutated against itself.

    A check that cannot demonstrate its own failure is the same class of
    problem it exists to prevent, so this builds a file with a toothless test
    in it and confirms the detection fires.
    """
    offender = tmp_path / "test_pretend.py"
    offender.write_text(
        "def test_looks_fine_but_proves_nothing():\n"
        "    value = 1 + 1\n",
        encoding="utf-8",
    )

    source = offender.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = [
        node.name
        for node, segment in _test_functions(tree, source)
        if not any(isinstance(n, _PROOF_NODES) for n in ast.walk(node))
        and not any(call in segment for call in _PROOF_CALLS)
    ]

    assert found == ["test_looks_fine_but_proves_nothing"], (
        "the guard failed to detect a test that asserts nothing"
    )
