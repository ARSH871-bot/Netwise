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
    """The guard pointed at itself -- by CALLING it, not by copying it.

    The first version of this test re-implemented the detection inline instead
    of invoking `test_every_test_can_fail`. @shubhamkataria2005 found it on
    #84 and it is worth recording exactly what he did, because the result is
    the same failure family this whole file is about. He disabled detection in
    the real guard, left this test untouched, and dropped a genuinely toothless
    test into the suite:

        if not has_assert and not has_call:   ->   if False:

        def test_proves_nothing():
            value = 1 + 1

        14 passed in 0.43s

    A hollow test sat in the suite, the guard that exists to find it was
    disabled, and the test whose entire job is proving the guard works passed
    anyway. It was verifying a copy of the logic while the real check could
    break independently -- "a weaker claim standing in for a stronger one",
    inside the file that names that pattern.

    So this now calls the real function and requires it to FAIL. Break the
    detection and this goes red, because there is no second copy left to pass.
    """
    offender = tmp_path / "test_pretend.py"
    offender.write_text(
        "def test_looks_fine_but_proves_nothing():\n"
        "    value = 1 + 1\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError) as caught:
        test_every_test_can_fail(offender)

    # Not just "it failed" -- it must name the offender, since the message is
    # the whole value of the guard to whoever has to fix it.
    assert "test_looks_fine_but_proves_nothing" in str(caught.value)


def test_the_guard_stays_quiet_on_a_healthy_test(tmp_path: Path):
    """The other half, and also by calling the real function.

    A guard that fires on everything gets switched off within a week, so the
    negative case matters as much as the positive one.
    """
    fine = tmp_path / "test_fine.py"
    fine.write_text(
        "def test_asserts_something():\n"
        "    assert 1 + 1 == 2\n"
        "\n"
        "def test_expects_a_raise():\n"
        "    import pytest\n"
        "    with pytest.raises(ValueError):\n"
        "        raise ValueError('boom')\n",
        encoding="utf-8",
    )

    test_every_test_can_fail(fine)


def test_the_guard_is_actually_pointed_at_some_files():
    """The failure nobody would notice: checking nothing, and passing.

    `test_every_test_can_fail` is parametrised over `_python_test_files()`. If
    that glob ever returns nothing -- a renamed directory, a changed pattern,
    a move of this file -- pytest collects zero cases and the suite stays
    green while the guard protects nothing at all.

    That is the empty-result-reads-as-good-news pattern this project has now
    hit several times: an empty answer meaning "we asked something that could
    not answer" being read as "there is nothing wrong". Cheap to rule out.
    """
    found = _python_test_files()

    assert len(found) >= 5, (
        f"the hygiene guard is only pointed at {len(found)} file(s). "
        "If this glob breaks, every test in it silently stops being checked."
    )
    names = {p.name for p in found}
    assert "test_pfsense_convert.py" in names, (
        "the file whose truncated tests caused this guard to exist is not "
        f"being checked by it. Found: {sorted(names)}"
    )
    assert Path(__file__).name not in names, (
        "the guard must not scan itself -- it would recurse on its own "
        "docstring examples"
    )
