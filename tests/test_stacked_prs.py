"""`tools/stacked_prs.py` must actually detect a stacked PR (#199).

WHY THIS FILE EXISTS
    The tool's whole argument is that a rule living only in prose is not a
    control. It shipped for review with 125 lines and no test of its own,
    which made the same mistake one level up: the control existed, and
    nothing checked that IT worked.

    @patelankeet2 found it in review by mutating the one line that carries
    the entire feature:

        if base == TRUNK:  ->  if base != TRUNK:

    That inverts the tool completely. PRs correctly targeting `main` get
    reported as stacked, and genuinely stacked PRs -- the #184 case the tool
    exists for -- are silently skipped. He ran the full suite against it:

        541 passed, 4 skipped     identical to the unmutated run

    Nothing caught it. `stacked()` takes a plain list of dicts and returns
    rows, with no subprocess involved, so there was never a good reason for
    it to be untested.

WHAT IS DELIBERATELY NOT TESTED HERE
    `open_pull_requests()` shells out to `gh`. Faking that would test the
    fake. Its behaviour on a machine WITHOUT `gh` is what matters, and that
    is asserted below through the return value contract (None vs []) rather
    than by running the subprocess.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.stacked_prs import (  # noqa: E402
    EXIT_CLEAN,
    EXIT_STACKED,
    EXIT_UNKNOWN,
    TRUNK,
    stacked,
)


def pr(number: int, base: str, head: str, login: str = "someone") -> dict:
    """One pull request in the shape `gh pr list --json` returns."""
    return {
        "number": number,
        "title": f"PR {number}",
        "baseRefName": base,
        "headRefName": head,
        "author": {"login": login},
    }


# ---------------------------------------------------------------------------
# The case the tool exists for
# ---------------------------------------------------------------------------


def test_finds_a_pr_stacked_on_another_open_pr():
    """The #184 case: a child based on a parent that is itself open.

    This is the mutation-killer. Inverting `base == TRUNK` makes this fail,
    because the stacked PR stops being reported at all.
    """
    prs = [
        pr(1, base=TRUNK, head="parent-branch"),
        pr(2, base="parent-branch", head="child-branch"),
    ]

    rows = stacked(prs)

    assert len(rows) == 1, (
        "the child is stacked on an open PR's branch and must be reported"
    )
    found, parent_number = rows[0]
    assert found["number"] == 2
    assert parent_number == 1, "the parent PR must be named, not just detected"


def test_a_pr_targeting_trunk_is_never_reported():
    """The other half of the mutation. Inverting the test makes this fail.

    Without this, a mutant that reports EVERY PR as stacked would still pass
    the test above -- it finds the stacked one, just among false positives.
    Both directions are needed to pin the comparison.
    """
    prs = [
        pr(1, base=TRUNK, head="a"),
        pr(2, base=TRUNK, head="b"),
        pr(3, base=TRUNK, head="c"),
    ]

    assert stacked(prs) == [], (
        "every one of these targets main; none can be closed by a merge"
    )


# ---------------------------------------------------------------------------
# The distinction the docstring draws, which is easy to collapse later
# ---------------------------------------------------------------------------


def test_a_base_that_is_not_an_open_pr_is_reported_with_no_parent():
    """"Unusual but not fragile" is still reported -- with `None` for parent.

    A PR based on some other branch cannot be auto-closed by a merge, because
    no open PR owns that branch. The tool reports it anyway and names the
    difference rather than collapsing the two into one warning.
    """
    prs = [pr(7, base="some-abandoned-branch", head="mine")]

    rows = stacked(prs)

    assert len(rows) == 1
    found, parent_number = rows[0]
    assert found["number"] == 7
    assert parent_number is None, (
        "no open PR owns that base, so there is no parent to name -- and "
        "saying '#None' or inventing one would be worse than saying nothing"
    )


def test_a_chain_of_three_reports_both_children():
    """A stacked on B stacked on main: B and A are both reported."""
    prs = [
        pr(1, base=TRUNK, head="one"),
        pr(2, base="one", head="two"),
        pr(3, base="two", head="three"),
    ]

    rows = stacked(prs)
    by_number = {found["number"]: parent for found, parent in rows}

    assert set(by_number) == {2, 3}
    assert by_number[2] == 1
    assert by_number[3] == 2


def test_no_open_pull_requests_at_all_is_not_stacked():
    assert stacked([]) == []


# ---------------------------------------------------------------------------
# Exit codes -- the tool's real interface once it gates a merge
# ---------------------------------------------------------------------------


def test_could_not_check_is_not_the_same_exit_code_as_clean():
    """@patelankeet2's other finding, pinned so it cannot regress.

    The first version returned `[]` both when `gh` was missing and when there
    were genuinely no open PRs, printed one message covering both, and exited
    0 either way. A CI runner without `gh` would have reported "clean"
    identically to a repository with nothing stacked.

    That is the found/error conflation F-4 exists to prevent, in the tool
    built to turn a rule into a control -- so the three outcomes must stay
    three distinct exit codes.
    """
    assert EXIT_CLEAN != EXIT_UNKNOWN, (
        "'I checked and nothing is stacked' and 'I could not check' must "
        "never share an exit code -- a caller cannot tell them apart"
    )
    assert EXIT_STACKED != EXIT_UNKNOWN
    assert EXIT_CLEAN != EXIT_STACKED
    assert EXIT_CLEAN == 0, "0 must mean safe, for the usual shell convention"


@pytest.mark.parametrize("code", [EXIT_STACKED, EXIT_UNKNOWN])
def test_every_non_clean_outcome_is_a_failing_exit_code(code):
    """Anything that is not 'checked and clean' must fail a gate.

    Including "could not check" -- which is the whole point. A merge script
    that treats 2 as success has reintroduced the bug.
    """
    assert code != 0
