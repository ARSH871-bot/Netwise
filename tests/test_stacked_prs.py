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

from tools import stacked_prs  # noqa: E402
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


#: What `main()` must return for each state `open_pull_requests()` can be in.
#:
#: THESE DRIVE main() ITSELF, AND THE FIRST VERSION DID NOT.
#:     It read:
#:
#:         assert EXIT_CLEAN != EXIT_UNKNOWN
#:         assert EXIT_STACKED != EXIT_UNKNOWN
#:         assert EXIT_CLEAN != EXIT_STACKED
#:
#:     which compares three constants to each other and is true no matter
#:     what `main()` does. @patelankeet2 found it the same way he found the
#:     first bug -- by mutating the real code rather than reading the test:
#:
#:         if pull_requests is None:      ->   if pull_requests is None and False:
#:
#:     `None` is falsy, so that falls straight through to `if not
#:     pull_requests:` and reports EXIT_CLEAN -- the exact collapse this tool
#:     was written to prevent, reintroduced one function up, with the suite
#:     still green:
#:
#:         before  555 passed, 6 skipped
#:         after   555 passed, 6 skipped
#:
#:     Same shape as the `x in (None, x)` tautology from #179: a test that
#:     describes the property in English and pins a fact that cannot fail.
_STATES = [
    (None, EXIT_UNKNOWN, "gh missing or failing -- nothing is known"),
    ([], EXIT_CLEAN, "asked, and there are genuinely no open PRs"),
    ([pr(1, base=TRUNK, head="a")], EXIT_CLEAN, "all target main"),
    ([pr(1, base=TRUNK, head="a"), pr(2, base="a", head="b")],
     EXIT_STACKED, "one is stacked on another open PR"),
]


@pytest.mark.parametrize("returned,expected,description", _STATES)
def test_main_returns_the_right_exit_code_for_each_state(
        monkeypatch, capsys, returned, expected, description):
    """Drive `main()`, not the constants.

    Asking "what states can the input actually be in" gives exactly four, and
    each one has a different correct answer. The dangerous pair is the first
    two: `None` and `[]` are both falsy, so any test that does not
    distinguish them lets the collapse back in.
    """
    monkeypatch.setattr(stacked_prs, "open_pull_requests", lambda: returned)

    assert stacked_prs.main() == expected, (
        f"main() returned the wrong exit code for: {description}"
    )


def test_could_not_check_never_reports_itself_as_clean(monkeypatch, capsys):
    """The one that matters, stated on its own so it cannot be lost in a list.

    A caller cannot tell "I checked and nothing is stacked" from "I could not
    check" if they share an exit code -- and a merge gate that treats them
    alike is not a gate.
    """
    monkeypatch.setattr(stacked_prs, "open_pull_requests", lambda: None)

    code = stacked_prs.main()
    printed = capsys.readouterr().out

    assert code != EXIT_CLEAN, (
        "a run that could not ask GitHub anything reported the same exit "
        "code as a run that checked and found nothing"
    )
    assert code == EXIT_UNKNOWN
    assert "NOT" in printed and "nothing is stacked" in printed, (
        "the output must say in words that this is not an all-clear, because "
        "a human reading the terminal never sees the exit code"
    )


def test_zero_still_means_safe():
    """The shell convention, kept deliberate rather than incidental."""
    assert EXIT_CLEAN == 0
    assert EXIT_STACKED != 0 and EXIT_UNKNOWN != 0
