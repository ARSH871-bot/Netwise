"""List open pull requests that are STACKED on another branch, not on main.

WHY THIS EXISTS
    Merging a parent with `--delete-branch` removes the base branch of any
    PR stacked on it. GitHub closes the child automatically, and then
    refuses both repairs:

        gh pr edit <child> --base main
          -> Cannot change the base branch of a closed pull request
        gh pr reopen <child>
          -> Could not open the pull request

    The head branch survives, so nothing is lost but the number, the review
    and the thread. It has happened twice:

        #179  stacked on #178   closed when #178 merged   -> reopened as #187
        #190  stacked on #180   closed when #180 merged   -> reopened as #197

    CONTRIBUTING section 5a has said "retarget a stacked PR to main BEFORE
    you merge its parent" since #188. That rule did not work. It was merged
    to main at 20:43:37Z and broken by its own author at 21:31:13Z, which is
    forty-eight minutes later.

    A rule that lives only in prose is not a control. This is the control.

RUN
    python -m tools.stacked_prs      # either form works
    python tools/stacked_prs.py

    Exits 1 if any open PR is stacked, so it can gate a merge script.
"""

from __future__ import annotations

import json
import subprocess
import sys

# RUN AS A SCRIPT, NOT ONLY AS A MODULE -- see tools/preflight.py and #176.
# This one imports nothing from the package, so the guard is not needed and
# tests/test_tools_invocation.py skips it with a printed reason rather than
# demanding a fix for a bug it cannot have.

#: The branch every PR should normally target.
TRUNK = "main"


def open_pull_requests() -> list:
    """Every open PR, with the branch it targets.

    Returns [] rather than raising when `gh` is unavailable: this is a
    convenience tool, and a machine without the GitHub CLI should be told
    that plainly rather than shown a traceback.
    """
    try:
        result = subprocess.run(
            ["gh", "pr", "list", "--state", "open", "--limit", "100",
             "--json", "number,title,baseRefName,headRefName,author"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"could not run gh: {error}")
        return []
    if result.returncode != 0:
        print(f"gh failed: {(result.stderr or '').strip()[:200]}")
        return []
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return []


def stacked(pull_requests: list) -> list:
    """Those whose base is not the trunk.

    A PR targeting a branch that is ALSO an open PR is the dangerous case --
    merging that parent closes this child. A PR targeting some other branch
    is unusual but not automatically fragile, so both are reported and the
    difference is named rather than collapsed.
    """
    open_heads = {pr["headRefName"]: pr["number"] for pr in pull_requests}
    rows = []
    for pr in pull_requests:
        base = pr["baseRefName"]
        if base == TRUNK:
            continue
        rows.append((pr, open_heads.get(base)))
    return rows


def main() -> int:
    pull_requests = open_pull_requests()
    if not pull_requests:
        print("no open pull requests found (or gh is unavailable)")
        return 0

    rows = stacked(pull_requests)
    print(f"open pull requests: {len(pull_requests)}")

    if not rows:
        print(f"all of them target {TRUNK} -- nothing is stacked, "
              f"nothing can be closed by a merge")
        return 0

    print(f"\n{len(rows)} STACKED -- merging the parent will CLOSE these:\n")
    for pr, parent_number in rows:
        parent = (f"#{parent_number}" if parent_number
                  else "(not an open PR)")
        print(f"  #{pr['number']:<5} {pr['author']['login']:<20} "
              f"base={pr['baseRefName']}")
        print(f"         parent PR: {parent}")
        print(f"         {pr['title'][:66]}")
        print(f"         FIX FIRST: gh pr edit {pr['number']} --base {TRUNK}")
        print()

    print("Retarget these BEFORE merging their parents. Recovering a closed"
          "\nstacked PR is not possible -- gh refuses both `pr edit --base`"
          "\nand `pr reopen` -- so the number and the review thread are lost"
          "\neven though the branch survives.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
