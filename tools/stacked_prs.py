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

    Exit codes, so it can gate a merge script:

        0  checked, nothing stacked      -- safe to merge
        1  checked, found stacked PRs    -- retarget them first
        2  COULD NOT CHECK               -- `gh` missing or failing

    2 is not 0. A run that could not ask GitHub anything knows nothing, and
    must never read as "clean" -- see `open_pull_requests()`.
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


def open_pull_requests():
    """Every open PR with the branch it targets, or None if we could not ask.

    NONE AND [] ARE DIFFERENT ANSWERS, AND THAT IS THE WHOLE POINT.
        `None`  we could not find out. Nothing is known.
        `[]`    we asked, and there genuinely are no open pull requests.

        The first version returned `[]` for both, and `main()` printed one
        message -- "no open pull requests found (or gh is unavailable)" --
        and exited 0 either way. @patelankeet2 found it by running the tool
        on a machine with no `gh` installed, and named it exactly right: that
        is the found/error conflation F-4 exists to prevent, inside the tool
        built to turn a rule into a control.

        A CI runner without `gh` on PATH would have reported "clean" in the
        same words, and with the same exit code, as a repository with nothing
        stacked. A merge gate that cannot tell "I checked" from "I could not
        check" is not a gate.
    """
    try:
        result = subprocess.run(
            ["gh", "pr", "list", "--state", "open", "--limit", "100",
             "--json", "number,title,baseRefName,headRefName,author"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"COULD NOT CHECK: could not run gh: {error}")
        return None
    if result.returncode != 0:
        print("COULD NOT CHECK: gh failed: "
              f"{(result.stderr or '').strip()[:200]}")
        return None
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError as error:
        print(f"COULD NOT CHECK: gh returned unreadable JSON: {error}")
        return None


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


#: Exit codes, which are this tool's real interface once it is a merge gate.
#:
#:   0  checked, nothing stacked        -- safe to merge
#:   1  checked, found stacked PRs      -- fix them first
#:   2  COULD NOT CHECK                 -- know nothing; do not read as safe
#:
#: 2 exists because of @patelankeet2's review. Without it, a caller cannot
#: distinguish the two answers that matter most, which is the same reason
#: F-4 has three states rather than two.
EXIT_CLEAN, EXIT_STACKED, EXIT_UNKNOWN = 0, 1, 2


def main() -> int:
    pull_requests = open_pull_requests()

    if pull_requests is None:
        # The message naming the cause was already printed by the caller
        # above; this says what it MEANS, which is the part a reader acts on.
        print("\nNothing is known about whether any PR is stacked. This is "
              "NOT\nthe same as 'nothing is stacked' -- do not merge on the "
              "strength\nof this run. Install the GitHub CLI, or check the "
              "base branches by\nhand before merging anything.")
        return EXIT_UNKNOWN

    if not pull_requests:
        print("checked: there are no open pull requests at all, "
              "so nothing can be stacked")
        return EXIT_CLEAN

    rows = stacked(pull_requests)
    print(f"open pull requests: {len(pull_requests)}")

    if not rows:
        print(f"all of them target {TRUNK} -- nothing is stacked, "
              f"nothing can be closed by a merge")
        return EXIT_CLEAN

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
    return EXIT_STACKED


if __name__ == "__main__":
    sys.exit(main())
