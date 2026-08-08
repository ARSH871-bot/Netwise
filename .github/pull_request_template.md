<!--
Netwise pull request. The checklist is not bureaucracy -- each line is a rule
that was broken at least once while merging the Sprint 2 queue. See
CONTRIBUTING.md section 5a.

Delete any section that genuinely does not apply, and say why rather than
leaving it blank.
-->

## What this changes

<!-- One paragraph. What was wrong, or what is new. -->

## How it was verified

<!--
Measured, not asserted. Paste the actual output.

  - a test count alone is not verification -- what did you RUN, and what did
    it say before and after?
  - if you fixed a bug, reproduce it against the pre-fix code and show that too
  - if you added a guard, break it deliberately and show the tests failing,
    then restore it
-->

## Before merging

- [ ] **Someone else approved it.** Never merge your own PR.
- [ ] **CI is green**, not pending. `UNSTABLE` means the checks have not finished.
- [ ] The suite passes locally: `pytest tests/ -q`
- [ ] No config data added outside `tests/fixtures/` — see `.gitignore`
- [ ] If this depends on another PR, the description says which, and in what order they must merge

## Findings contract (delete if this touches no check)

- [ ] Findings are built with `analysis/findings.py`, not hand-rolled dicts
- [ ] `found` / `none` / `error` are distinguished — a check that could not run
      must never report `none` (**F-4**)
- [ ] No change to `docs/finding-format.md` — or if there is, **all four members
      have signed**, because that is the one contract
