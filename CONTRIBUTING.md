# Contributing to Netwise

For Ankeet, Shubham and Samika — read this before your first commit. It is short.

---

## 1. Nobody commits directly to `main`

Every story gets its own branch, and reaches `main` through a pull request that
**at least one other member reviews**.

```bash
git checkout main
git pull                                   # start from the latest main
git checkout -b feat/us-11-routing-check   # feat/<story>-<short-description>

# ... do the work ...

git add analysis/checks/routing.py
git commit -m "US-11: add routing check"
git push -u origin feat/us-11-routing-check

gh pr create --fill                        # or open the PR on github.com
```

Then ask someone to review it. Once approved, merge. GitHub deletes the branch
for you — "Automatically delete head branches" is on.

### Open the pull request as soon as you push, even as a draft

`gh pr create --draft` costs nothing and is the difference between work that
exists and work that is *visible*.

**A pushed branch with no PR is invisible to everything.** It is not on the
board, not in the queue, not in anyone's review list, and not in any list this
project keeps. Nobody has to ignore it — they simply never see it.

Two pieces of real work were found that way, both by accident, both while
looking for something else:

| | |
|---|---|
| `docs/a1-ratified-and-sprint3-scope` | a fix written and never opened. `main` contradicted itself about A-1 for two days — telling two people they still owed signatures they had already given (#97) |
| `docs/explanation-delivery` | Samika's design proposal with three options, a recommendation and a sign-off table, unmerged since 6 August. Its constraint 2 predicted #92, which was then filed six days later as a fresh finding (#135) |

Neither was anyone's fault, and neither would have happened if the PR had been
opened at push time. A draft says "this exists and is not ready"; a branch with
no PR says nothing at all.

### Why this matters here specifically

**All four of us add our check to the same `CHECKS` registry in
`analysis/pipeline.py`.** That one dictionary is the most likely place our work
collides. If two people edit `main` directly on the same afternoon, one of us
loses work or spends an evening untangling a conflict.

Branches keep the collision contained to one file in one PR, where git shows it
clearly and a reviewer can resolve it deliberately. This is the single biggest
practical reason for the rule.

## 2. Do not use VS Code's "Sync" button

It pushes automatically, without you deciding to. On a shared `main` that means
work reaching everyone else before it is ready, or before anyone has reviewed
it.

**Commit locally, then push on purpose** — `git push`, when you mean it.

## 3. How to add your check

A check is **one file with one function**. That is the whole contract.

1. Copy [`analysis/checks/access_control.py`](analysis/checks/access_control.py).
   It is written to be the template.
2. Write your function:

   ```python
   def run(bf: Session) -> list[dict]:
       ...
   ```

   You get a live Batfish session with the snapshot already loaded. You do
   **not** connect, load snapshots, or catch your own crashes — the pipeline
   does all of that. If your check raises, the pipeline turns it into a
   `status="error"` finding, so a bug in your code cannot break anyone else's.

3. Return findings built with the helpers in
   [`analysis/findings.py`](analysis/findings.py). They must match
   [`docs/finding-format.md`](docs/finding-format.md) — **that document is the
   contract, and it needs all four of us to change.**

   Pay particular attention to `status`:

   | `status` | Meaning |
   |---|---|
   | `found` | You ran and found a problem |
   | `none` | You ran and found nothing — good news |
   | `error` | You **could not** run |

   `none` and `error` must never be confused. "We checked and found nothing"
   and "we could not check" are different claims, and mixing them up is how a
   security tool tells someone they are safe when nobody looked.

4. Add **one line** to the `CHECKS` dictionary in `analysis/pipeline.py`.

## 4. Running the pipeline

```bash
python -m analysis.pipeline tests/fixtures/rtr-us5-secure     # clean config
python -m analysis.pipeline tests/fixtures/rtr-us5-insecure   # has a real flaw
python -m analysis.pipeline tests/fixtures/rtr-us5-messy      # dead rules + undefined ACL
python -m analysis.pipeline tests/fixtures/unparseable        # fails to parse
```

## 4a. Running the tests

```bash
pytest tests/ -v
```

They need **neither Batfish nor Docker** and finish in about a second, so
there is no excuse for not running them before opening a PR.

**Check your environment first, and check it again if a number surprises you:**

```bash
python -m tools.preflight
```

It reports whether `pybatfish`, `pandas`, `fastapi`, `uvicorn`,
`python-multipart` and `ollama` are actually importable — separately from
Docker, the Batfish container and the Batfish service, because those fail
separately.

**This is here because it was missing, and the gap cost something real.** The
README has pointed at `preflight` since it was written; this file — the one
that says *"read this before your first commit"* — never mentioned it. A
teammate with three packages missing had four test files failing to collect
and reported the suite as **295 tests** in a status update. It was 370.

Two things worth taking from that. **`pytest` does not hide a collection
error** — it prints them next to the pass count — but a summary line is
skimmed, and "295 passed" reads like success. And the failure ran in the safe
direction: it **understated** what the project does. Nobody fact-checks a
smaller number, so it survived into a status update and was heading for the
report.

If a count here ever disagrees with CI, believe CI and run `preflight`. CI
installs `requirements.txt` on a clean machine every time, which is precisely
the thing your laptop stops doing after the first week.

**Please add tests with your check.** The suite exists because a real bug —
two findings sharing an `id` — sat in the code for days, survived a review, and
was only caught when someone built a dashboard and looked at the data. Every
verification before that had been done by hand.

You do not need to test against Batfish. The most valuable tests are the ones
that need nothing running: give your function a hand-built input and assert it
returns the right findings. `tests/test_finding_ids.py` is written that way and
is a reasonable model to copy.

Run it from the repository root. Batfish must be running:
`docker start batfish`. The first snapshot load after starting the container
takes a few minutes while its JVM warms up — that is normal, not a hang.

## 4b. CI runs your tests automatically

Every pull request runs the suite on Python **3.12 and 3.13** — see
`.github/workflows/tests.yml`. You will see a green tick or a red cross on your
PR without doing anything.

**It cannot block a merge.** Required status checks need branch protection,
which needs GitHub Pro or a public repo, and we are deliberately private so
client configs stay protected (§6). So a red cross is a *signal*, not a gate —
the same standing as everything else in this document. Please treat it as one.

**If a test ever needs a live Batfish or Ollama, put it behind a separate,
manually-triggered workflow** rather than adding it here. The first snapshot
load against a cold container takes minutes and the service went down three
times during development. Flaky CI gets ignored, which is worse than no CI.

CI earned its place on its very first run: it caught that `pytest tests/` — the
command this document tells you to use — failed on a clean machine, because
`python -m pytest` puts the repo root on `sys.path` and the bare command does
not. Nobody would have found that locally, because the thing that made it work
was the thing we all did without thinking.

## 5. Config files

Real network configs **never** go in git. Only synthetic fixtures we invented
ourselves belong in `tests/fixtures/`. Everything else lives in `configs/`,
which is ignored. When in doubt, keep it out.

## 5a. The merge rules

Five rules. They exist because each one was broken at least once on 6 August,
by the person who wrote this file, while merging a fourteen-PR queue. They are
written down because **GitHub cannot enforce any of them here** — see §6.

**1. Never merge your own pull request without a current approving review
from someone else.**
One approval, every time, including documentation. **Current** means no commits
pushed since it — GitHub marks a review stale when the branch moves, so this is
observable rather than a judgement call. With a current approval and green CI,
the author may press the button.

If a change is genuinely too urgent to wait for review, say so in the PR and
name what made it urgent — then it is a judgement someone can disagree with,
rather than a rule quietly skipped. *(Broken on #62: reviewers requested, then
self-merged before anyone looked.)*

**Why the wording changed — see §5d.** The original said "never merge your own",
which read as *someone else must press the button*. Combined with rule 4, that
made a queue of one author's approved work unlandable by anyone but volunteers,
which is the state #99 recorded.

**2. Wait for CI to go green before merging.**
`MERGEABLE / UNSTABLE` means the checks have not finished. A local `pytest` run
is not a substitute — the entire point of CI is that it runs somewhere that is
not your machine, on both 3.12 and 3.13. *(Broken on #58, #54, #62: all merged
while pending. They passed afterwards, which was luck.)*

**3. Ask before rewriting someone else's branch — every time, no exception.**
If their PR needs a rebase, ask them and wait. Not "ask unless it is blocking":
**asked and waited, always.** If it is genuinely holding up a queue, say that
when you ask and they can prioritise it — that is their call to make, not
yours.

This rule is stricter than the first draft, at Ankeet's request on #63. The
draft let you rebase without asking when the author was unavailable and it was
blocking, with `--force-with-lease` and a comment afterwards. His answer, and it
is the right one: *"I'd just rather be asked before it happens than told
after."* Disclosure after the fact is a mitigation, not consent, and the escape
hatch would have covered the exact case where it was broken.

If you ever do rewrite a branch — with permission — use `--force-with-lease`,
never bare `--force`. *(Broken on #54 and #58.)*

**3a. If `main` moved since your last push, re-run the checks before merging.**
A green tick describes this PR merged with `main` **as it was when the tick was
earned**. GitHub's `pull_request` event tests `refs/pull/N/merge`, which is
computed at event time — if `main` moves afterwards, the tick describes a
combination that no longer exists.

This is not theoretical. It produced two red `main`s in two days, both the same
shape:

```
#84  and #89   each passed alone, failed together
#104 last commit 23:51   <- its CI tested main as of 23:51
#84  merged      00:06   <- after that
#104 merged      00:40   <- the combination was never tested
```

Both times a test's *restoration* met a *behaviour change* that invalidated it.
Neither author could have seen it; neither branch was wrong.

`.github/workflows/tests.yml` now merges `origin/main` before running, so a
**re-run** tests against `main` as it is now rather than repeating the stale
answer. That makes this rule actionable rather than a plea for care:

```bash
gh pr checks <n> --watch      # after re-running, if main moved
```

It is still not a gate — branch protection needs GitHub Pro (§6). It is a
signal that is now telling the truth about the right thing.

**4. Merge small and merge often.**
A queue of fourteen approved PRs produced three simultaneous conflicts in the
same test file. None of them were hard; all of them were avoidable. If something
is approved and green, land it.

**5. Rebase to resolve, don't merge `main` into your branch.**
Keeps feature branches linear and keeps the PR diff showing your work rather
than everyone else's. When you rebase a branch that was built on another PR,
rebase only your own commits:

```bash
git rebase --onto origin/main <the-other-prs-old-head> <your-branch>
```

### Two habits worth copying

**Commit before you experiment.** `git checkout -- <file>` on an *uncommitted*
file destroys the work, not just the experiment. Commit, then break things.

**Stack deliberately when work depends on unmerged work.** Branch from the PR
you depend on, say so in the description, and name the merge order. Writing
documentation that describes behaviour not yet on `main` is how this repo has
gone wrong before.

## 5b. Releases, tags, and why there are no packages

We tag a release at the **end of each sprint**, once that sprint's work is
actually on `main`. Nothing else gets a tag.

```bash
git tag -a v0.3.0 -m "Sprint 3"      # on the real last commit of the sprint
git push origin v0.3.0
gh release create v0.3.0 --title "Sprint 3" --notes-file docs/sprint3/SPRINT3.md
```

**Version numbers are sprint-aligned and pre-1.0.** `v0.<sprint>.<patch>`.
There is no 1.0 until the client can run this against his own firewall.

### Why a tag is worth the two minutes

Without one, *"the product as it was when we demoed to Senaka"* is only
recoverable by reading merge dates and guessing. With one it is a fixed,
citable commit — which matters in the report and matters more in a defence.

### The tag goes on the last commit of the sprint's WORK, not its record

The obvious choice — the commit that adds `SPRINTn.md` — is wrong, and this
document got it wrong first time round. Ankeet and Samika both caught it.

**State the timezone.** The team is in NZT (+1200), and a bare date is
ambiguous: `--before=2026-08-06` returned a commit that is 6 August in *both*
NZT and UTC, i.e. outside the sprint. If `merge-base` is meant to remove
ambiguity about the boundary, the window feeding it cannot reintroduce it.

```bash
LAST=$(git log origin/main   --since="2026-07-30T00:00:00+12:00"   --until="2026-08-06T00:00:00+12:00"   --format='%h' -1)

git merge-base --is-ancestor <the-sprint-s-headline-merge> $LAST   # verify
```

### Both earlier sprints ARE tagged retroactively, and here is the correction

An earlier draft of this section argued *against* retroactive tags, on two
worked examples that were both wrong — and wrong by using the record commit as
the boundary, which is the exact mistake the rule above exists to prevent. The
document was demonstrating the error it was written to stop.

Corrected, measured with the recipe above:

| | Real last commit (NZT) | Python files | Contains the headline merge |
|---|---|---|---|
| **Sprint 1** | `3b08a4c`, 29 Jul 00:27 | 1 (`analysis/smoke_test.py`) | n/a |
| **Sprint 2** | `a2d36fd`, 5 Aug 22:22 | 18 | **yes** — `#39` is an ancestor |

So the case against tagging dissolved once the facts were right:

- **Sprint 2's boundary does contain #39.** The record was written, then
  corrected the same day *because of* #39 — six minutes after it merged — and
  `SPRINT2.md` still carries that sentence. Nothing about it falls outside the
  sprint.
- **Sprint 1 has one Python file**, not zero — a connectivity smoke test. That
  does not make "a release with no software" right in substance, but the number
  was wrong and the reasoning rested on it.

**Tag both**, with release notes that say what each sprint actually delivered —
Sprint 1's deliverable was a verified environment, not an application, and the
note should say so rather than let a version number imply otherwise.

### No CHANGELOG.md

Our PR descriptions are thorough and the sprint records already narrate each
sprint. A changelog would be the same facts in a third place, and *a fact stored
twice is the documented cause of every staleness bug we have had* (§6 and
`CLAUDE.md` §11). GitHub Releases render the history without us maintaining it.

### No Packages, and this is a decision rather than an omission

Netwise is not a library anyone installs. It is an application you run against
your own Batfish and Ollama on your own machine, and the whole premise is that
nothing leaves it. Publishing to a registry would add a distribution channel
nobody wants and invite exactly the "just pip install it" workflow the offline
constraint exists to prevent.

Recorded here so a reviewer can tell "we chose not to" from "nobody thought of
it" — those look identical in an empty Packages tab.

## 5c. Keeping the record honest after a change

A document that lags reality does not merely mislead — it gets quoted into a
team update, a client report, or the capstone write-up before anyone notices.
Every staleness incident on this project was caught by someone reading
carefully, never by a tool.

**After a change lands, update what records it:**

| Changed | Also update |
|---|---|
| a check, the pipeline, the AI layer | `CLAUDE.md` §11, and §7a/§7b/§7c if behaviour changed |
| anything measured | `docs/evaluation.md` — **re-run it, do not reword it** |
| a decision | move it from "Open decisions" to "Settled" in `CLAUDE.md` |
| what an issue really is | the issue, its milestone, and the board's columns and fields |
| work landing | the sprint record in `docs/sprintN/` |
| the contract | `docs/finding-format.md` **and** its ratification table (all four) |

Board fields that get forgotten: **Start date and Target date** — the Roadmap
view is blank without them — plus Priority, Size, and adding open PRs as items.
Merged PRs move themselves; the seven automation workflows are enabled.

### But the real fix is removing the duplicate

Every one of those incidents had the same cause: **a fact stored in two places
and only one copy updated.** A longer checklist fights the symptom.

So before writing a fact into a second file, ask whether the first can be its
only home. `CLAUDE.md` §11 says *"for the count, run it"* rather than quoting a
test number, precisely because a number written there rots the next time anyone
adds a test.

### Do not trust the documents — re-derive

```bash
sed -n '/^CHECKS = {/,/^}/p' analysis/pipeline.py   # what actually runs
pytest tests/ -q                                     # what is actually tested
git log --oneline origin/main -1                     # where main actually is
gh pr list --state open && gh issue list --state open
```

**If a document disagrees with those, the document is the bug.**


## 5d. Amendment record for §5a

The merge rules are a shared agreement, so changing one needs **all four of
us** — the same reasoning `docs/finding-format.md` uses for F-1, and the same
mechanism: a table anyone can check, rather than agreement inferred from a PR
having been merged quietly.

**Merging this PR means the wording is worth having. It does NOT mean the
amendment is ratified.** Ratification is the table below.

### M-1 — rule 1 requires a current review, not a second pair of hands

Changes rule 1 from *"never merge your own pull request"* to *"never merge your
own pull request without a current approving review from someone else"*.

**What this changes:** with a current approval and green CI, the author may
merge. Nothing else moves — one approval is still required every time, and the
urgency escape hatch is unchanged.

**Why.** Rule 1's purpose is independent **review**, not an independent mouse
click. The violation it records is #62 — *reviewers requested, then self-merged
before anyone looked* — where the fault was merging **unreviewed**, not merging.

Read as "someone else presses the button", rule 1 contradicted rule 4 outright
whenever one person authored most of the open work: rule 4 says land approved
and green work, rule 1 said the author may not, and there was nobody obliged to
do it instead. #99 recorded that state at nine PRs; it reached fourteen twice.

**Why "current" is load-bearing.** Without it, a stale approval satisfies the
rule. That is not hypothetical — four PRs were approved, then had fixes pushed
in response to those reviews, and GitHub re-requested review on all four. The
earlier approval plus green CI would have licensed self-merging code nobody had
read, which is #62 exactly. GitHub already marks a review stale when the branch
moves, so the condition is observable rather than argued.

**What it does not fix.** Nothing here is enforceable — §6 still applies, and
this remains an agreement we keep because we keep it. It also does not address
the thing underneath: work that only one person produces will queue behind
three people who review in bursts, and no rule changes that.

| Member | Why it touches them | Agreed |
|---|---|---|
| **Shubham** | Proposed the "current" condition after four of his approvals went stale | ✅ |
| **Arsh** | Wrote §5a, raised #99, and has refused to self-merge all week under the old reading | ⬜ |
| **Ankeet** | Landed 13 PRs under the old reading, which is the work this removes the need for | ✅ |
| **Samika** | Bound by it equally; asked for rule 3 to be stricter on #63, so has form on this file | ⬜ |

---

## 5e. Verifying a dependency bump CI cannot check

Some bumps cannot be validated by a green tick, and `requirements.txt` says so
in a comment. **A comment is not a checkable artifact** — that is #138's point,
and it is the same shape this project has already found unenforced in a
docstring and a JS comment. So the verification is a checklist you fill in and
paste into the PR, not a claim you make.

### When this applies

- A **major** version bump of anything whose real behaviour lives outside CI:
  `pandas` (Batfish answers arrive as DataFrames), `pybatfish` (pinned, must
  match the container), `fastapi` (the endpoints are only exercised against a
  real snapshot).
- Any bump where you cannot say what would break if it were wrong.

A patch or minor floor raise on something CI genuinely exercises does not need
this. Say so in the PR rather than filling the form in with shrugs.

### The checklist — paste it into the PR and fill it in

```
Dependency:            <name>  <old> -> <new>
Verified by:           <who>          Date: <when>
Environment matches requirements.txt: python -m tools.preflight   -> OK / BROKEN

[ ] Full suite on the NEW version          <count> passed
[ ] Real Batfish pipeline, not fakes       <fixtures run, statuses>
[ ] The feature that touches it most       <what, and the result>
[ ] End to end through the web layer       <upload -> findings -> ask>
[ ] Results identical to the old version?  yes / no -- if no, what differs
```

**The third and fourth lines are the ones that matter.** The suite passing on a
new major mostly proves the tests that do *not* use the dependency still pass —
`tests/` uses fakes for DataFrames, so on a pandas bump the unit suite is
nearly silent about the thing being bumped.

### Worked example — pandas `>=2.0` → `>=3.0.5` (#131)

Recorded here because a filled-in example is worth more than a blank form, and
because this one is a **second, independent** verification of a bump that had
already been checked in an isolated venv and reported in a `requirements.txt`
comment. Two people getting the same answer by different routes is what makes
the comment trustworthy.

```
Dependency:            pandas  2.3.3 -> 3.0.5
Verified by:           Arsh            Date: 17 August 2026
Environment matches requirements.txt: OK (after upgrading; it was BROKEN before)

[x] Full suite on the NEW version          375 passed, ruff clean
[x] Real Batfish pipeline, not fakes       rtr-us5-insecure  {found 5, error 1}
                                           rtr-us5-messy     {found 6, error 1}
                                           routing-missing-route {found 1, error 2}
                                           unparseable       {error 3}
[x] The feature that touches it most       change_impact: CH-001 high, CH-002 high
[x] End to end through the web layer       upload 200 -> {found 5, error 1};
                                           /api/ask grounded=True
[x] Results identical to the old version?  yes -- every count and severity
```

**How this bump was found to need re-checking at all** is the part worth
keeping. The local environment had pandas 2.3.3 while `requirements.txt`
declared `>=3.0.5`, so every local run was quietly testing the *old* major
while CI tested the new one — both green, on the same commit, measuring
different things. `tools/preflight.py` reported "all importable" because they
all import perfectly well. That gap is closed by the version check added in
#162; **before quoting a local number, run `python -m tools.preflight`.**

---

## 6. This is an agreement, not an enforcement

We cannot turn on branch protection — it needs GitHub Pro or a public repo, and
we keep this repo **private** so client configs stay protected. That trade is
deliberate.

So nothing stops you pushing to `main`, self-merging, or merging red. Please
don't. The convention only works because we all keep it — and it is worth being
blunt that the first person to break these rules was the one who wrote them,
which is precisely why they are now written down rather than assumed.
