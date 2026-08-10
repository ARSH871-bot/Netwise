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

Then ask someone to review it. Once approved, merge, and delete the branch.

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

**1. Never merge your own pull request.**
One approval from someone else, every time, including documentation. If a change
is genuinely too urgent to wait, say so in the PR and name what made it urgent —
then it is a judgement someone can disagree with, rather than a rule quietly
skipped. *(Broken on #62: reviewers requested, then self-merged before anyone
looked.)*

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

Checked before writing this rule, because the obvious choice is wrong.
`SPRINT2.md` was committed on the sprint's last day, and it **does not contain
#39** — the upload-to-findings integration that the record itself calls the
headline achievement. It landed after the record was written.

Tag the commit that actually has the work. Verify it:

```bash
git merge-base --is-ancestor <the-feature-merge> <the-tag-candidate>
```

### We are not tagging Sprints 1 and 2 retroactively

Deliberate, not an oversight. Sprint 1's boundary commit contains **zero Python
files** — it was environment setup, so `v0.1.0` would announce a release with no
software in it. Sprint 2's honest boundary falls after the sprint ended.

Both options mean encoding a boundary we know to be wrong. **A label that looks
like a fact and is not is the failure mode this project keeps finding**, so we
start tagging from Sprint 3 and leave the earlier history un-labelled rather
than mislabelled.

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

## 6. This is an agreement, not an enforcement

We cannot turn on branch protection — it needs GitHub Pro or a public repo, and
we keep this repo **private** so client configs stay protected. That trade is
deliberate.

So nothing stops you pushing to `main`, self-merging, or merging red. Please
don't. The convention only works because we all keep it — and it is worth being
blunt that the first person to break these rules was the one who wrote them,
which is precisely why they are now written down rather than assumed.
