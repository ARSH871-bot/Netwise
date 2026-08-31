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
`python-multipart` and `ollama` are actually importable, **and separately
whether the installed versions satisfy `requirements.txt`** — both apart from
Docker, the Batfish container and the Batfish service, because all of those
fail separately.

**Those last two are different questions, and the second one caught something
real.** Measured on the SCRUM master's machine on 17 August, while every local
test run was being quoted as evidence:

```
pandas            installed 2.3.3    declared >=3.0.5
fastapi           installed 0.128.0  declared >=0.141.1
uvicorn           installed 0.40.0   declared >=0.52.1
python-multipart  installed 0.0.21   declared >=0.0.32
pytest            installed 9.0.2    declared >=9.1.1
```

Five of seven, and the import check said "all importable" throughout, because
every one of them imports perfectly well. CI installs `requirements.txt` on a
clean machine, so **CI was testing pandas 3.x while the same suite locally was
testing pandas 2.x — both green, and not the same test.** #131 raised that
floor deliberately, and #132 exists because a major pandas bump cannot be
validated on a CI tick.

If the version check is BROKEN, run `pip install -r requirements.txt --upgrade`
before quoting a local number at anyone.

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

**Retarget a stacked PR to `main` BEFORE you merge its parent.** One command,
and skipping it costs the child pull request permanently.

```bash
gh pr edit <child> --base main      # FIRST
gh pr merge <parent> --merge --delete-branch
```

`--delete-branch` removes the parent's head branch, which is the child's *base*.
GitHub then closes the child automatically — and refuses both repairs:

```
gh pr edit 179 --base main   -> Cannot change the base branch of a closed pull request
gh pr reopen 179             -> Could not open the pull request
```

A deadlock: the base cannot be fixed while the PR is closed, and it cannot be
opened while the base is missing. **Measured on #179**, which was stacked on
#178 and approved. No work was lost — the head branch survives, and the same
commits went up again as #187 — but the number, the review, and the discussion
thread did not move with them, and a teammate had to approve an identical tree
twice.

If you have already merged the parent, that is the recovery: open a new PR from
the surviving branch, and comment on the closed one saying which number
replaced it, so the thread is not a dead end for anyone reading back.

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
| **Sprint 1** | `3b08a4c`, 29 Jul 00:27 | 1 (`analysis/smoke_test.py`, since removed from `main` — see `v0.1.0`) | n/a |
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
| **Arsh** | Wrote §5a, raised #99, and has refused to self-merge all week under the old reading | ✅ |
| **Ankeet** | Landed 13 PRs under the old reading, which is the work this removes the need for | ✅ |
| **Samika** | Bound by it equally; asked for rule 3 to be stricter on #63, so has form on this file | ✅ |

> **RATIFIED — four of four.** @SamikaPerera's signature above completed it on
> 17 August, in `021bda8` on this branch. With M-1 ratified, the approved and
> green pull requests held under the old reading — #130, #146, #148, #149,
> #150, #151, #154 — are released for their author to merge, given a **current**
> approving review.
>
> **How it got here is worth keeping.** #156 said plainly: *"Merging this PR
> means the wording is worth having. It does not mean the amendment is
> ratified. That is the A-1 convention, and A-2 is why it matters — that one
> merged with two of four signatures and the record said so for two days."*
>
> It then merged with **two** of four, and this document spent that interval
> stating the new rule 1 in §5a while its own record said the change was not
> agreed. **The amendment's own warning came true about the amendment** — the
> fourth instance of the family this project keeps finding, arriving inside the
> paragraph that describes it.
>
> **And then it happened once more, to the fix.** This paragraph read "NOT YET
> RATIFIED — three of four" for two days after the table above it reached four,
> naming @SamikaPerera as the missing signature he had already given.
> @patelankeet2 caught it on review the same day; @SamikaPerera offered exact
> replacement wording the next morning and flagged it again that evening. The
> author of this PR read neither, and went on reporting "2 of 4" from `main`
> while the branch in front of him said otherwise — measuring the wrong file and
> publishing a conclusion about a person from it.
>
> Meanwhile the rule was already governing merges: **#163 was authored and
> merged by @SamikaPerera on two current approvals**, which is legitimate under
> M-1 and not under the old reading. The practice moved before the record did.
>
> Nothing here blames anyone for the original two-of-four merge. A signature is
> a separate action from a merge, nobody is obliged to notice that, and a table
> is a poor reminder. **The lesson is that "merged" and "agreed" are different
> facts and only one of them is visible on a pull request** — and the corollary,
> learned the hard way here: **check the branch, not `main`, before reporting
> what someone has or has not agreed.**
>
> If A-3 is ever proposed, the ratification row belongs in
> `.github/pull_request_template.md`, read at the moment someone is about to
> merge, rather than in anybody's memory. @shubhamkataria2005 suggested exactly
> that on #102 when A-2 did this, and it was not followed up.

---

## 5e. Verifying a dependency bump CI cannot check

Some bumps cannot be validated by a green tick, and `requirements.txt` says so
in a comment. **A comment is not a checkable artifact** — that is #138's point,
and it is the same shape this project has already found unenforced in a
docstring and a JS comment. So the verification is a checklist you fill in and
paste into the PR, not a claim you make.


### M-2 — define "current", because M-1 delegated it to a feature we do not have

**M-1 is mine, and this corrects it.**

M-1's justification ends:

> GitHub already marks a review stale when the branch moves, so the condition
> is **observable rather than argued**.

That sentence is false for this repository. Auto-dismissing an approval when
new commits arrive is `dismiss_stale_reviews` — a **branch protection**
setting — and no protection is configured:

```
GET /repos/ARSH871-bot/Netwise/branches/main/protection
-> "Not Found"
```

So M-1 made "current" the load-bearing word and then delegated checking it to a
mechanism that has never been switched on. **Nothing marks anything stale.**

> **This paragraph originally said the setting was unavailable "because we are
> deliberately private", citing §6.** The repository is **public**
> (`private: false`), so every protection setting is available and simply off.
> The claim that matters — nothing marks anything stale — was verified against
> the API and stands. The reason given for it was copied from another document
> instead of checked, in an amendment arguing that a fact repeated from another
> document is how facts rot. Corrected after @ARSH871-bot found the same stale
> premise in `CLAUDE.md` §11 (#246). I queried `/branches/main/protection` and
> not `/repos/...` — one call short of the whole answer.
>
> **It changes nothing about the definition below.** Recorded rather than
> silently edited because M-2 is unratified, and an unratified amendment must
> not shift meaning while people are deciding whether to sign it.

**Measured, this week, three times:**

```
#211   approved commit 1; a fix landed after it. The approval stayed green
       over a commit nobody had read. Found by comparing dates by hand.

#213   a push landed 53 seconds after an approval. GitHub recorded the review
       against the NEW head, so it did not even look stale -- the author
       stopped and asked rather than trusting it.

#181   4 commits pushed after a changes-requested   0 reviews, NO request
#183   3 commits pushed after a changes-requested   0 reviews, NO request
       Both sat six days. Chased with thirteen comments between them, into
       threads nobody was notified to reload.
```

#241 fixes the second half — the author re-requests the review. This fixes the
first half: what the reviewer owes when they get it back.

**"Current" means:**

1. **New work pushed since the approval** — the approval is void. Re-review it.
2. **A merge-only push** — re-reading the diff is not required, because there
   is no new work to read. **Confirming the merged result still passes is.**
3. **The reviewer establishes which of the two it is**, by looking, rather than
   accepting the author's description of their own push.

**Why (2) is not "merges are exempt".** A clean merge changes behaviour. From
this week, reviewing #181:

```
merged with main   0 conflicts
result             7 failed, 548 passed
```

`#186` landed a policy fixture omitting `queries`; `#181` made that key
required. Neither PR touched the other's lines, so there was nothing for git to
conflict on — and the merged result was broken. An exemption reading *"only a
merge, nothing you read changed"* waves exactly that through. Nothing anyone
read had changed there either.

**What this costs:** about two minutes, and it replaces re-reading a diff that
is genuinely identical with running the suite on the combination — which is
both cheaper and the check that would have caught #181.

**What it does not fix:** still not enforceable, still §6. And it does not help
a reviewer notice a PR came back — that is #241's half, and the two only work
together.

| Member | Why it touches them | Agreed |
|---|---|---|
| **Shubham** | M-1 is his; this corrects his own justification, and two of the three measurements above are approvals of his that went stale unnoticed | ✅ |
| **Arsh** | Wrote #241's re-request rule, which this is the reciprocal of; stopped on #213 rather than trusting a fresh-looking approval | ⬜ |
| **Ankeet** | Reviews under it, and #211 is the case where a stale tick sat over his branch | ✅ |
| **Samika** | Bound equally; owns the dashboard PRs most often reviewed then fixed | ⬜ |

> **NOT RATIFIED.** One of four. Do not treat the wording above as agreed
> because this merged — that is exactly the A-2 mistake M-1's own record spends
> two paragraphs on, and it would be the fifth instance of the family.

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
because this one is a **second verification by a different method** — the bump
had already been checked in an isolated venv and reported in a
`requirements.txt` comment; this one used the real container.

**Corrected after review.** This paragraph said *"Two people getting the same
answer by different routes"*. It was not two people. @patelankeet2 checked and
both entries are mine — `bd5c0254` (14 August, the `requirements.txt` comment)
and `14b2ff2` (18 August, this checklist). Two methods, one person.

That distinction is the whole subject of this section, so getting it wrong here
is worth leaving on the page rather than quietly rewording. **Two methods rule
out a broken method; two people also rule out a person reading their own result
back.** Only the first claim is supported, and the second is the one the
original sentence made.

He approved the PR and flagged this separately rather than blocking on it,
which is the right call for a framing error in something factually correct —
and it is still the more valuable half of the review.

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

### 6a. What *is* enforced, because a setting can do it

Branch protection is out of reach. These are not, and each one moves a rule out
of "please remember" and into the repository itself. Changed 17 August.

**Merge commits only.** Squash and rebase merging are now switched off.
Measured before changing anything, across the whole history rather than a
sample: **90 merged pull requests, 90 `Merge pull request #N` commits.** Not
one has ever been squashed or rebase-merged. So this makes the setting agree
with what we already do rather than imposing a new habit. It matters because our commit messages carry the
reasoning — squashing a branch would flatten five explained commits into one
subject line, and the explanation is often the most valuable thing in the diff.

This is **not** the same rule as §5a rule 5, which is about how you *update*
your branch (rebase onto `main`, don't merge `main` into your branch). That
still stands. This is about how the PR itself lands.

**Auto-merge stays OFF, deliberately.** It looks like exactly the automation
this section wishes it had, and it is the one piece we must not turn on.
Auto-merge lands a PR the moment its conditions are met — and with no branch
protection, "its conditions" cannot include a passing CI run. It would merge on
approval alone, which is precisely the manual check §5a rule 3a exists to force.
The green tick you are waiting for describes a `main` that may already have
moved. **A gate we cannot configure is worse than no gate**, because it looks
like one.

**Branch deletion on merge is on**, so the branch list stays a list of live
work. 22 stale remote branches were deleted on 16 August; the setting is what
stops them accumulating again.

**Dependabot security alerts and automated security fixes are on** — enabled 17
August, and they were **not** on before, which is worth recording rather than
quietly fixing. `.github/dependabot.yml` has argued since the day it was written
that *"a vulnerable dependency in something that reads firewall configurations
is worse than the same vulnerability elsewhere"*. That file configures **version**
updates: the scheduled Monday bumps. Security **alerts** are a separate switch,
and it was off. So the stated reasoning was real and the mechanism it described
was half-connected — a documented practice standing in for a performed one,
which §5b already names as this project's recurring failure family arriving
through process rather than code. Third instance now.

Secret scanning and push protection are **not** available: they need GitHub
Advanced Security on a private repo. Nothing in git should ever be a secret
here anyway — `.gitignore` was the first commit and `configs/` never enters the
repository — but that is a convention too, and this is a case where we genuinely
cannot back it with a setting.

**Branch protection and rulesets are both genuinely out of reach — checked,
not assumed.** This document has asserted it since it was written, which is
exactly why it was worth testing rather than repeating:

```
GET  /repos/ARSH871-bot/Netwise/rulesets
POST /repos/ARSH871-bot/Netwise/rulesets
  -> 403 "Upgrade to GitHub Pro or make this repository public"
```

Rulesets are the newer mechanism and are gated the same way, so there is no
server-side enforcement available to us at all. That is what §6b is for.

### 6b. What runs on YOUR machine, because nothing runs on the server

Given §6a, every rule we have is either something you remember or a red cross
that arrives after the work is pushed and reviewed. `.pre-commit-config.yaml`
is the third option: checks that run before the commit exists, where a fix
costs seconds instead of a review round trip.

```bash
pip install pre-commit
pre-commit install          # once per clone
pre-commit run --all-files  # check everything without committing
```

It runs the same ruff CI runs — **pinned to the same version and the same
`--select`** — plus merge-conflict markers, oversized files, private keys,
unparseable YAML/JSON/TOML, and the project's own constraint-1 test.

**Two files now pin ruff, and two places pinning one tool will drift.**
`tests/test_repo_config.py` asserts the version *and* the rule set match, so
drift fails a test rather than producing "passes locally, red in CI" — the most
demoralising possible failure of a lint rule, because the author has already
satisfied it.

**One hook was removed after running it, and the reason is instructive.**
`mixed-line-ending` looked obviously right and rewrote 16 files on its first
run, including `.gitignore`, `conftest.py` and five committed fixtures. #126
settled line endings in `.gitattributes`, which normalises on *commit* and
leaves the working tree native — so CRLF in a Windows checkout is correct and
that hook fights it. A test now stops it coming back. **The only way to find
this was to run the thing rather than reason about it.**

**It is opt-in, and nothing installs it for you.** Until you run
`pre-commit install`, that file does nothing. Saying so plainly matters: a
config nobody activated, sitting in the repository looking like coverage, is
precisely the pattern §6a just caught in `dependabot.yml`. **CI remains the
backstop and is not optional.** Skip this and the same ruff runs on your PR,
only later.

**Recommended git settings**, which make two of our conventions the default
rather than something to remember:

```bash
git config pull.rebase true    # §5a rule 5 — rebase, don't merge main into your branch
git config fetch.prune true    # branches are deleted on merge; this drops dead local refs
```

#### Commit signing — recommended, and NOT currently in force

Signed commits give each commit a verified author, which for a capstone is
real evidence of who wrote what. GitHub shows a **Verified** badge.

```bash
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true
```

…then add that public key to GitHub as a **signing key**, not just an
authentication key.

**Written as a recommendation rather than a rule, deliberately.** None of our
existing history is signed, none of us has set this up, and enabling it affects
only future commits. Describing it here as though it were practice would be the
fourth instance of the thing §6a and §5b keep catching — a documented practice
standing in for a performed one. If we adopt it, we adopt it explicitly, and
this paragraph changes to say so.
