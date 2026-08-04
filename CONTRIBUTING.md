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

## 5. Config files

Real network configs **never** go in git. Only synthetic fixtures we invented
ourselves belong in `tests/fixtures/`. Everything else lives in `configs/`,
which is ignored. When in doubt, keep it out.

## 6. This is an agreement, not an enforcement

We cannot turn on branch protection — it needs GitHub Pro or a public repo, and
we keep this repo **private** so client configs stay protected. That trade is
deliberate.

So nothing stops you pushing to `main`. Please don't. The convention only works
because we all keep it.
