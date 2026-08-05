# Proposal: three shapes for pipeline features

**Status:** PROPOSAL — for team decision. Nothing is built against this yet.
**Raised by:** Arsh (pipeline owner)
**Needs:** all four, because it changes what "add your check" means.
**Blocking:** Samika's severity ruleset cannot be written until this is settled.

---

## The problem, in one line

**Two of our five registered checks cannot honour the contract we all agreed to.**

`analysis/pipeline.py` promises every feature the same deal:

```python
def run(bf: Session) -> list[dict]
```

*"You get a Batfish session with one snapshot loaded. Give back findings."*

That works for three features. It cannot work for the other two, and **for two
different reasons** — which is what makes this a design question rather than two
bugs.

| Feature | Owner | Fits `run(bf)`? | Why not |
|---|---|---|---|
| `access_control` | Arsh | ✅ | — |
| `routing` | Ankeet | ✅ | — |
| `policy_compliance` | Shubham | ✅ | — |
| `change_impact` | Shubham | ❌ | `differentialReachability` needs **two** snapshots; the registry supplies one |
| `risk` | Samika | ❌ | Risk prioritisation needs **everyone else's findings**; the registry supplies a Batfish session |

The contract quietly assumed every feature is *"session in, findings out"*. Two
of them aren't, and they were the last two written — so the assumption held
right up until it didn't.

## Why not just patch each one

We could give `change_impact` a second snapshot, and give `risk` some way to see
the findings. Two special cases in a five-entry registry is not a pattern worth
defending, and each patch would put an unused parameter on the three checks that
never need it.

The honest reading is that we have **three kinds of thing**, and only one of them
is a check.

## The proposal — name the three shapes

### 1. Producers — `bf → findings`

What we already have. Reads one snapshot, returns findings about it.

```python
def run(bf: Session) -> list[dict]
```

**Members:** `access_control`, `routing`, `policy_compliance`
**Registered in:** `CHECKS`
**Changes for these three: none.** This is the point of the proposal — the
people who fit the contract keep the contract exactly as it is.

### 2. Post-processor — `findings → findings`

Runs **after** the producers, over the combined list. Can re-rate, re-order,
annotate, or add findings of its own.

```python
def refine(results: list[dict]) -> list[dict]
```

**Member:** `risk`
**Hooks in at:** `analysis/pipeline.py`, immediately after the check loop, where
the combined list already exists.

This is the only shape in which risk prioritisation can do its actual job.
Registered as a peer check it would be the one check unable to see what it is
supposed to prioritise.

### 3. Differential entry point — `(before, after) → findings`

Not part of an audit run at all. A separate top-level function.

```python
def analyse_change(before_dir, after_dir) -> list[dict]
```

**Member:** `change_impact`
**Registered in:** nothing. It is called directly.

The reason is not only technical. Look at what triggers each:

| | Trigger | Input | Question |
|---|---|---|---|
| Producers | User uploads a config | One config | *"Is this config bad?"* |
| Change impact | User proposes a change | Two configs | *"What does this change do?"* |

These are two different user journeys, and the client described them as two
different features — audit, versus *"block YouTube, and tell me what it breaks"*.
The dashboard has to build them as separate screens regardless.

**F-1 is unaffected.** Findings still carry `check="change_impact"` and `PC-` ids.
This changes the *input* contract only. The *output* contract — the document that
needs all four of us — does not move.

## What this settles about severity

`docs/finding-format.md:36` says severity is *"assigned by Samika's rules, not by
the AI"*. The code disagrees: `access_control` sets `violation_severity` per
statement, and `findings.py` hardcodes `low` for `none` and `high` for `error`.
Both cannot be true.

The post-processor shape resolves it cleanly:

- **Producers set severity as a default.** Every finding is valid the moment it is
  created, which matters because `error` findings can be produced before `risk`
  ever runs — including by the pipeline itself when Batfish is unreachable.
- **`risk` may re-rate.** That is exactly what a `findings → findings` stage is for.

The alternative — producers leave severity unset — breaks F-1, because `severity`
is required and a pipeline-level error finding would have none.

**One carve-out worth agreeing explicitly: `risk` must not downgrade
`status="error"` findings.** An unrunnable check is a blind spot regardless of
what the policy says about the device, and letting a scoring rule bury it
re-creates the F-4 failure by another route.

If we adopt this, `finding-format.md:36` needs rewording to something like:

> Set by the check as a default; risk prioritisation may re-rate it. Never set
> by the AI.

That is a contract edit and needs all four of us.

## What changes, per person

| Person | Impact |
|---|---|
| **Ankeet** | None. `routing` is a producer; write it exactly as documented. |
| **Shubham** | `policy_compliance` unchanged. `change_impact` becomes a separate entry point rather than a `CHECKS` entry — **do not register it**. |
| **Samika** | `risk` becomes a post-processor. It never edits `CHECKS`, which also removes the merge-conflict risk `CONTRIBUTING.md` warns about. |
| **Arsh** | Adds the post-processor stage and the `analyse_change` entry point. Shares `connect` / `load_snapshot` / `find_parse_problems` between both entry points so they cannot drift. |

## Recommendation

**Adopt all three shapes.** The cost is small and falls almost entirely on the
pipeline; the three producers are untouched.

Doing it now is much cheaper than later. One producer is merged, one is in
review, and neither of the two misfits is written yet — so this is a decision
about code that does not exist, which is the best kind.

## Open questions for the team

1. **Where does the "after" config come from** for change impact — the user
   uploads two folders, or the AI generates a change and we snapshot the result?
   That shapes `analyse_change`'s signature more than anything here, and it is
   US-13 territory.
2. **Should `analyse_change` also run the producers over the "after" config?**
   Arguably yes: the client asked the system to *push back* when a proposed change
   creates a flaw, and that means auditing the proposed state, not just diffing
   it. That is the difference between *"here is what changed"* and *"here is what
   changed, and it opens a hole"*.
3. **Can `risk` add findings, or only re-rate existing ones?** If it can add them,
   it needs its own `RK-` numbering that cannot collide with what it is
   annotating.
4. **Does the post-processor run when a producer errored?** Proposed: yes, but it
   must not downgrade `error` findings — see the carve-out above.

---

## 7. Sign-off

Added at Ankeet's suggestion on review of #20: `docs/policy-rules.md` records
agreement explicitly, and this proposal gates Samika's work, so "adopted"
should be a recorded fact rather than something inferred from the PR having
been merged quietly.

**Merging this PR means "this document is worth having in the repo". It does
NOT mean the proposal is adopted.** Adoption is the table below. Do not build
against these shapes until every row is ticked.

| Member | Stake in this decision | Agreed |
|---|---|---|
| **Arsh** | Author; owns `pipeline.py`, implements the post-processor stage and the `analyse_change` entry point | ✅ |
| **Ankeet** | `routing` stays a producer, unaffected — confirmed on review of #20 | ✅ |
| **Shubham** | `change_impact` becomes a separate entry point rather than a `CHECKS` entry | ⬜ |
| **Samika** | `risk` becomes a post-processor; unblocks her severity ruleset | ✅ |

Adopting this also implies one wording change to `docs/finding-format.md:36`
(severity set by the check as a default, re-ratable by risk, never by the AI).
That is an F-1 edit and needs all four members separately — ticking a row here
is not a substitute for it.
