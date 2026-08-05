# Sprint 2 — The core loop

**Status:** Complete
**Sprint dates:** 30 July – 5 August 2026
**Record written:** 5 August 2026, on the last day of the sprint

> Unlike `SPRINT1.md`, this record was written *inside* the sprint rather than
> reconstructed afterwards. Every figure in it was measured against the repo on
> the day, not recalled.

---

## Sprint goal

Build the backend pipeline: load a chosen config folder as a snapshot, run the
key analyses, and return the results as structured data rather than printed
tables, so a later component can feed them to the AI layer.

**Met, and exceeded.** The AI layer and the dashboard were not in this sprint's
scope and both exist. What did *not* happen is the integration — see
"Carried into Sprint 3".

## What was delivered

Eleven pull requests merged between 30 July and 5 August.

| Piece | Who | Evidence |
|---|---|---|
| **F-1, the finding contract** | all four | `docs/finding-format.md`, agreed 30 July |
| **F-3, the shared pipeline** | Arsh | connect, snapshot, parse check, dispatch, error isolation, duplicate-`id` guard |
| **`access_control` check** | Arsh | four analyses: `testFilters`, `searchFilters`, `filterLineReachability`, `undefinedReferences` (#19) |
| **`policy_compliance` check** | Shubham | five policy rules with reasoning, `docs/policy-rules.md` (#18) |
| **`routing` check** | Ankeet | `traceroute` reachability, two-router fixtures (#25) |
| **AI explanation layer** | Ankeet | `ai/explain.py` + `ai/Modelfile`, local Ollama (#26) |
| **Dashboard + secure upload** | Samika | two-pane UI, server-side validation (#21) |
| **Test suite** | Arsh | 47 tests, needing neither Batfish nor Ollama |
| **CI** | Arsh | `pytest` on 3.12 and 3.13, every PR (#32) |

**Stories delivered this sprint:** US-5, US-7, US-8, US-9.

**Also closed during the sprint, but Sprint 1 work:** US-2 and US-3 were
completed in Sprint 1 and left open; they were closed here as tidy-up. Counting
them as Sprint 2 output would overstate the sprint, so they are listed
separately.

## The three decisions that shaped the sprint

**F-1 and its `status` field.** Agreeing that `found` / `none` / `error` are
three distinct outcomes — and that "we checked and found nothing" must never
look like "we could not check" — is the decision everything else was built
around. It is why an unreachable Batfish produces findings rather than a stack
trace.

**Three shapes, not one contract.** Two features could not honour
`run(bf) -> list[dict]`: `change_impact` needs two snapshots, `risk` needs the
combined findings list. Rather than bolting an unused parameter onto every
check, the pipeline now recognises producers, a post-processor, and a separate
differential entry point (`docs/design/pipeline-feature-shapes.md`).

**`searchFilters` over `reachability`.** Shubham found that `reachability`
returns empty for a *routing* reason on our fixtures, which would have put a
green tick on the config that permits everything. `searchFilters` reasons about
the filter rather than the path and cannot be fooled that way.

## What review caught

Worth recording specifically, because "our process caught defects" is a
stronger claim with instances attached.

| Found by | Defect |
|---|---|
| Samika | Two findings could share an `id` (`PC-000`), silently dropping one — including, in the worst case, an `error` |
| Shubham | `reachability` gives a false all-clear; warned the one person about to hit the same trap |
| Ankeet | A `CLAUDE.md` update written as if two PRs had already merged — caught by checking the merge base |
| Ankeet | `README.md` contradicting itself three ways about the AI layer |
| Ankeet | An ACL-shadowing bug in his own AI layer, fixed by computing the logic in Python rather than trusting the model |
| CI | `pytest tests/` — the command our own docs told people to run — failed on a clean machine |

The last one is the clearest argument for CI: it caught not wrong code, but
code depending on something about our own machines nobody noticed we relied on.

## Carried into Sprint 3

Normal sprint carry-over, not failure. Recorded plainly so Sprint 3 planning
starts from fact.

**The integration gap is the important one.** Every piece works and is tested
individually, but nothing is joined: `web/main.py` still serves mock findings
with a single `TODO` where `analyse()` belongs. **No real config has produced a
finding that reached the screen.** That is US-10, and it is the single thing
between five working parts and a demonstrable product.

| Carried | Story | Note |
|---|---|---|
| Upload triggers analysis | #10 | the integration gap above |
| Risk prioritisation | #12 | shape agreed; ruleset not written |
| Change-impact analysis | #30 | shape agreed; not started |
| Explanations on screen | #31 | depends on #10 |
| Natural-language questions | #11 | the other half of Layer 2 |
| PF Sense conversion | #6 | in review (#34) |
| Device scoping | #29 | checks hardcode fixture device names |

**Open at sprint end:** three pull requests (#34, #35, #36) and one signature
on the shapes proposal.

## Known limitations, stated rather than discovered later

1. **Checks hardcode device names.** Every check names `rtr-us5`, `rtr-hq` or
   `rtr-branch`. A genuinely new device produces `status="error"` for every
   check — correct under F-4, but it means the first real config anyone uploads
   yields no analysis. #29.
2. **Parse strictness is absolute.** Any status other than `PASSED` stops the
   run. Safe for test configs; likely too strict for real ones. It is also
   currently the only thing catching a mis-converted PF Sense config.
3. **`explain()` raises rather than degrades** when Ollama is unreachable,
   unlike `analyse()`, which returns failures as findings.
4. **`change_impact` shares the `PC-` id prefix** with `policy_compliance`.
   Detected by the pipeline; only a distinct prefix makes it impossible.

## Numbers

```
11 pull requests merged        53 commits on main
47 tests, ~1.5s, no Batfish or Ollama needed
3 of 5 checks registered       CI green on 3.12 and 3.13
```
