# Scoping #221's second half — remediation beyond the three known shapes

**Status:** OPEN PROBLEM — no decision proposed here, deliberately. This
document exists to make the question decidable, not to decide it.
**Raised by:** Ankeet, having just shipped Phase A.
**Needed from:** whoever picks this up next — reading this is the first
task, not building.

---

## What Phase A actually built, and its real limit

`ai/explain.py`'s `remediate_with_source()` names a specific fix for three
evidence shapes, matched by tight regex against `evidence.detail` a check
already produced — never the model, never a guess. Measured against this
project's own fixtures:

```
rtr-us5-insecure: 4/5 found-status findings match a known shape
rtr-us5-messy:    5/6 found-status findings match a known shape
```

That is strong coverage on synthetic fixtures built to exercise exactly
these check paths. It is not a promise about a stranger's config: any
evidence shape this project has not yet seen — a check we add later, an
unusual Batfish output string, a client policy asserting something none of
our fixtures do — gets `None`, silently, and the dashboard says so in words
("no mechanical remediation available") rather than inventing a fix. That is
correct behaviour, not a bug, but it means Phase A's real-world coverage is
unmeasured outside this project's own two fixtures.

## The question Phase B has to answer

For a finding whose evidence does not match one of the three known shapes,
should Netwise attempt to generate a fix at all — and if so, how?

Two candidate shapes, not a recommendation between them:

**B1 — Loosen `ai/Modelfile` rule 6.** It currently forbids the model from
recommending a fix "unless the evidence itself states what would resolve
it." Widening that means: a new worked example in the Modelfile, and new
`_is_unacceptable()`-style post-generation validation specific to fix
prose — the existing checks (`_looks_like_a_result_claim()`,
`_looks_like_speculation()`) were built for explanation text, and a
recommended fix is a different kind of claim with its own failure modes
(e.g. syntactically plausible but wrong config, or a fix that addresses the
symptom Batfish reported rather than the actual misconfiguration). Cheaper
to build; the trust surface is a 3B model inventing configuration text,
which is a materially bigger claim than paraphrasing a finding.

**B2 — Reuse `ai/propose.py`'s generate-simulate-verify pipeline.**
`ai/propose.py` + `analysis/change_impact.py` already generate a candidate
config line, apply it to a scratch snapshot, re-run `analyse()`, and diff
the result — verified rather than merely plausible-sounding, the same
"refuse rather than guess" discipline used everywhere else in this project.
Originating from a finding instead of a free-text user request needs the
generation step re-pointed at `evidence.detail`/`evidence.source` instead of
parsed English, but the verification half is already built. Likely the
safer shape, since every candidate fix would be simulated before being
shown — but it also means every remediation suggestion pays the cost
`ai/propose.py` already pays (connect to Batfish, load a snapshot, run
`change_impact` twice), which is not free on every `/api/findings` load the
way Phase A's regex matching is.

Not scoped here: whether B1 and B2 are mutually exclusive, or whether B1
could be a stated fallback when B2's verification fails to find a candidate
worth simulating.

## What this is not

Not a decision. Not started. Filed so the choice is visible rather than
re-derived from scratch by whoever picks it up, the same reason
`config-change-and-pushback.md` and `query-grounding-problem.md` exist as
separate documents from the features they scoped.
