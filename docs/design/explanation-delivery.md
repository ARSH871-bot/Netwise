# Proposal: how the AI explanation reaches the dashboard

**Status:** PROPOSAL — for team decision. Nothing is built against this yet.
**Raised by:** Samika (dashboard) — affects Ankeet (AI layer) directly
**Needs:** Samika and Ankeet at minimum. Option A additionally needs all four,
because it amends F-1.
**Blocking:** #31. The explanation slot has been on screen since #40 with a
placeholder in it; `ai/explain.py` has been on `main` since #26. Neither can
meet the other until this is decided.

---

## 1. The question

`explain(finding) -> str` exists and works. The slot to display it exists. What
does not exist is the route between them, and it is not obvious, because the
straightforward answer breaks the one contract we agreed not to break.

This was raised once before, as open question 2 in
[`output-schema-proposal.md`](output-schema-proposal.md), and never settled.
That document is superseded; the question outlived it.

## 2. Three constraints that decide it

**F-1 fields are closed.** `docs/finding-format.md` lists seven fields, "all
required", and `findings.make_finding()` emits exactly those seven and nothing
else. Adding an eighth is an F-1 amendment needing all four members.

**Explanations are slow and they fail.** `explain()` calls a local 3B model,
once per finding, with a retry. On a seven-finding run that is a long wait added
to a `/api/findings` call that already takes ~10 seconds for Batfish. And
`_generate()` deliberately has no `try/except` — if Ollama is not running,
`explain()` raises rather than inventing a sentence. That is the right choice
for the AI layer and it makes the caller's error handling mandatory.

**Finding ids are not unique.** `policy_compliance` and `change_impact` share
the `PC` prefix, which is why the dashboard never keys by `id` and why
`pipeline.duplicate_id_findings()` exists. Any design that maps explanations to
findings *by id* is unsound today.

## 3. Options

### Option A — the pipeline adds an `explanation` field

`analyse()` calls `explain()` per finding and returns eight-field findings.

**For:** one request, one shape, nothing for the frontend to coordinate.

**Against:** amends F-1, so it needs all four members. It also couples analysis
to Ollama — a config analysis would then fail, or hang, because a *language
model* is down, which inverts the dependency: the findings are the product, the
prose is the garnish. And it makes every consumer pay for explanations,
including `python -m analysis.pipeline`, which has no use for them.

### Option B — a separate endpoint, one finding at a time *(recommended)*

Findings render immediately from `/api/findings` as they do now. The dashboard
then requests an explanation per displayed finding from a new endpoint, POSTing
the finding itself.

**For:** F-1 is untouched, so this needs two of us rather than four. Findings
appear at Batfish speed and explanations fill in behind them, which is also
better on screen than one long blank wait. A model that is down degrades one
part of one card instead of the whole analysis. POSTing the finding sidesteps
the id-uniqueness problem entirely — nothing is looked up.

**Against:** N requests instead of one, and per-card state for the frontend to
manage. POSTing a finding back to the server is slightly odd, though it matches
how `explain()` already works: it is grounded strictly in the single finding it
is handed, and never sees anything else.

### Option C — a parallel `{id: explanation}` map alongside findings

**Against:** unsound today. Ids are not unique, so the map silently loses one of
any colliding pair — and that pair is most often a `status="error"`, which is
the F-4 failure we have now hit twice through the `id` field. Not viable unless
`change_impact` gets its own prefix first.

## 4. Recommendation

**Option B.** It is the only one that does not either amend F-1 or depend on an
id-uniqueness property we do not have. It is also the only one where "Ollama is
not running" degrades gracefully instead of taking the analysis with it.

If the team prefers A on simplicity grounds, that is defensible — but it is an
F-1 amendment and should be voted as one, not arrived at by implementation.

## 5. The part that is not about plumbing

Whichever option wins, the dashboard needs **three visually distinct states**,
for the same reason `none` and `error` are distinct:

| State | Means | Must not look like |
|---|---|---|
| not requested yet | the model has not been asked | a real explanation |
| unavailable | asked, and Ollama did not answer | a real explanation, or a finding-level error |
| explained | the model answered and passed validation | either of the above |

The dashed `.ai-explanation.placeholder` style from #40 already covers the
first. The second needs its own treatment and does not have one.

This matters more than it sounds. An "explanation unavailable" box that looks
like an explanation is a security tool implying it explained something it did
not, and an unavailable *explanation* must not be mistaken for a failed
*check* — the finding is still perfectly valid, only the prose is missing.

## 6. Sign-off

Merging this PR means "this document is worth having in the repo". It does NOT
mean the option is adopted. Adoption is the table below.

| Member | Stake | Agreed |
|---|---|---|
| **Samika** | Builds the dashboard side and the three states | ⬜ |
| **Ankeet** | Owns `explain()`; Option A would change when and how often it is called | ⬜ |
| **Arsh** | Owns `pipeline.py`; only affected if Option A wins | ⬜ |
| **Shubham** | Only affected if Option A wins, as an F-1 amendment | ⬜ |
