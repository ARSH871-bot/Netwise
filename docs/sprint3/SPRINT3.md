# Sprint 3 — planning proposal

**Status:** PROPOSAL — still not agreed.
**Proposed dates:** 6–12 August 2026 (following the seven-day cadence of Sprints 1 and 2 — confirm)
**Written:** 6 August 2026, the day after Sprint 2 closed
**Updated:** 9 August 2026, after the queue landed and Ankeet's review

> **⚠️ If the proposed dates are right, this sprint is on day 4 of 7 and its
> scope is still not agreed.** That is the most important fact in this
> document and it belongs at the top rather than implied by the dates.
>
> Half of a seven-day sprint has been spent, productively — ten pull requests
> merged on 8 August — but on Sprint 2's carry-over rather than on anything
> Sprint 3 chose. Either we agree scope now and accept a three-day sprint, or
> we say plainly that Sprint 3 started on 8 August and runs to 14 August. Both
> are defensible; drifting without deciding is not.
>
> This is deliberately a **proposal**, not a plan. Sprint scope is a team
> decision and a client conversation, not the SCRUM Master's to settle alone.
> It exists so the discussion starts from measured facts rather than from
> everyone recalling a different version of where we are.
>
> Replace this header with `**Status:** Agreed` once we have.

---

## Where Sprint 3 actually starts

Not from a clean slate — but no longer from a stalled queue either. **This
section originally said the first job of Sprint 3 was landing what Sprint 2
finished. That has now happened**, and the update is recorded rather than
silently overwritten, because the difference matters to how much room the sprint
has.

**Ten pull requests merged on 8 August**, closing **#12, #29, #31 and #47**:

| PR | Owner | What it delivered |
|---|---|---|
| #48, #50 | Shubham | requirement rules proven to fail; policy scoping |
| #52, #53, #54, #56, #58 | Ankeet | `explain()` hardening; PF Sense injection, traversal and rule-order ambiguity; explanations on screen |
| #55, #57, #62 | Arsh | routing scoping; §11 sync; §7 rewrite |
| #60 | Samika | the risk post-processor |

`main` is at `488f3d8` with **167 tests**, and all five features are on it
together for the first time. Verified end to end after the merge, not just by
test count: every fixture through the pipeline, all ten PF Sense protections
re-checked, the AI layer degrading correctly with Ollama down, and zero
`RK-8xx` post-processor violations on any snapshot.

**Still open, and each waiting on one person:**

1. **#59** — the F-1 severity amendment. Signed by Arsh and Ankeet; **needs
   Shubham**. It is an F-1 edit, so it takes all four, and it is the last
   outstanding piece of the shapes decision.
2. **#51** — one commit from Samika moving `playwright` to
   `requirements-dev.txt`, then it merges.
3. **#63** — the merge rules, approved by Ankeet with one change requested and
   applied.

None of these are a day's work, so the sprint has more room than this document
originally assumed.

## What is genuinely not built

Verified by looking, not by memory — no module, no entry point, no references
beyond design notes:

| Story | Owner | Note |
|---|---|---|
| #30 US-18 change-impact | Shubham | design agreed (`analyse_change(before, after)`), nothing written |
| #11 US-11 natural-language questions | Ankeet | the other half of Layer 2 |
| #13 US-13 config change from plain English | Ankeet | the client's "input direction" |
| #14 US-14 safety pushback | Ankeet | inseparable from #13 — see below |
| #15 US-15 evaluation against known flaws | all | what the capstone is marked on |
| #16 US-16 deployment & docs | all | ditto |

**Six stories, four people, one week.** That does not fit, which is the whole
reason this document is a proposal rather than a plan.

## The shape I would argue for

Three claims, offered as arguments rather than decisions:

**1. #13 and #14 are one story, not two.** The client asked for "block YouTube"
to produce a proposed config change *and* for the system to push back when a
change would create a security flaw. Building the first without the second
produces exactly the tool CLAUDE.md §4 says we must not build. If we take #13,
we take #14 with it or we take neither.

**2. #15 is worth more than it looks.** "Evaluation against known flaws" is the
only story that produces evidence the tool *works* rather than evidence it
*runs*. We have opposite-fixture pairs for every check already, so much of the
raw material exists. For a capstone review this is the difference between
demonstrating features and demonstrating results.

**3. #11 is the cheapest remaining client-visible win — but "cheapest"
undersells one genuinely new problem inside it.** `ai/explain.py` already has a
working, safety-netted model integration, and the natural-language direction
reuses that machinery rather than starting fresh. Contrast #13/#14, which need
config *generation* — genuinely hard, and flagged in CLAUDE.md §4 as possibly
only partly achievable.

**The caution, raised by Ankeet on this PR and correct:** the reuse is true of
the *plumbing*, not of the hard part. `explain()` rephrases a finding that
already exists, grounded in evidence a check already produced. #11 has to go the
other direction first — take free text and decide **which Batfish question to
run, with which parameters** — before there is anything to explain.

That translation step is new and unproven, and it is where a wrong answer is
worst. A confidently wrong *finding* is bad. A confidently wrong *query* is
worse: the explanation afterwards is faithfully grounded in the wrong question
and still reads as authoritative. Every safety net we have sits downstream of
the query being the right one.

That does not change the ordering — #11 still goes ahead of #13/#14, which need
config generation on top of the same problem — but it should change the estimate
and it is where the design effort belongs.

That suggests: **land the queue, then #11, then #15**, with #13/#14 as the
stretch and #30 and #16 deferred. But see the open question below, because one
external fact could reorder all of it.

## The open question that outranks the rest

**Does Senaka's real PF Sense export mark its rules `quick`?**

One `grep quick config.xml` on his file answers it, and the answer changes the
sprint:

- **If yes** — the converter's assumption holds for his network, #58 makes it
  safe, and we can show him his own config. Plan as above.
- **If no** — every overlapping non-`quick` rule pair now correctly *refuses to
  convert* (#58), which means we cannot analyse his firewall at all until the
  converter handles last-match-wins properly. That is a substantial piece of
  work nobody has scoped, and it would become the sprint.

This is not a hypothetical risk. It was measured: a two-rule export without
`quick` converts into an ACL that denies traffic the real firewall permits, and
Netwise then reports the deciding rule as one that never takes effect. See
issue #47.

**Ask Senaka before planning is finalised.**

## Carried into Sprint 3 from Sprint 2

Recorded plainly, not as failure — this is ordinary carry-over.

- ~~The twelve-PR queue above.~~ **Landed 8 August.**
- ~~`CLAUDE.md` §7 states something now known to be false.~~ **Fixed by #62.**
  It said *"Our fixture is written so both models agree"*, which it never did —
  the trailing catch-all deny overlapped every rule before it. #58 fixed the
  fixture, #62 rewrote §7, and #47 moved to Settled.
- **`#17`'s acceptance criteria predate the shapes decision** and still say five
  checks register in `CHECKS`. There are three, and `risk` is a post-processor.
  Correction proposed in a comment on that issue, still awaiting a second
  opinion — this is the one genuine carry-over left, and it is why #17 sits in
  **In review** rather than Done.

## What we should decide in planning

1. **Sprint dates, and this one is now urgent.** If 6–12 August stands, we are
   on day 4 of 7 with no agreed scope. Either accept a three-day sprint, or
   restate Sprint 3 as 8–14 August starting from when the queue landed.
2. ~~Who lands the queue, and when.~~ **Done — ten PRs merged 8 August.**
3. Scope: which of the six stories, given four people and whatever is left of
   the week after (1) is answered.
4. Whether #13 and #14 are taken together or not at all.
5. Whether anyone has asked Senaka about `quick` yet.
6. **Who takes the query-grounding problem** (`docs/design/query-grounding-problem.md`)
   if #11 is in scope. It is the one genuinely new design problem in the
   sprint, and it needs deciding before code, not during review.
