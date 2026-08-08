# Sprint 3 — planning proposal

**Status:** PROPOSAL — not agreed. Nothing here is committed until the team says so.
**Proposed dates:** 6–12 August 2026 (following the seven-day cadence of Sprints 1 and 2 — confirm)
**Written:** 6 August 2026, the day after Sprint 2 closed

> This is deliberately a **proposal**, not a plan. Sprint scope is a team
> decision and a client conversation, not the SCRUM Master's to settle alone.
> It exists so the discussion starts from measured facts rather than from
> everyone recalling a different version of where we are.
>
> Replace this header with `**Status:** Agreed` once we have.

---

## Where Sprint 3 actually starts

Not from a clean slate. **Twelve pull requests are open, approved and unmerged**,
representing most of a sprint's work already done:

| PR | Owner | What it delivers |
|---|---|---|
| #48, #50 | Shubham | requirement rules proven to fail; policy scoping |
| #51 | Samika | auto-refresh after upload |
| #52, #53, #54, #56, #58 | Ankeet | explain() hardening; PF Sense injection + traversal + ambiguity; explanations on screen |
| #55, #57 | Arsh | routing scoping; §11 sync |
| #59, #60 | Samika | F-1 severity amendment; the risk post-processor |

Merged, that queue closes **#12, #29, #31, #47** and finishes **#17**.

**So the first job of Sprint 3 is not new work — it is landing what Sprint 2
finished.** Three things block it, and none are code:

1. Merges are blocked in Arsh's tooling; they need doing by hand.
2. #54 and #58 need rebasing onto #53 (all three touch the same test file).
3. #59 is an F-1 amendment and needs Ankeet's and Shubham's signatures.

That is a day's work at most, and until it is done the board shows an empty
"In progress" column with five items stuck in review.

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

**3. #11 is the cheapest remaining client-visible win.** `ai/explain.py` already
has a working, safety-netted model integration; the natural-language direction
reuses that machinery rather than starting fresh. Contrast #13/#14, which need
config *generation* — genuinely hard, and explicitly flagged in CLAUDE.md §4 as
possibly only partly achievable.

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

- The twelve-PR queue above.
- `CLAUDE.md` §7 states something now known to be false: *"Our fixture is
  written so both models agree."* It never did — the trailing catch-all deny
  overlapped every rule before it. #58 fixes the fixture; the §7 rewrite is a
  follow-up Arsh has taken, blocked until #58 lands.
- `#17`'s acceptance criteria predate the shapes decision and still say five
  checks register in `CHECKS`. Correction proposed in a comment on that issue,
  awaiting a second opinion.

## What we should decide in planning

1. Sprint dates — is 6–12 August right?
2. Who lands the queue, and when. It blocks everything.
3. Scope: which of the six stories, given four people and one week.
4. Whether #13 and #14 are taken together or not at all.
5. Whether anyone has asked Senaka about `quick` yet.
