# Sprint 3 — planning proposal

**Status:** Dates AGREED by all four. Scope still open.
**Sprint dates:** **6–12 August 2026** — agreed, not inferred.
**Written:** 6 August 2026, the day after Sprint 2 closed
**Updated:** 10 August 2026 (NZST), after the queue landed, Ankeet's review, and US-11's backend

> **⚠️ The dates are confirmed, so the clock is real: today is day 5 of 7.**
> Three days remain, counting today (10, 11, 12 August). Scope is still not
> agreed.
>
> Four of the seven days went on Sprint 2's carry-over — ten pull requests
> merged on 8 August, all of it real work, none of it work Sprint 3 chose.
> That is not recoverable and not worth relitigating; it is simply the budget
> we now have.
>
> **What this changes: the scope section below was written against a
> seven-day sprint and is no longer affordable as written.** See "What
> actually fits in three days" — the arithmetic, not the ambition, is what
> moved.
>
> Scope is still a team decision, not the SCRUM Master's to settle alone.
> Replace this line with `**Status:** Agreed` once scope is settled too.

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

1. **#59** — the F-1 severity amendment. **3 of 4 signed** (Arsh, Ankeet,
   Samika); **needs Shubham alone**. It is an F-1 edit, so it takes all four,
   it is the last outstanding piece of the shapes decision, and it is the only
   open item with no work attached to it at all.
2. **#51** — one commit from Samika moving `playwright` to
   `requirements-dev.txt`, then it merges.
3. **#63** — the merge rules, approved by Ankeet with one change requested and
   applied.

None of these is a day's work — between them they are a signature, a commit and
a confirmation. But that does not mean the sprint has room: four of its seven
days are already spent. See "What actually fits in three days".

## What is genuinely not built

Verified by looking, not by memory — no module, no entry point, no references
beyond design notes:

| Story | Owner | Note |
|---|---|---|
| #30 US-18 change-impact | Shubham | design agreed (`analyse_change(before, after)`), nothing written |
| #11 US-11 natural-language questions | Ankeet + Samika | **Backend landed 10 August** (#66). Shape chosen on #64 (A + C). The chat pane is Samika's half and is outstanding |
| #13 US-13 config change from plain English | Ankeet | the client's "input direction" |
| #14 US-14 safety pushback | Ankeet | inseparable from #13 — see below |
| #15 US-15 evaluation against known flaws | all | what the capstone is marked on |
| #16 US-16 deployment & docs | all | ditto |

**Six stories, four people, one week.** That does not fit, which is the whole
reason this document is a proposal rather than a plan.

## What actually fits in three days

Written 9 August and revised 10 August, once the dates were confirmed. Everything below this line in
"The shape I would argue for" was reasoned against seven days and still holds
as *ordering*; what follows is the same argument costed against the three days
we actually have (10, 11, 12 August).

**The arithmetic moved, not the ambition.**

| | Fits? | Why |
|---|---|---|
| **Close the six open PRs** | Yes — hours | #59 needs two signatures, #51 one commit, #63 one confirmation, #61 and #65 need reactions. Nothing here is work, it is unblocking |
| **#15 evaluation against known flaws** | Yes | The raw material exists — opposite-fixture pairs for every check, and a measured before/after for the PF Sense conversion. This is assembling evidence we already produced, not producing it |
| ~~**#64 — decide the query-grounding shape**~~ | **DECIDED** | Ankeet chose **A (constrained selection) + C (show the question back)** on #64, with reasoning, and has taken #11 |
| **#11 — the template surface** | **Yes** | Ankeet's first task: enumerate which of the five questions map cleanly to a natural-language pattern, which parameters validate against `snapshot.py`, and what "cannot map, refuse" looks like as a response. Analysis, not model integration |
| **#11 — model integration** | **No** | Deliberately after the surface is known and reviewed. Building the generation side before the thing it selects from is how the guard gets skipped |
| **Refining the risk ruleset** | **Yes** | Samika's, proposed on this PR and verified: R-2 flattens the list when one blanket permit causes everything. `rtr-us5-insecure` renders **5 high**, so ranking stops discriminating; `rtr-us5-messy` renders 1 high / 3 medium / 2 low and does. Already documented in `docs/severity-rules.md` §6, independent of anyone else's story, and it directly strengthens what #15 can demonstrate |
| **#13 / #14** | No | Config generation on top of the same unsolved problem |
| **#30 change-impact** | No | Design agreed, nothing written, and no one free |

**What I would put to the team, given three days:**

1. **Unblock everything** — the six open PRs. It costs a signature, a commit and
   a few reactions, and it clears the board.
2. **Refining the risk ruleset — Samika.** He raised on this PR that the plan
   named no Sprint 3 work for him once #11 became Ankeet's, which was a fair
   catch and a gap in my planning rather than in his workload. The weakness is
   already measured in `docs/severity-rules.md` §6 and I confirmed it against
   the fixtures before adding it here.
3. **#15**, as the sprint's other delivered story. It is the only story that turns
   "the checks work" into something a capstone panel can see, and it is the
   cheapest remaining item precisely because the evidence already exists.
4. ~~Decide #64.~~ **Done.** Ankeet chose A + C on #64 and took #11.
5. **#11 — the template surface only**, reported back for review before any
   model integration. That is Ankeet's own sequencing and it is the right one:
   the thing that selects queries cannot be built before the set it selects
   from is known.
6. **#11's model integration moves to Sprint 4** — not as a failure. We
   discovered mid-sprint that the story contained a design problem nobody had
   costed, chose a shape for it, and scoped the first honest piece of work. That
   is what a sprint is for.

The honest framing for the retro: Sprint 3 spent four of seven days finishing
Sprint 2 and discovered a hidden design problem in the story it planned to take.
Neither is a mistake. Both are worth recording, because the same thing will
happen again if we keep planning as though carry-over is free.

**Worth recording as the sprint's best moment:** the design problem was found in
*review*, by someone reading a planning document and disagreeing with an
estimate — not in production, and not after the code was written. Ankeet raised
it on #61, it became `docs/design/query-grounding-problem.md`, and he then chose
a shape and took the story. That is the review culture doing exactly what it is
for.

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

1. ~~Sprint dates.~~ **AGREED by all four: 6–12 August 2026.** Which makes
   today day 5 of 7, with three days left counting today — the constraint
   everything else is now costed against.
2. ~~Who lands the queue, and when.~~ **Done — ten PRs merged 8 August.**
3. Scope, and it is the only big one left: given three days, is the answer
   "unblock the six PRs, deliver #15, and take #11 as far as its template
   surface"? See "What actually fits in three days".
4. Whether #13 and #14 are taken together or not at all.
5. Whether anyone has asked Senaka about `quick` yet.
6. ~~Who takes the query-grounding problem.~~ **Ankeet, and he has chosen the
   shape: A (constrained selection) + C (show the question back).** Recorded on
   #64 with reasoning. What is left is not a decision but a review point: he
   reports the template surface back before building the generation side.
