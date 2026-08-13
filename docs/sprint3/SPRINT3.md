# Sprint 3 — the plan, and how it changed

**Status:** **COMPLETE.** Scope was agreed by all four (the sign-off note
below); the sprint ran 6-12 August and closed with its milestone at 8 of 8.
Tagged `v0.3.0` at `9988cff`. The closing record is at the bottom of this
document - everything above it is the plan as it stood *during* the sprint and
is deliberately left as it was written.
**Sprint dates:** **6–12 August 2026** — agreed, not inferred.
**Written:** 6 August 2026, the day after Sprint 2 closed
**Updated:** 10 August 2026 (NZST), after the queue landed, Ankeet's review, and US-11's backend

> **Day 5 of 7 when this line was written**, on 10 August. Left in place
> rather than deleted: this document was written inside the sprint, and the
> point of that is visible in the tense.
>
> **How this was agreed, recorded rather than asserted.** Every teammate
> engaged with a specific argument and each one changed the document:
>
> - **Ankeet** — #11 is not "cheap"; the translation step is the hard part and
>   a confidently wrong *query* beats a confidently wrong finding. Became #64,
>   which he then took and built.
> - **Samika** — the plan named no Sprint 3 work for him once #11 became
>   Ankeet's. Proposed refining the risk ruleset, with the weakness already
>   measured in `docs/severity-rules.md` §6.
> - **Shubham** — #13/#14 is *neither*, not "together"; the empty-answer
>   pattern has now bitten us three times; #30's stated primitive does not
>   work. Approved.
>
> Nobody objected to the scope. "Agreed" here means three people argued it and
> were answered, not that three people said nothing.
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
> Scope was a team decision, not the SCRUM Master's to settle alone, and it
> was settled that way.

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

1. ~~#59 — the F-1 severity amendment.~~ **RATIFIED by all four and merged**
   (10 August). Severity is set by the check as a default, `risk` may re-rate,
   the AI never sets it. The last outstanding piece of the shapes decision is
   now closed.
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

## Why #13/#14 is *neither*, not "together"

Raised by Shubham reviewing this document, and it is a sharper argument than
the one it replaces.

"Together or neither" is true but leaves a door open: if the days look like
they fit, someone takes them together. The stronger reason to say **neither**
is that #13/#14 stack **config generation on top of the translation layer that
is itself new and unproven**.

The failure mode is not a bad suggestion. It is the tool proposing a
configuration change based on a question it misunderstood — two unproven
layers composed, where the outer one produces something a person might apply
to a firewall.

Recorded explicitly so it is not reopened on day 6 when #11 looks close.

## The empty-answer pattern — name it before building on it

Also Shubham's, and it is the most useful thing anyone has generalised on this
project. The same fault has now appeared three times:

| Where | Question asked | An empty answer was read as |
|---|---|---|
| `policy_compliance` | `reachability` | "policy holds" — actually no route |
| `change_impact` (#30) | `differentialReachability` | "nothing changed" — actually no route |
| Query layer (#11) | whichever question is selected | "no problem found" — actually the wrong question |

**An empty result that means "we asked something which could not have answered"
gets read as good news.** That is F-4's lesson — `none` is not `error` —
appearing one level up, in the *question* rather than the *status*.

The concrete consequence for #11's template surface: **a template should carry
what its empty answer is entitled to mean**, so "no results" can never render
as "you are fine" for a question that could not have produced results either
way. Cheaper to build in now than to retrofit.

## #30 is deferred, and there is a trap in how its primitive is called

> **RETRACTED, 12 August.** This section originally said
> `differentialReachability` "reports zero difference between a config that
> denies everything and one that permits everything", and that `compareFilters`
> was the working primitive. **That is wrong.** @shubhamkataria2005 withdrew the
> measurement himself, and it was reproduced independently before being
> corrected here. The original claim is described rather than silently deleted,
> because a sprint record that edits out a retracted claim is worth less than
> one that shows the claim being retracted.

Both primitives work. The real finding is narrower, and is a trap rather than a
failure - measured on a purpose-built `deny ip any any` to `permit ip any any`
pair, and reproduced twice:

```
startLocation="rtr-us5"                              rows=0
startLocation="rtr-us5[GigabitEthernet0/0]"          rows=0   <- the trap
startLocation="@enter(rtr-us5[GigabitEthernet0/0])"  rows=1
(no pathConstraints)                                 rows=1
```

The middle line is the dangerous one. It **looks like the careful thing to
write** - it names the exact device and the exact interface the inbound ACL is
bound to - and returns zero difference for a change that opens the network
completely.

The original error was constraining `startLocation` to a place an inbound ACL is
never traversed. The empty result was correct for the question asked; the
question was wrong. **`analyse_change()` must use `@enter(...)` or no path
constraints at all**, and #30 should carry a test for it, because an empty
result there would read as "your change is safe".

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
4. ~~Whether #13 and #14 are taken together or not at all.~~ **Answered:
   neither, this sprint.** Shubham argued it harder than the original framing
   and he is right — see "Why #13/#14 is *neither*" below. "Together or
   neither" invites taking them together if the days look like they fit;
   saying **neither**, explicitly, stops it being reopened on day 6.
5. Whether anyone has asked Senaka about `quick` yet.
6. ~~Who takes the query-grounding problem.~~ **Ankeet, and he has chosen the
   shape: A (constrained selection) + C (show the question back).** Recorded on
   #64 with reasoning. What is left is not a decision but a review point: he
   reports the template surface back before building the generation side.

---

# Closing record — written 13 August, the day after the sprint ended

Everything above this line is the plan as it stood *during* Sprint 3 and is
left exactly as written, including the parts that turned out wrong. This
section is the outcome.

**Sprint 3 ran 6–12 August 2026. Milestone closed at 8 of 8. Tagged `v0.3.0`
at `9988cff`.**

## Numbers, measured rather than recalled

Every figure below comes from the repository, over the sprint window in NZT
(`--since="2026-08-06T00:00:00+12:00" --until="2026-08-13T00:00:00+12:00"`).

| | |
|---|---|
| Pull requests merged | **39** |
| Commits on `main` | **113** |
| Python files | 18 → **31** |
| Test files | **11** |
| Milestone issues closed | **8 of 8** |

## What was delivered

**All five analysis features joined end to end, which first became true on
8 August.** Uploading a config and clicking **Scan Now** produces real findings
on screen, explained in plain English and sorted worst-first.

- **Risk prioritisation** (#60) landed as a post-processor, with the two limits
  — never downgrade a `status="error"` finding, never drop one — *enforced* in
  `run_post_processors()` rather than documented.
- **The AI explanation reached the screen** (#56, closing #31). Only
  `status="found"` findings are ever explained, so a card that could not be
  checked can never acquire prose reading as though it had been.
- **The natural-language query backend** (#66) shipped with `/api/ask`, built
  to refuse: a closed intent set, no model in either direction, every parameter
  resolved against the real snapshot, and the translated question always shown
  back.
- **Upload and analysis were separated** (#82). A staged file is no longer
  confused with a checked one, and stale findings are cleared on upload rather
  than left under a success message describing a different network.
- **The PF Sense converter met its first real client export** and refused it
  cleanly rather than mistranslating it.

## What review caught, and it is the sprint's most important output

Three of the significant defects found this sprint were in the SCRUM master's
work, found by teammates who re-ran claims instead of reading them:

| Found by | What |
|---|---|
| Ankeet | an estimate true of the plumbing and false about the hard part |
| Ankeet | a document demonstrating the error it warned against |
| Ankeet | a tool whose guarantee was verified only against known-good input |
| Samika | a fix that was half a fix |
| Shubham | a latent pipeline bug, found while verifying before signing A-1 |

And the worst was nobody else's: **two guard tests asserted nothing for days**,
truncated during a conflict resolution, on branches that had been asked not to
be rebased without asking. `pytest` cannot fail a test that does nothing, so
nothing detected it.

## The pattern this sprint named

**A weaker claim standing in for a stronger one.** It appeared often enough to
stop being a coincidence: a fixture preserved instead of a behaviour tested, a
lint gate clean against an unstated ruff version, an empty Batfish result read
as good news, a docstring asserting coverage that did not exist.

The response that worked was not more review. It was **re-running the claim** —
which is how every instance above was found, including by the person who made
it.

## Honest limitations at close

- **The policy is ours, not the user's** (#87). Rename a device in a fixture and
  detection drops from 6 findings to 3, because everything except dead rules and
  undefined references is checked against assertions hardcoded to our own
  configs. This is the largest gap in the product and it had no issue until
  after the sprint closed.
- **No real configuration has been analysed by the pipeline.** The client's
  export has been examined structurally only, and the converter refuses it.
- **The explanation layer is unevaluated.** Whether the plain-English text is
  *good* is untested — the one thing a client actually reads.

## Carried into Sprint 4

- #78 — the client's export, **timeboxed to item 1** with an explicit stop
- #30 — change-impact, with the `startLocation` trap recorded above
- #95 / A-2 — raised day 1 rather than when the code needs an ID
- #16 — deployment and docs, split
- #87 — the open question against all of the above
