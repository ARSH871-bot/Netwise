# Sprint 4 — the plan, and how it changed

**Status:** **AGREED**, and running. Approved by all three teammates on #86
(@patelankeet2, @shubhamkataria2005, @SamikaPerera). Milestone **Sprint 4**
created, due 19 August.
**Dates:** 13–19 August 2026 (the seven-day cadence of Sprints 1–3)
**Written:** 12 August 2026, on Sprint 3's closing day
**Status updated:** 13 August, day 1, once scope was settled and work had begun

> Same shape as `docs/sprint3/SPRINT3.md`: a proposal the team changes, not a
> plan handed down. It was changed — see "Three corrections from review" below,
> all @shubhamkataria2005's, one of which reversed the author's own
> recommendation.

## Day 1, recorded as it happened

The scope below is **not** the version first proposed. @shubhamkataria2005
argued #78 should be timeboxed to item 1 with an explicit stop rather than
committed whole, and the author agreed with him over his own table. That is
what was assigned.

Already delivered on day 1:

| | |
|---|---|
| **A-2 ratified and merged** (#102) | @shubhamkataria2005 raised it on day 1 as asked, rather than when the code needed an ID. `change_impact` now owns `CH-`. |
| **#78 items 1 AND 2 merged** (#104) | @patelankeet2. Multi-interface rule sets, and last-match-wins **modelled** rather than refused. Two of four client blockers gone. |

**The timebox went past its stop, and that was right.** Item 2 turned out to be
a reversal plus a guard rather than the sprint it might have been — knowable
only from inside item 1. The timebox forced a re-decision with better
information, which is what it is for, and that is worth carrying as precedent
rather than leaving as a quiet overrun.

Milestone at the time of writing: **3 closed, 10 open.**

---

## Sprint 3 closed clean

`main` at `9988cff`, **215 tests**, Sprint 3 milestone **8 of 8 closed**.

Delivered: US-11 end to end, US-15's evaluation, US-12 risk scoring (and #83
fixed its flattening in the same sprint), US-17 with corrected acceptance, F-1
amendment A-1 ratified by all four, Scan Now, and `tools/pfsense_shape.py`.

**Carried in, and it is small:** #84 and #76, both mine, both awaiting a
re-review after teammate corrections. Neither is new work.

---

## This sprint's shape is not open — the client's file decided it

Sprint 3's plan argued about which feature to build next. Sprint 4 does not get
that luxury. Senaka's export (#78) established, measured with
`tools/pfsense_shape.py`:

```
filter rules      7
marked quick      0      -> last-match-wins applies to his whole rule set
interfaces        3      -> rules span 4 interface values; we support 1
elements      1,998      -> against our fixture's 54
sections                 -> nat, openvpn, ipsec, aliases, dhcpd, shaper
```

**We cannot analyse the client's firewall today.** Everything else in the
backlog is secondary to that, because a network-analysis tool that cannot read
its only real network is not finished, however green the suite is.

### What it needs, in dependency order

1. ~~**Multi-interface rule sets**~~ — **DONE, #104.** Several ACLs, each bound
   to its own interface, rather than one `acl_in`.
2. ~~**Real PF Sense evaluation order**~~ — **DONE, #104.** With zero `quick`
   rules the converter reverses the list, which is provably the same decision
   as last-match-wins for every flow. Verified against Batfish. Mixed lists
   still refuse.

   *Items 1 and 2 were written as pending and delivered on day 1. Left in
   place, struck through, because the dependency ordering below them is what
   this list was for and deleting them would hide that two of the four are
   gone.*
3. **A decision on NAT** — two of his rules carry `associated-rule-id` and are
   meaningless without it. NAT is out of scope today; that may have to change,
   or we say plainly which rules we cannot interpret.
4. **Rules omitting `<type>` / `<protocol>`** — #80, and **blocked on Senaka**,
   not on us. Four of his seven rules omit `<protocol>`, which our converter
   silently widens to `ip`. Do not fix before he answers; guessing there is the
   exact failure the issue is about.

**Honest estimate: this is a sprint, and plausibly two.** #78 is sized XL on the
board for that reason, and an XL that is really two sprints should be split once
item 1 is understood.

---

## What I would put to the team

| Who | Proposed | Why |
|---|---|---|
| **Ankeet** | #78 items 1 and 2 — multi-interface, then evaluation order | It is his converter, and #53/#54/#58 are all his. Item 1 blocks item 2 |
| **Shubham** | #30 change-impact, with **`compareFilters` *and* `differentialReachability`** | Design agreed, nothing written. Both primitives work; the caveat he measured is the location specifier, not the primitive |
| **Samika** | #16 deployment & docs, the user-facing half | It is what the capstone is marked on and nobody has started it; he owns everything a user touches |
| **Arsh** | Land the carry-over, then #16's engineering half | Two of my PRs are the queue; clearing them is worth more than starting anything |

**Not this sprint: #13 and #14.** Shubham's argument from Sprint 3 stands and
has not weakened — they stack config *generation* on top of a translation layer
that is still new. Two unproven layers, where the output is something a person
might apply to a firewall. Recorded as **neither**, explicitly, so it is not
reopened on day 5.

---

## Three corrections from review, all Shubham's, all before merge

**1. His row credited him with a finding he had withdrawn.** The table said he
had "already measured that the story's stated primitive does not work". He
retracted that on #30 the same day: `differentialReachability` works, and his
empty result came from constraining `startLocation` to a place an inbound ACL is
never traversed. His measurement was correct for the question he asked; the
question was wrong.

```
startLocation="rtr-us5"                             rows=0
startLocation="rtr-us5[GigabitEthernet0/0]"         rows=0   <- right interface, still blind
startLocation="@enter(rtr-us5[GigabitEthernet0/0])" rows=1
(no pathConstraints)                                rows=1
```

The real caveat to carry into the sprint is **the location specifier, not the
primitive** — and it is worth carrying, because it is a trap that returns an
empty answer rather than an error. Row corrected. This matters more than a
wording fix: a sprint record is what the evaluation report is built from, and
this one credited a teammate with a retracted claim.

**2. A constraint from the original brief was deleted, not overridden — and it
was about exactly this sprint.** `CLAUDE.md` §7 as first written (`88dbdfb`):

> The client's real firewall is **PF Sense** ... This is a known hard problem —
> **timebox it** and fall back to supported-vendor sample configs if it stalls.

Verified in the history:

```
88dbdfb   "timebox it"  present
b2456fd   "Document the PF Sense converter, and surface its rule-order caveat"  -> 0 occurrences
main      0 occurrences
```

**The constraint was not re-decided. It was overwritten while writing
documentation about the thing it constrained**, in a docs PR of mine. So
proposing a sprint (plausibly two) on #78 is not merely a scope trade — it is
the outcome the brief specifically told us to guard against, and the guard was
removed incidentally rather than deliberately.

That does not settle it, and Shubham says so himself: circumstances changed. We
have the real file now, and *"if it stalls"* reads differently when the
converter **refuses cleanly** rather than flails. But **the team must re-take
that decision explicitly**, knowing it was once made the other way, and it
belongs in this record as a decision with reasons — the same standard we hold
for F-1 and the shapes proposal. It must not be inherited from a document that
quietly stopped saying it.

**3. #30 is blocked on an F-1 amendment nobody has scheduled.** `change_impact`
shares the `PC-` prefix with `policy_compliance`. Giving it its own prefix is an
F-1 edit, and **A-1 took from 6 to 12 August to collect four signatures.** If
#30 is Sprint 4 work, that amendment must be raised on **day 1**, or Shubham is
either blocked mid-sprint or shipping into a collision the pipeline will
correctly flag. He has offered to draft it, since it is his check that collides.

**Added to the decisions list: who raises A-2, and when.** Tracked as #95.

---

## The thing I would most like argued with

**Is #16 (deployment & docs) actually more valuable than #78?**

My table says do both. A case exists for the opposite: the capstone is marked on
what we can *show*, `#78` may consume the whole sprint and end with the client's
file still unreadable, and "we can analyse your firewall" is a worse demo than
"here is a working tool and an honest account of what it refuses."

I do not think that is right — the converter refusing his file is a *finding*,
not a gap, and it is more interesting than a deployment script. But it is the
strongest argument against my own proposal and someone should make it properly.

**Shubham has now made it properly, and it is firmer than I framed it** — see
correction 2 above. It is not a judgement call about demo value; the brief
already made this call once. His own position:

> **#16 in, #78 timeboxed to item 1 (multi-interface) with an explicit stop.**
> Item 1 is the blocker, it is bounded, and finishing it tells us whether items
> 2–4 are a sprint or a term. Committing to all four before item 1 lands is
> estimating work we have not scoped.

That last clause names the failure mode directly, and it is the same one that
produced a fourteen-PR queue merged in one sitting. **I now think he is right
and my table is wrong.** Recording that here rather than silently editing the
table, so the disagreement and its resolution are both visible.

**One further argument nobody has made yet, and it may outrank both:** #87 —
there is no way for a user to state their own policy. Even a finished converter
leaves the client's config producing only dead rules and undefined references,
because a converted config is by definition a stranger's device name. #78 buys
the ability to *read* his firewall; #87 is what makes reading it worth
anything. Shubham reached the same conclusion independently on #88.

---

## Carried over from Sprint 3's retro

**The review culture is the project's strongest asset, and it should be said
in the report rather than only felt.** Three of the four significant defects
found in Sprint 3 were in the SCRUM master's work, found by teammates:

- an estimate true of the plumbing and false about the hard part (Ankeet)
- a document demonstrating the error it warned against (Ankeet)
- a tool whose guarantee was verified only against known-good input (Ankeet)
- a fix that was half a fix (Samika)
- a latent pipeline bug, found while verifying before signing an amendment
  (Shubham)

And the worst was mine alone: **two guard tests asserted nothing for days**,
truncated by my own conflict resolution, on branches I had been asked not to
rebase without asking. Nothing could detect it, because `pytest` cannot fail a
test that does nothing.

**The lesson for Sprint 4 is not "review harder".** It is that the one defect
nobody caught got through because work outran review — a fourteen-PR queue
merged in one sitting. Merge small, and land things as they go green.

---

## What we should decide

1. Sprint dates — is 13–19 August right?
2. Does #78 take one sprint or two, and do we split it after item 1?
3. Is #16 in, and if so does it beat #78 for anyone's time?
4. Who chases Senaka for the `<protocol>` answer that unblocks #80?
5. Do we tag `v0.4.0` at this sprint's close, per `CONTRIBUTING.md` §5b?


---

## Days 2–6, recorded on day 6

Written on **18 August**, the day before close, rather than reconstructed
afterwards — the same convention Sprint 3's record used. The closing verdict is
deliberately **not** written yet; the sprint has a day left and writing its
ending early is how a record becomes a story.

### Measured, not recalled

```
main                eac2a81      384 tests, ruff clean, CI green
merged this sprint  47 pull requests
open                12 PRs, 11 of them approved
milestone           21 closed / 6 open, due 19 August
```

### What was committed, and what happened to it

| Committed on day 1 | Outcome |
|---|---|
| **#78 timeboxed to item 1, explicit stop** | Item 1 done. The converter now models multi-interface rule sets and last-match-wins order (#104), and #142 split the refusal message so the two remaining blockers name their real causes. Still refuses the client's export — correctly. |
| **#16 split** | Not closed. |
| **#30 change impact** | **Done** (#140), with the trap it is built around now defended by a test (#152). |
| **#87 raised as the open question** | Made *decidable* (#134) rather than solved, and the gap re-measured across every fixture rather than the friendliest one (#158). |

### The two things that were not on the plan and mattered more than half of it

**M-1 — rule 1 was contradicting rule 4.** Raised as #99 in Sprint 3, unratified
for a week, and settled by @shubhamkataria2005 writing the text (#156) rather
than arguing further. The condition he added — *current* review, meaning no
commits pushed since the approval — was tested against eleven open PRs the day
it was proposed: ten passed, one failed, and the one it caught was carrying a
real post-approval fix.

**It then merged with two of four signatures**, which is the exact failure its
own body warned about, quoting A-2. §5d records that on the page rather than
tidying it away. Still 2 of 4 at the time of writing.

### What the sprint actually ran into

**Not a shortage of work. A shortage of merges.**

At the time of writing, **11 of 12 open pull requests are approved and green**,
and every one of them has been proven to merge together cleanly. Nine are the
SCRUM master's, held back by rule 1 as it stood before M-1 — which is precisely
the contradiction M-1 exists to fix, and which M-1 cannot fix until it is
ratified.

That is worth stating plainly for the retro, because it is a **process**
outcome rather than an engineering one, and it will not be visible in any
burndown: the work was finished, reviewed and green, and the sprint may still
close with it sitting in branches.

### The pattern that kept recurring, and the one that changed

Every significant defect found this sprint was the same shape the project has
been naming since Sprint 2 — *a weaker claim standing in for a stronger one*:

- a reachability query that could not observe the ACL it claimed to answer
  about, in **three separate modules in one week** (#108, `change_impact`, and
  the pin that now defends both)
- Dependabot **security alerts off** for weeks while `dependabot.yml` argued in
  a comment that they mattered
- **"it imports" standing in for "it is the version we declare"** — five of
  seven packages adrift locally, so CI tested pandas 3.x while the same suite
  locally tested 2.x, both green, on the same commit
- a stale README that made a teammate's status update **understate** the tool,
  which nobody fact-checks, because nobody audits a limitation

**What changed is who finds them.** Sprint 3's were found by the author. This
sprint's were mostly found by someone else re-running a claim rather than
reading it: @shubhamkataria2005 found #108 and the incomplete fix in #145;
@SamikaPerera found a false statement about the record inside a PR about record
accuracy; the SCRUM master found the environment drift only by verifying a
routine Dependabot bump he could have waved through.

### Still open at day 6

| | |
|---|---|
| **M-1 ratification** | 2 of 4. Releases nine approved PRs. |
| **#159** | 1 of 3 answered. @shubhamkataria2005 answered `1A 2A 3A 4A 5A` with two additions that are now verified and carried. |
| **#91** | Solved in #150 (Apache 2.0), approved, unmerged. |
| **#127** | Confirmed privately, not on the issue — so `.mailmap` still cannot record it. |

### One defect in this sprint's own process, found by a teammate

#159 re-lettered the five decisions so that **A** was always the
recommendation, convenient for replying `1A 2A 3A 4A 5A` — and it silently
contradicted the merged document, where decisions 2 and 4 recommend **B**.
@shubhamkataria2005 answered `2A` here having written `B` there and had to
explain that it was not a reversal.

**A form built to make agreement unambiguous made it ambiguous.** Corrected on
the issue with the mapping, and worth carrying into any future decision
request: do not re-letter options that already have letters somewhere else.


---

## Closing — written 19 August, 16:45, on the closing day

**Boundary stated first, because it changes how to read what follows.** This is
written inside the last day rather than after it, at 16:45 NZST. Sprint 3's
record was written the day after; this one is not, so a signature arriving
tonight would make one section below out of date. Everything here is what was
true at 16:45, measured rather than recalled.

### Measured

```
main                 598cae2   384 tests, ruff clean, CI green
merged 13-19 August  50 pull requests
open at close        16 PRs, 12 of them APPROVED, 13 of them the SCRUM master's
milestone            22 closed / 6 open
```

### The queue did not land, and that is the sprint's result

Say it plainly, because a burndown will not: **twelve approved, green pull
requests were still open when the sprint closed.** Every one of them had been
reviewed. Every one had been verified to merge with the others — most recently
onto `598cae2`, together, 416 tests, no conflicts, any order.

Two of them close sprint issues outright. **#150 closes #91** — the licence
decision, made and written. **#168 closes #127** — the mailmap, re-crediting
1,221 lines to the person who wrote them. Both sit in the "still open" column
of a milestone that will read 22/6.

**The blocker was never engineering.** It was §5d at two signatures of four.
M-1 was written to fix exactly this contradiction — rule 1 forbidding the
author to merge while rule 4 demands approved work land — merged on 17 August,
and then could not take effect, because ratification needs four ticks and got
two.

There is no version of this where the work was late. It was finished,
reviewed, green, and held by a rule that a rule change had already been
written to remove.

### What was actually delivered

| Committed on day 1 | Outcome |
|---|---|
| **#78 timeboxed to item 1** | Item 1 done. Multi-interface rule sets and last-match-wins order are modelled (#104); #142 split the refusal so the two remaining blockers name their real causes. Still refuses the client's export, correctly. |
| **#30 change impact** | **Done** (#140), and the trap it is built around is now defended by a test (#152). |
| **#16 split** | Not closed. #172 completes the setup instructions and is open. |
| **#87 as the open question** | Made **decidable** (#134), then **decided** — #159 collected `1A 2A 3A 4A 5A` from all three teammates, and the loader's refusal paths exist (#173). The gap itself has not moved and is not claimed to have. |

Unplanned and larger than half the plan: **M-1** settling #99, and the
**evaluation round** (#90) producing three independent ratings and a confirmed
defect in the AI layer.

### The pattern, and what changed about it

Every significant defect this sprint was the shape this project has named
since Sprint 2 — *a weaker claim standing in for a stronger one*:

- a query that could not observe the ACL it claimed to answer about, in
  **three separate modules in one week**
- Dependabot **security alerts off** for weeks while `dependabot.yml` argued
  in a comment that they mattered
- **"it imports" standing in for "it is the version we declare"** — five of
  seven packages adrift locally, CI testing pandas 3.x while the same suite
  locally tested 2.x, both green, same commit
- a stale README that made a status update **understate** the tool
- `preflight` reporting **"the service did not answer"** for an import error,
  in the one tool whose purpose is attributing failures to the right cause

**What changed is who finds them.** Sprint 3's were mostly the author's own.
This sprint: @shubhamkataria2005 found the query-layer bug and the incomplete
fix in #145; @SamikaPerera found a false claim about the record inside a PR
about record accuracy, and then found the `preflight` misattribution;
@patelankeet2 found and declined to fix a second AI-layer defect rather than
widen a contested PR.

That is the review culture doing the thing it was built for, and it is the
part of this sprint worth putting in the report.

### For the retrospective

1. **M-1 needs its fourth signature.** Until then the contradiction it fixes
   is still live and the queue is still held.
2. **Ratification is not merging.** M-1 merged at two of four while warning,
   in its own text, that A-2 had done exactly that. The signature row belongs
   in the merge checklist rather than in somebody's memory.
3. **A decision request must not re-letter options** that already have letters
   in a merged document. #159 did, and made agreement ambiguous in the form
   built to make it unambiguous.
4. **Two people filling disjoint rows of one table will conflict.** Land one,
   rebase the other. Do not merge them.

### v0.4.0

**Not tagged, and not tagged unilaterally on purpose.** `CONTRIBUTING.md` §5b
puts a release on the last commit of a sprint's work, and twelve approved PRs
of this sprint's work are not in `main`. Tagging now would cut a release that
omits the licence, the mailmap correction, the policy loader and the sprint
record itself.

**Proposal for the team, not a decision:** merge the queue, then tag `v0.4.0`
on the resulting `main`. If the queue lands after the sprint boundary, the tag
still belongs to Sprint 4's work — §5b's own worked examples cover that case.
