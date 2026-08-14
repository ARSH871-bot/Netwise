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
