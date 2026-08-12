# Sprint 4 — planning proposal

**Status:** PROPOSAL — not agreed. Argue with it.
**Proposed dates:** 13–19 August 2026 (the seven-day cadence of Sprints 1–3)
**Written:** 12 August 2026, on Sprint 3's closing day

> Same shape as `docs/sprint3/SPRINT3.md`: a proposal the team changes, not a
> plan handed down. Sprint 3's version was improved by all three of you, and
> two of those changes were corrections rather than additions.
>
> Replace this line with `**Status:** Agreed` once scope is settled.

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

1. **Multi-interface rule sets** — several ACLs, each bound to its own
   interface, rather than one `acl_in`. **Blocks 2 and 3.**
2. **Real PF Sense evaluation order** — last-match-wins, or a per-pair refusal
   that is defensible rather than blanket. With zero `quick` rules, #58's
   current check refuses every overlapping pair.
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
| **Shubham** | #30 change-impact, **with `compareFilters`** | Design agreed, nothing written, and he has already measured that the story's stated primitive does not work |
| **Samika** | #16 deployment & docs, the user-facing half | It is what the capstone is marked on and nobody has started it; he owns everything a user touches |
| **Arsh** | Land the carry-over, then #16's engineering half | Two of my PRs are the queue; clearing them is worth more than starting anything |

**Not this sprint: #13 and #14.** Shubham's argument from Sprint 3 stands and
has not weakened — they stack config *generation* on top of a translation layer
that is still new. Two unproven layers, where the output is something a person
might apply to a firewall. Recorded as **neither**, explicitly, so it is not
reopened on day 5.

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
