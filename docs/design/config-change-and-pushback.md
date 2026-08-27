# Scoping #13/#14 — config change from plain English, and safety pushback

**Status:** OPEN PROBLEM — no decision proposed yet, deliberately, same
posture as `docs/design/query-grounding-problem.md` (US-11) before it was
built.
**Raised by:** Ankeet, scoping #13 and #14 before writing any of it.
**Needed from:** whoever picks up #13/#14 — this is the first task, not
building.

> **UPDATE, 21 August.** "What I would argue for" below is now built: a first
> PR implements shape A plus simulate-then-reanalyse (`ai/propose.py`), reusing
> `analysis/change_impact.analyse_change()` (#30) for the diff rather than
> building a second comparison mechanism. Precise about what this is and is
> not: it is the mechanism this document argued should exist regardless of the
> B-vs-C decision, not that decision being made. "Block YouTube" is still
> refused, on purpose -- widening past shape A is still open, exactly as
> argued below.

> Same shape as `query-grounding-problem.md`: not a design, the statement of
> a problem plus candidate shapes and what each costs. That document is a
> precondition for this one, not just prior art — see "Why this is harder
> than US-11" below.

---

## What #13 and #14 actually ask for

From the issues themselves:

- **#13 (US-13).** *"As a client, I can request a change in plain English
  ('block YouTube') and receive a proposed configuration change, so that I
  can act without technical knowledge."* Acceptance: the system generates a
  proposed config change and explains it. Scope note already fixes the
  ceiling: **generate and simulate only, never applied to a live device**
  (`CLAUDE.md` §4 repeats this as a non-negotiable scope limit, not a
  suggestion).
- **#14 (US-14).** *"As a client, if I propose an insecure change, the
  system warns me, so that I don't make things worse."* Acceptance: a
  known-bad request produces a warning rather than silent compliance.

Neither issue has a line of code behind it. `ai/` currently has exactly two
things: `explain()` (findings → English) and `query.py` (English → findings,
read-only). Nothing in the codebase writes a configuration line, and nothing
proposes one. This is not a partially-built feature — it is a gap.

## Why this is harder than US-11, not just bigger

`query-grounding-problem.md`'s whole argument is that translating English
into a Batfish *question* is dangerous because a wrong-but-plausible query
produces a truthful, evidenced, confidently wrong answer. Every existing
guard in this project — F-4, the dead-rule computation, thin-evidence
refusal, validation and retry — sits downstream of the query already being
right, and none of them catch the query itself being wrong.

#13 has the same shape one level up, with a worse failure mode. US-11 picks
*which existing fact to check*. #13 has to **synthesize a new configuration
line that does not exist yet**, from an instruction with no fixed
vocabulary ("block YouTube" names a service, not a protocol, port, or
address — Netwise has no notion of what "YouTube" resolves to, and
`CLAUDE.md` §4 already flags this as "genuinely hard... may only be partly
achievable"). A wrong *query* returns a wrong answer about the network as it
is. A wrong *generated config change* is a wrong claim about what a real
edit to the network **would do** — grounded in nothing yet, because nothing
has been applied, simulated, or checked.

**#14 depends on #13 being solved first.** You cannot warn that a proposed
change is insecure until a proposed change exists in a form that can be
evaluated. #14 is not a parallel, independent feature — it is a
post-condition on whatever #13 produces.

## What makes it tractable, and what doesn't

US-11's key move was noticing that "is this the right query?" is largely
*checkable* against the snapshot rather than trusted (device names, ACL
names, and address ranges either exist or they don't). The equivalent move
here is weaker, and it is important to be honest about that rather than
assume the same trick scales up:

- **A proposed rule's syntax is checkable.** Whether `deny tcp any host
  10.20.0.5 eq 443` is well-formed Cisco IOS is a parsing question, not a
  network-understanding one.
- **A proposed rule's *effect* is checkable, and this is the one real
  lever.** Netwise already has an engine built exactly for "if the
  configuration were X, what would happen" — Batfish, via a second
  snapshot. A proposed change does not have to be trusted, guessed at, or
  explained by a model reasoning about it in the abstract. It can be
  **applied to a scratch copy of the snapshot and re-analysed with the same
  pipeline that already exists**, and the before/after `analyse()` results
  compared. `change_impact` (owned by Shubham, `CH-` prefix per A-2) is
  already exactly this shape for a *given* before/after pair — #13 would be
  the first feature that has to *produce* the "after" snapshot rather than
  receive one.
- **What is not checkable is intent.** "Block YouTube" naming a *service*
  rather than a protocol/port/address has no deterministic resolution
  Netwise can perform offline — there is no DNS-independent, offline
  mapping from a service name to the address ranges it uses, and guessing
  one would be exactly the kind of invention constraint 2 exists to forbid.
  This is not a gap this project can close with better engineering; it is
  the ceiling `CLAUDE.md` §4 already names.

## Three candidate shapes for #13

**A — Constrained templates, addresses/ports only.** The system accepts
requests that reduce to a closed set of templates it can resolve without
guessing: block/allow `<source>` to `<destination>` on `<protocol>/<port>`,
where source and destination must resolve to literal addresses or CIDRs
already present in the snapshot (reusing `analysis/snapshot.py`'s
resolution, same as US-11's `answer_question()`). "Block YouTube" is
**refused**, with a reason, the same way US-11 refuses "can the guest
network reach the finance server" today. Generates one candidate config
line, in the target device's own syntax.
*Cost:* cannot handle the client's own headline example. *Benefit:* nothing
generated is guessed; every generated line names things that already exist
in the model.

**B — Constrained templates plus a declared, editable alias list.** Same as
A, plus a small, explicit, user-maintained mapping from service names to
address ranges (e.g. a config file the client fills in, "YouTube ->
`<ranges>`"), so "block YouTube" resolves through a mapping *the user
supplied*, not one Netwise invented. Netwise still never guesses; it looks
up a fact the user is responsible for.
*Cost:* real work the client has to do before the feature is useful to them
for anything but IP-level requests. *Benefit:* extends A to real client
scope without inventing anything.

**C — Open generation, verified after the fact.** A model proposes
arbitrary config text from the plain-English request; the system parses it,
applies it to a scratch snapshot, and only shows the result if it parses
cleanly and the resulting `analyse()` run does not silently break something
unrelated. Widest coverage.
*Cost:* the model is generating configuration syntax, not rephrasing
evidence — a materially different, larger trust surface than anything else
in this project, and the parse-and-reanalyse check only catches
*syntactically valid and non-regressive* mistakes, not "technically valid
but not what was asked for." A rule that compiles, applies cleanly, and
regresses nothing is not the same as a rule that does what the client
asked — that gap is exactly the "confidently wrong" failure
`query-grounding-problem.md` already warned about, one layer further out.

## What I would argue for

1. **Start at A, same reasoning US-11 used.** Refuse rather than guess.
   "Block YouTube" stays refused, with a clear reason, until B exists —
   consistent with how this project has resolved every prior
   guess-vs-refuse decision (the PF Sense converter, US-11 itself).
2. **#14 falls out of A almost for free, and should be built as a
   *property of the pipeline*, not a separate judgement.** If every
   candidate change is required to go through simulate-then-reanalyse
   before it is shown to the client, "insecure" has a deterministic
   definition available immediately: **the proposed change causes
   `analyse()` to newly report a `status="found"` finding it did not report
   before.** That is F-1 and the existing checks doing the safety work, the
   same way `_compute_dead_rule_outcome()` replaced model judgement with
   computation elsewhere. It does not require a model to decide what
   "insecure" means; it requires running the tool the project already
   trusts, twice, and diffing the result.
3. **Simulate-then-reanalyse should be the mechanism regardless of which of
   A/B/C is chosen for generation.** It is the one piece of this that is
   genuinely safe to build first, is useful on its own, and is a
   precondition for #14 under any of the three shapes above.

## What I am not proposing

I am not picking a final answer for B vs. staying at A permanently — that
is a product/client-scope question (does the client actually need
service-name blocking, or is address/port-level control sufficient for the
report). I am also not scoping the UI for presenting a proposed change;
that is downstream of this document, not part of it.

## The estimate consequence

**#13/#14 together are not a Sprint 4 item finished from a standing start.**
The simulate-then-reanalyse mechanism (shape A generation + diffing two
`analyse()` runs) is buildable and testable without Ollama, the same way
US-11 is — that part is concrete, scoped, and roughly comparable in size to
the routing check. Generation beyond shape A (service-name resolution, or
open generation) is not scoped here at all and should not be estimated
until a decision is made on B vs. C, if either is wanted.
