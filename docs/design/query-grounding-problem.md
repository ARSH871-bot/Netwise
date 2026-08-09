# The query-grounding problem (US-11, natural-language questions)

**Status:** OPEN PROBLEM — no decision proposed yet, deliberately.
**Raised by:** Ankeet, reviewing the Sprint 3 proposal (#61).
**Written by:** Arsh (pipeline owner), because the fix is structural.
**Needed from:** whoever takes #11, before they write any of it.

> This is not a design. It is the statement of a problem we did not know we
> had, plus three candidate shapes and what each costs. If #11 is taken, the
> first task is choosing between them — not building.

---

## The gap, in one line

**Every safety mechanism in Netwise sits downstream of the query being the
right one.**

Constraint 2 in `CLAUDE.md` says the AI is grounded strictly in real Batfish
output and must never invent network behaviour. We enforce that *structurally*:
the model only receives real results and is only asked to rephrase them. That
enforcement is real, and it is complete — for the direction we have built.

`explain()` goes **findings → English**. A finding already exists. It was
produced by a check that ran a specific Batfish question with parameters a human
wrote. The model's whole job is rephrasing.

US-11 goes **English → findings**. Before anything can be explained, something
must decide *which* Batfish question to run and *with what parameters*. Nothing
in the current architecture does that, and nothing in it checks that answer.

## Why this is worse than a wrong finding

Ankeet's formulation on #61, which is the clearest statement of it:

> a confidently wrong *query* means the explanation afterward is grounded in the
> wrong question and still reads as authoritative

Walk it through. A user asks *"can the guest network reach the finance
server?"*. The translation step picks `traceroute` from a guest host to the
wrong destination — say the finance server's gateway rather than the server.
Batfish answers **truthfully**. The finding is real. `explain()` grounds
faithfully in genuine evidence. The user is told, with evidence attached, that
the guest network cannot reach finance.

Nothing hallucinated. Every guard did its job. The answer is wrong, and it is
wrong in the most dangerous way available to a security tool: *specific,
evidenced, and confident*.

Run our existing guards against that scenario and watch every one pass:

| Guard | Does it catch this? |
|---|---|
| F-4 `found`/`none`/`error` | No — the check genuinely ran |
| `_compute_dead_rule_outcome()` | No — computes shadowing, not intent |
| Thin-evidence refusal (#52) | No — the evidence is real and substantial |
| Validation + retry + fallback | No — the prose is accurate about the query |
| `risk` re-rating | No — it re-rates, it does not re-ask |
| Parse strictness | No — the config parsed fine |

**This is the same failure family as #47.** There, the converter faithfully
translated a config it had mis-modelled; every check downstream reasoned
correctly about a firewall that did not exist. We fixed that by making the
converter *refuse* when it could not be sure. The parallel is exact.

## What makes it tractable

We are not facing open-ended natural language. The surface is small and closed:

```
testFilters   searchFilters   filterLineReachability
undefinedReferences           traceroute
```

Five questions, each with a known parameter shape, against a snapshot whose
devices, interfaces and ACL names we can enumerate — `analysis/snapshot.py`
already reads the device list. A question naming a device that is not in the
snapshot is *detectably* wrong, not a matter of judgement.

That is the lever: **much of "is this the right query?" is checkable against the
snapshot rather than trusted.**

## Three candidate shapes

**A — Constrained selection.** The model never emits a query. It picks from an
enumerated list of parameterised templates, and every parameter is validated
against the snapshot before anything runs. Unmappable question → refuse and say
so.
*Cost:* only answers questions we anticipated. *Benefit:* the model cannot
express a wrong query, only fail to express one.

**B — Generate then verify.** The model proposes a query; code validates it
against the snapshot (devices exist, ACL names exist, IPs are in known subnets)
and rejects it otherwise.
*Cost:* validation catches malformed queries, not plausible-but-wrong ones —
the guest/gateway example above would pass. *Benefit:* wider coverage.

**C — Show the question back.** Whatever produces the query, the answer states
the question that was actually asked, in plain English, next to the result:
*"I checked whether 10.20.0.5 can reach 10.10.10.5 over TCP/443."*
*Cost:* none structurally; it does not prevent a wrong query. *Benefit:* it
makes one visible to the person best placed to notice — the one who asked.

**These are not exclusive, and C is close to free.** A or B decides how the
query is produced; C should probably be done regardless, because it converts a
silent wrong answer into a visible one.

## What I am not proposing

I am deliberately **not** picking one. Whoever takes #11 should, and this
document exists so that choice happens before the code rather than after.

What I would argue for, and expect to be argued with:

1. **C regardless.** A tool that shows its working is the difference between a
   user catching our mistake and trusting it.
2. **Start at A.** It is the same "refuse rather than guess" discipline the
   converter and `_compute_dead_rule_outcome()` already use, and this project
   has been right every time it chose refusing over guessing. Widen to B later
   if A proves too narrow — that direction is safe, the reverse is not.

## The estimate consequence

The Sprint 3 proposal (#61) called #11 "the cheapest remaining client-visible
win" because it reuses `explain()`'s safety-netted integration. That is true of
the plumbing and false about the hard part. **The translation step is new,
unproven, and is where the design effort belongs.** #11 still sits ahead of
#13/#14 — those need config *generation* on top of this same problem — but it
is not cheap, and planning should not treat it as such.
