# Evaluation — does Netwise find the flaws it is meant to find?

**Measured:** 10 August 2026, against `main` at `b0ce0c5` (197 tests passing).
**Story:** US-15 (#15). This is the evidence chapter of the report.
**How to reproduce:** every number below comes from `python -m analysis.pipeline
<fixture>`. Nothing here is recalled or estimated; re-run the commands and you
get the same table.

---

## Read this before the numbers

**The headline result is 5 of 5 planted flaws detected, with no false positives
on the clean configurations. That number is weaker evidence than it looks, and
this section exists so nobody quotes it without the caveat.**

These are **our own fixtures**. We planted the flaws, we knew what they were,
and the checks were written against them. A tool scoring 100% on a test set its
authors wrote is demonstrating that *the checks do what they were designed to
do* — it is **not** evidence that Netwise would find an unknown flaw in a
configuration nobody had seen.

That stronger claim needs a configuration we did not write. We do not have one
yet. See "What this evaluation does not show" at the bottom, which is the
honest half of this document.

---

## Method

Each fixture is a synthetic configuration with a **documented, deliberate**
fault, recorded in a comment at the top of the config file itself before any
check was run against it. The fault list below is copied from those comments,
not reconstructed afterwards.

A flaw counts as **detected** when a finding with `status="found"` names it and
the evidence identifies the responsible config line. A finding that is merely
adjacent does not count.

Two configurations are **controls** with no planted fault. A false positive on
either would matter more than a miss, because a tool that cries wolf on a clean
config is one nobody keeps using.

---

## Results

### rtr-us5-insecure — 1 planted flaw

> *"the specific HTTPS rule has been replaced with a blanket `permit ip any
> any` … It silently allows everything."*

| Planted | Detected | Evidence produced |
|---|---|---|
| Blanket `permit ip any any` | ✅ | `Expected DENY but got PERMIT, decided by: permit ip any any` |

**5 findings, 1 flaw.** `AC-001`, `AC-002`, `PC-001`, `PC-002`, `PC-003` all
trace to the same root cause, seen from five angles: policy violation, an
example permitted flow, a forbidden destination, a non-HTTPS flow reaching the
internal server, and an accepted forged source address.

**Worth stating plainly: five findings is not five problems.** Independent
checks converging on one fault is the system working, but a reader counting
cards would overestimate the damage. Whether the dashboard should group them is
an open design question, not a defect.

### rtr-us5-messy — 3 planted flaws

> *"It contains three separate faults, one for each new access-control
> analysis."*

| Planted | Detected | Evidence produced |
|---|---|---|
| Blanket deny at the top makes two permits dead | ✅ | `AC-002`, `AC-003` — *"Unreachable line: permit udp … (action PERMIT)"* |
| `acl_guest_in` referenced but never defined | ✅ | `AC-004` — *"The structure 'acl_guest_in' is never defined"* |
| DNS that should be permitted is now denied | ✅ | `AC-001`, `PC-004` — *"Expected PERMIT but got DENY, decided by: deny ip 10.10.10.0 0.0.0.255 any"* |

**3 of 3.** `PC-005` additionally reports HTTPS blocked by the same deny — a
genuine consequence the fixture's comment does not list, so it is a *bonus*
detection rather than a planted one, and is excluded from the count.

**This fixture is the strongest result here**, because the three faults exercise
three different Batfish questions and one of them — the over-restrictive DNS
block — is the failure mode nobody thinks to test. A config that is too *closed*
looks like security at a glance.

### routing-missing-route — 1 planted flaw

> *"the static route from rtr-hq to rtr-branch's LAN was never added … a
> one-directional break, not a total one."*

| Planted | Detected | Evidence produced |
|---|---|---|
| Missing static route, HQ → branch | ✅ | `RT-001` — *"traceroute ended in NO_ROUTE. Path: rtr-hq"* |

**1 of 1**, and the *one-directional* nature is respected: the reverse direction
still holds and is not reported.

### Controls — configurations with nothing wrong

| Fixture | Result | False positives |
|---|---|---|
| `rtr-us5-secure` | `AC-000` none, `PC-000` none | **0** |
| `routing-secure` | `RT-000` none | **0** |

### Control — a configuration that cannot be read

| Fixture | Result |
|---|---|
| `unparseable` | **3 × `status="error"`** — *"Analysis could not run: the config did not fully parse"* |

This is the most important control in the document. A file Netwise cannot read
produces **three amber "could not check" results and zero green ticks.** It never
reports a config as clean because it failed to analyse it. That is F-4, and it is
the difference between a tool that is unhelpful and a tool that is dangerous.

---

## Summary

| Measure | Result |
|---|---|
| Planted flaws detected | **5 of 5** |
| False positives on clean configs | **0 of 2** |
| Unreadable config reported as clean | **Never** — 3 errors, 0 green ticks |
| Every detection names the responsible line | **Yes** |

---

## What this evaluation does not show

Stated as prominently as the results, because a reader who takes only the table
away has the wrong impression.

1. **It does not show Netwise finds unknown flaws.** Every fault here was
   planted by us and known to the check author. This measures design intent, not
   discovery.

2. **The sample is tiny.** Five flaws across three configurations. No statistical
   claim is possible, and none is made.

3. **No real configuration has been analysed.** The client's own PF Sense export
   would be the first, and is blocked on an open question about rule ordering
   (see `CLAUDE.md` §7). Until then, every result here is on configs we authored.

4. **The device-scoping errors are correct, but they are still gaps.** Several
   runs report *"N assertions could not be checked against this config"*. That is
   honest — those policy statements name devices not in the snapshot — but it
   means the checks are not covering those configs, and a real deployment would
   need policy statements written for the real devices.

5. **The explanation layer is not evaluated here.** Whether the plain-English
   text is *good* is a separate question from whether the findings are *correct*.
   That needs human judgement, and it should be its own evaluation.

6. **The natural-language question feature is not evaluated here.** It landed on
   10 August (#66), and it deserves its own measurement of how many reasonable
   questions it answers versus refuses.

**The honest one-line summary:** *the checks reliably detect the faults they were
built to detect and do not fire on clean configurations — which is a necessary
result, not a sufficient one.*
