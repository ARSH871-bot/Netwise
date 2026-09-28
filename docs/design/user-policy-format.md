# A policy the user can write — the decisions, not the design

**Status:** PROPOSAL, for #87. Nothing here is agreed.
**Written:** 13 August 2026, measured against `main` at 346 tests.

> **UPDATE, 21 August.** All five decisions below were ratified on #159 (all
> three of Arsh, Shubham and Samika replied `1A 2A 3A 4A 5A`). D1-D5 are
> implemented in `analysis/policy.py` (#173): an already-parsed mapping goes
> in, a validated `Policy` object comes out, failing loudly and naming the
> offending entry per D5. The vocabulary mismatch this document names below
> is fixed as of #177 -- `routing.py` adopts `node`, closing the last of the
> three checks still using the old name.
>
> **What has NOT changed: no check reads a `Policy` object yet.** #173 is
> explicit about this -- the loader exists, but `access_control`, `routing`
> and `policy_compliance` all still read their own hardcoded lists. The
> measurement in "The measurement that makes this worth doing" below is
> therefore still current: renaming a device still halves detection, because
> nothing has wired the loader into a single check. This document's original
> table is left as written below, since it is the record of the problem that
> motivated the decision, not something to quietly edit now that it is fixed.

> **UPDATE, 12 September 2026. The paragraph immediately above is now wrong,
> and it is the sentence in bold that went stale.**
>
> "No check reads a `Policy` object yet" was true on 21 August and false from
> 28 August, when #181 wired `policy_compliance`. `access_control` followed on
> #316 and `routing` on #319. All three read one now, so #87 is closed and
> "renaming a device still halves detection" no longer holds.
>
> Re-measured with `python -m tools.stranger_config`: 3 policy-driven
> detections on a stranger's network became 13, of which 3 are an artefact of
> rebinding our two-router routing assertions onto a single router — the
> comparable figure is **10**.
>
> Two dated notes now sit above a table that both describe. That is the cost
> of the convention this document chose, and it is the right cost: the table
> is still the record of why the format exists, and neither note pretends the
> other never applied.

#87 is the largest gap in the product: every policy assertion is hardcoded to
our own fixtures, so on a stranger's network Netwise reports only dead rules
and undefined references. This document exists to make that decidable, not to
decide it. **@shubhamkataria2005 offered to take the first increment** — the
questions below are what he would otherwise have to guess at.

---

## What is actually hardcoded, measured

```
access_control.POLICY            2 entries   rtr-us5
access_control.GUARANTEES        1 entry     rtr-us5
policy_compliance.POLICY_RULES   5 entries   rtr-us5
routing.ROUTES                   2 entries   rtr-hq, rtr-branch
```

**Ten entries, three device names.** That is the whole of it — smaller than
"no file format, no loader, no UI" suggests, and Shubham said so on #88:

> rules are **already plain data** — each carries its own `node`, `filter`,
> `kind`, `severity` and header constraints, deliberately so the policy could
> be edited without reading the code under it

He is right, and the measurement confirms it. What is missing is
serialisation plus a device binding, not a redesign.

---

## The thing nobody has noticed yet

The four structures use **different key names for the same concept**:

| concept | `access_control` | `policy_compliance` | `routing` |
|---|---|---|---|
| which device | `node` | `node` | **`start_node`** |
| how bad | `violation_severity` | **`severity`** | `violation_severity` |
| what should happen | `expected` | *(implied by `kind`)* | `expected` |

That is invisible while each list lives beside the code that reads it. **It
becomes a user-facing inconsistency the moment they share one file**, and a
user who writes `node:` under a route gets silence rather than an error.

**This is the decision that has to be made first**, because every other
question assumes an answer to it.

---

## Decision 1 — one vocabulary, or four sections that keep their own?

**A. Normalise.** One set of key names across all three checks. `node`
everywhere, `severity` everywhere.

- the file reads as one document rather than three dialects
- costs a rename inside three checks, all of it mechanical
- **breaks nothing at runtime** — these are internal dict keys today

**B. Keep four sections, each with its own shape.** Lowest immediate cost,
because each check keeps reading what it already reads.

- but it makes the *user* absorb an inconsistency that exists only because of
  how we happened to write three files

**Recommendation: A.** The user did not choose our key names and should not
inherit the accident. The rename is contained and mechanical, and doing it
before there is a file to migrate is free — the same argument that made A-2
cheap to do before `change_impact` existed.

---

## Decision 2 — where does the device name live?

Today every entry repeats it. Ten entries, three distinct values.

**A. Once at the top**, entries inherit it:

```yaml
device: acme-edge-fw
access_control:
  - description: DNS lookups to the approved server must be allowed
    filter: acl_in
    ...
```

**B. Per entry**, as now — required when one policy covers several devices,
which `routing` already does (`rtr-hq` **and** `rtr-branch`).

**Recommendation: B with an optional top-level default.** `routing` proves
multi-device policies are real, so A alone cannot express what we already
have. A default plus per-entry override covers both without forcing the
common case to repeat itself.

---

## Decision 3 — what happens when the policy names a device the snapshot lacks?

**This one is already answered and must not be re-litigated.** #29, #45 and
#50 established it: report **once per check**, as `status="error"`, saying how
many statements could not be applied and which devices they name.

A loaded policy changes nothing about that — it makes it *more* common, since
a user's policy will often be written before their config is uploaded.

**No decision needed. Just do not regress it.**

---

## Decision 4 — is an empty policy an error, or a valid mode?

**A. Error.** "You gave me no policy" is a real mistake worth naming.

**B. Valid** — run only the two policy-free analyses (dead rules, undefined
references) and say so.

**Recommendation: B, loudly.** It is the honest description of what Netwise
does for a stranger *today*, and it is a legitimate way to use the tool: point
it at a config, get the universal checks, add policy later. But it must say
which checks did not run, or it becomes the F-4 failure — a green screen that
means "we checked less than you think".

---

## Decision 5 — schema, or validate by hand?

Ten entries with seven keys each. **Recommendation: validate by hand and fail
loudly**, with a message naming the offending entry.

A schema library is a dependency, and `analysis/findings.py` already
demonstrates the alternative working: explicit validation with errors that
name the field. Adding a schema would be the second validation mechanism in a
codebase that has one.

---

## What this must NOT become

- **No policy DSL.** YAML or JSON that maps onto the existing dicts. The
  moment it grows expressions, it needs its own tests and its own failure
  modes, and the AI-grounding argument gets harder rather than easier.
- **No policy in the UI yet.** A file the user edits is enough to close #87.
  An editor is a separate story and should not block this one.
- **No silent defaults.** If a required field is missing, refuse and name it.
  A policy that half-loads is worse than one that will not load, for the same
  reason a check that half-runs is.

---

## The measurement that makes this worth doing

Rename one device in a fixture, change nothing else:

```
our device name      6 findings   access-control + policy-compliance
a stranger's name    3 findings   access-control only
```

**One rename removes half the detection.** Everything surviving is an analysis
that needs no policy. That is what this closes.
