# What stands between Netwise and a product

**Written:** 12 August 2026, against `main` at `9988cff` (215 tests).
**Status:** analysis, not a plan. Sprint scope stays in `docs/sprintN/`.

This is the honest list, ordered by how much each thing prevents Netwise being
useful to someone who is not us. It is deliberately not a feature wishlist: two
of the six sections say "do nothing", and the largest gap is not on any story
board.

---

## Tier 0 — a stranger cannot use this yet

### 0.1 The policy is ours, not the user's — and this is the biggest gap

**Every policy assertion in the product is hardcoded to our test fixtures.**

```
analysis/checks/access_control.py     POLICY, GUARANTEES      name rtr-us5
analysis/checks/policy_compliance.py  POLICY_RULES            name rtr-us5
analysis/checks/routing.py            ROUTES                  name rtr-hq, rtr-branch
```

Two of those modules say so in a comment — *"PLACEHOLDER … the real client
policy will replace them"* — and nothing replaces them. **There is no mechanism
for a user to state their own policy at all.** No file format, no UI, no
loader; grep for one and there is nothing.

**Measured, not argued.** Take `rtr-us5-messy`, rename the device, change
nothing else:

| | findings | from |
|---|---|---|
| our device name | **6** | `access_control` + `policy_compliance` |
| a stranger's name | **3** | `access_control` only |

**One rename removes half the detection.** What survives is the two analyses
that need no policy — dead rules and undefined references. Everything that
makes Netwise more than a linter is unavailable to anybody but us.

The device-scoping work (#29, #45, #50) made that *honest* — the user is told
"could not check" rather than shown a green tick. It did not make it *useful*.
Honest and useless is better than dishonest, and still not a product.

**What it needs:** a policy file the user writes — devices, prohibitions,
requirements, route assertions — loaded at analysis time instead of imported
from Python. Design questions worth arguing before anyone builds it: what
happens when the policy names a device the snapshot lacks (the scoping answer
already exists), whether an empty policy is an error or a valid "just lint it"
mode, and whether the format is worth a schema or is small enough to validate
by hand.

**This is a bigger deal than anything on the board**, and it has no issue.

### 0.2 The converter cannot read the client's only real firewall

Tracked as **#78**, and Sprint 4's proposed scope. Zero of seven rules `quick`,
rules across four interface values against our one, 1,998 elements against our
54, plus `nat`, `openvpn`, `ipsec`, `aliases`.

Note the ordering: **0.1 outranks this.** If the converter were finished
tomorrow, the client's config would still produce only dead rules and undefined
references, because we have no way to express his policy.

---

## Tier 1 — the brief promises things that do not exist

### 1.1 Change-impact analysis (#30)

Designed, unbuilt. Carries a measured trap: `differentialReachability` reports
**zero difference** between a config that denies everything and one that permits
everything. `compareFilters` is the working primitive. The issue text still
names the broken one, so whoever picks it up walks into it.

### 1.2 Config change from English, and safety pushback (#13, #14)

The brief's "input direction". Deliberately **not** scheduled: they stack config
*generation* on the query-translation layer that is itself new, and the output
is something a person might apply to a firewall. Two unproven layers.

**Do not build these until the query layer has been used in anger.** That is a
"not yet", not a "no".

---

## Tier 2 — we cannot yet show that it works

### 2.1 The explanation layer is unevaluated

`docs/evaluation.md` measures detection and question-answering. It does not
measure whether the plain-English text is *good*, and cannot — that needs human
judgement. **This is the one thing a client actually reads**, and we have no
evidence about it beyond it not being wrong.

Cheapest useful version: five findings, four people rate each explanation for
accuracy and usefulness, disagreements recorded rather than averaged away.

### 2.2 No real configuration has ever been analysed

Every published number is against fixtures we wrote. Stated prominently in the
evaluation already; repeated here because it is the ceiling on every claim.

### 2.3 Operational fragility

The Batfish container was **OOM-killed twice** during one working day
(`Exited (137)`). Nothing detects that except a failed run, and the product
reports it correctly as `status="error"` — honest, and indistinguishable to the
user from a broken tool. A demo that starts with a dead container looks like a
demo of a dead product.

Worth: a preflight check that says "Batfish is not running: `docker start
batfish`" rather than surfacing a connection error as a finding.

---

## Tier 3 — real, small, and worth doing

- **`LICENSE` is missing.** Nobody — including the university and the client —
  can tell what they may do with this. Needs a decision, not a default; it is
  the one Tier 3 item that is genuinely blocking something.
- **Wider linting.** `--select E,F,W,I,UP,B,SIM` finds 256 issues and
  `ruff format` rewrites 10 files. Worth doing between sprints, never mid-sprint
  with open PRs against every module.
- **Explanation caching.** Every `/api/findings` call re-explains every finding.
  Fine at six findings; not at sixty.

---

## What we should NOT do, and why

Recorded because "world-class" invites adding things, and the discipline is
knowing which additions are noise.

- **No packaging or PyPI.** Netwise is not a library. Publishing invites the
  "just pip install it" workflow the offline constraint exists to prevent.
  Already decided in `CONTRIBUTING.md` §5b.
- **No `CHANGELOG.md`.** The same facts in a third place, and a fact stored
  twice is the documented cause of every staleness bug we have had.
- **No hosted demo.** The entire premise is that configuration data does not
  leave your machine. A hosted demo contradicts the product.
- **No cloud LLM fallback**, however tempting when Ollama is awkward. Constraint
  1 is not a preference.
- **No more test-count badges, dashboards or metrics.** We have measured
  evidence in `docs/evaluation.md`. A badge is a number in a second place.

---

## The honest summary

Netwise **works**, end to end, with measured evidence — for us.

For anyone else it is currently a linter that finds dead rules and undefined
references, because the policy is ours and the converter cannot read their
firewall. Those two gaps, **0.1 and 0.2, are the product**; everything below
them is improvement to something that already functions.

If only one thing gets built next, it should be **0.1** — user-definable
policy. It is the difference between a tool that analyses our test network and
a tool that analyses yours, and unlike 0.2 it is entirely within our control.
