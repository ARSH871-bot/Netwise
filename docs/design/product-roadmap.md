# What stands between Netwise and a product

**Written:** 12 August 2026, against `main` at `9988cff` (215 tests).
**Status:** analysis, not a plan. Sprint scope stays in `docs/sprintN/`.

This is the honest list, ordered by how much each thing prevents Netwise being
useful to someone who is not us. It is deliberately not a feature wishlist: two
of the six sections say "do nothing", and the largest gap is not on any story
board.

> **Two claims in the first draft of this document were wrong, and both were
> caught by re-running them rather than by review** — see §1.1 and §2.3, where
> the correction is left in place rather than tidied away. Both had the same
> cause: a result *recalled* instead of *re-measured*. That is this project's
> recurring defect family, and finding two instances of it in the document
> arguing for quality is the strongest evidence that the habit of re-running
> claims is worth its cost. **Every number below has been re-run on 12 August.**

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

Reproduce it — copy the fixture, rewrite the one name, run the pipeline on both:

```bash
cp -r tests/fixtures/rtr-us5-messy /tmp/stranger
sed -i 's/rtr-us5/acme-edge-fw/g' /tmp/stranger/configs/*
python -m analysis.pipeline tests/fixtures/rtr-us5-messy   # 6 found, 1 error
python -m analysis.pipeline /tmp/stranger                  # 3 found, 3 error
```

The three errors in the second run are `AC-001` (3 access policy statements),
`PC-050` (5 policy rules) and `RT-050` (2 route assertions) — **ten policy
statements, none of which can be checked**, which is the whole of our policy.

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

Designed, unbuilt, and **the primitive it needs works** — measured 12 August
against the two opposite fixtures:

```
secure -> insecure    differentialReachability=1 row    compareFilters=1 row
insecure -> secure    differentialReachability=1 row    compareFilters=1 row
```

and the row carries what the feature actually needs — the flow, plus the trace
from *both* snapshots:

```
Flow              start=rtr-us5 GigabitEthernet0/0 [10.10.10.2->10.10.10.0 ICMP]
Snapshot_Traces   RECEIVED -> PERMITTED(acl_in) -> FORWARDED
Reference_Traces  RECEIVED -> DENIED(acl_in)
```

**An earlier draft of this section claimed the opposite** — that
`differentialReachability` reported zero difference between a deny-all and a
permit-all config, and that `compareFilters` was the only working primitive. It
does not reproduce: a purpose-built deny-all/permit-all pair returns 1 row, and
so do the real fixtures in both directions. The claim was recalled rather than
re-run, and it would have sent whoever picked up #30 away from the correct
primitive. Recorded rather than quietly deleted, because "a weaker claim
standing in for a stronger one" is this project's recurring defect and **this
one was mine, in the document about quality.**

So the honest status is: no known trap, and the two primitives are
complementary rather than rival — `compareFilters` names the changed ACL
*lines*, `differentialReachability` shows the *traffic* whose fate changed.

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
(`Exited (137)`). A demo that starts with a dead container looks like a demo of
a dead product.

**Measured 12 August, and this is smaller than an earlier draft of this section
claimed.** The pipeline already handles it correctly: a simulated
`ConnectionError` produces **3 findings, all `status="error"`**, summary
*"Analysis could not run: Batfish is not reachable"*, and the detail already
ends with *"Is Docker running, and the batfish container started?"* F-4 holds —
no green tick is ever shown.

So the missing preflight the earlier draft asked for is **already there in
substance**. Two real defects remain, both narrow:

1. **The actionable sentence is buried.** The detail leads with ~200 characters
   of truncated urllib3 (`Max retries exceeded with url: /v2/question_templates
   … NewConnectionError('<urllib3.connection.HTTPConnection�`) and the advice
   comes last, past where a user stops reading. Put the instruction first and
   the raw error after it.
2. **It takes 21 seconds to say so** — pybatfish retries before giving up. On an
   unreachable (rather than refusing) host it hung for over 120 seconds in
   testing. The dashboard just spins.

Neither is a missing feature. Both are worth a small change to `connect()`.

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
