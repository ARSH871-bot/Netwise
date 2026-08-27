# What is my own work, and where is the proof?

**Slice** policy compliance · change impact
**Owner** Shubham Kataria
**Format** the two-part shape from my Evidence Portfolio, now the team's.
One rule matters: *every row and every entry must name something a reader
can open and check.*

> Batfish answers questions about a network. It has no idea what your
> security policy **is**, which question to ask, or what an answer means.
> My slice is the layer that turns a policy written in English into
> questions a solver can prove, and the layer that says what a proposed
> change would actually do to traffic.

---

## Part 1 — Traceability

Read left to right: somebody asked for this → it became a story → here is
the code → here is the test that proves it → this is what the user sees. A
row that cannot be completed is work that was never really finished.

| What was asked for | Story | Rule | Implemented in | Proved by | Finding |
|---|---|---|---|---|---|
| The LAN may reach only the two approved servers | US-17 | POL-1 | `policy_compliance.py` — `POLICY_RULES[0]` | `tests/test_device_scoping.py` | `PC-001` high |
| The internal server is reachable only over HTTPS | US-17 | POL-2 | `policy_compliance.py` — two query arms | `tests/test_policy_partial_checks.py` | `PC-002` high |
| Only LAN addresses may enter the LAN interface | US-17 | POL-3 | `policy_compliance.py` | `tests/test_device_scoping.py` | `PC-003` medium |
| DNS to the approved resolver must work | US-17 | POL-4 | `policy_compliance.py` | PR #48 — the requirement rules fail when they should | `PC-004` medium |
| HTTPS to the internal server must work | US-17 | POL-5 | `policy_compliance.py` | PR #48 | `PC-005` medium |
| "What breaks if this rule changes?" | US-18 | — | `change_impact.py` — `analyse_change()` | `tests/test_change_impact.py` — 16 tests | `CH-001+` |
| A proven violation must survive a failed query | #22 | all | `policy_compliance.py` — per-arm isolation | `test_violation_survives_a_failing_arm` | `PC-002` + `PC-052` |
| A check that could not run must never look clean | F-4 | all | the `status="error"` path in both features | `tests/test_policy_partial_checks.py` | `PC-050` / `CH-050` |
| Evidence must name the required action, not a pronoun | #145 | all | `policy_compliance.py` — `_describe()` | `test_evidence_never_leaves_the_required_action_as_a_pronoun` | all `PC-` |

Rule numbers are **pinned**, never assigned in discovery order — POL-2 is
always `PC-002`, so an id means the same thing on every run. A retired
rule's number is never reused. Errors take the same number plus
`ERROR_NUMBER_OFFSET` (50), so a rule's violation and its check-error can
never collide.

Every file path and test name above was checked to exist before being
written here, not recalled.

---

## Part 2 — Decisions, and why

Each entry is a choice that could have gone the other way, the reason it
did not, and a source.

### Ignored the analysis approach the project brief specified

The brief says to use reachability checks. Measured against the fixture
whose ACL contains `permit ip any any`:

```
reachability(src=10.10.10.0/24, dst=10.20.0.5, tcp/80)
  actions="success" -> 0 rows
  actions="failure" -> 1 row   ORIGINATED, NO_ROUTE(Discarded)
```

`rtr-us5` has one interface and no route to `10.20.0.5`, so the dangerous
flow lands in the **failure** bucket for a routing reason, not a policy
one. A check reading "no successful flows means the policy holds" would put
a green tick on the config that permits everything.

There is a second failure in the same question, and it is the one that
catches anyone re-running this by hand. Widen the destination and a
*success* row appears:

```
... same query but dst=0.0.0.0/0
  actions="success" -> 1 row
     start=rtr-us5 [10.10.10.0->10.10.10.0 ICMP (type=8, code=0)]
```

That is the router reaching its own directly-connected LAN. Batfish returns
**one example flow per disposition**, and over a wide headerspace the
example it picks can be trivially local and say nothing about the rule
under test.

So the accurate claim is not *"reachability returns nothing"*. It is that
reachability answers a question about **paths**: the flow we care about is
filed under `failure` for the wrong reason, while a flow we do not care
about can surface as `success`. **Neither bucket means what a policy check
needs it to mean.** `searchFilters` reasons about the filter rather than the
path, so it needs no routing and cannot be fooled in either direction.

The broad-destination half was found by @ARSH871-bot re-running this
paragraph rather than reading it, after the earlier wording stated the
result without naming the headers. **A measurement is only reproducible if
its parameters travel with it.**

**Source** PR #18 · PR #198 · `docs/policy-rules.md` · reproducible live

### Rejected `invertSearch` for "everything except X"

`searchFilters` has a flag that searches *outside* a headerspace. It looks
like the natural way to write "anything to this server other than HTTPS".
It produces false alarms on a **clean** config: it inverts the whole
headerspace including the destination, so the search escapes to other
destinations entirely and returned the legitimate DNS traffic to a
different server as a violation. The complement is written out as separate
queries instead — which is why POL-2 has two arms, and why the arm-isolation
decision below matters.

**Source** `docs/policy-rules.md` · measured on `rtr-us5-secure`

### Severity grades how long a problem hides, not how bad it is

An availability rule sounds more serious than a silent exposure, and is
graded lower on purpose. A broken ACL is **loud** — the helpdesk hears
within minutes and someone reverts it the same morning. `permit ip any any`
is silent: nothing breaks, nobody complains, and it is still there at the
breach. Only a tool finds it.

Grading both `high` would dilute the word until "drop everything" and
"someone will notice this shortly" looked identical on the dashboard, and
the severity filter would stop being useful. `analysis/findings.py` already
commits to this reasoning: `error_finding()` is hardcoded `high` because a
blind spot in a security tool deserves attention.

**Source** `docs/policy-rules.md` — the severity model · signed off by the
`risk` owner, who owns severity under F-1

### A proven violation survives a failed query

One rule can ask several questions. The original code wrapped a rule's
whole query loop in one `try`, so this happened:

```
arm A proves a violation
arm B raises
-> the violation is discarded; the user sees only "could not check"
```

For a security tool that is the wrong trade. A **proven** violation
outranks the fact that a second query failed, and replacing it with "we
don't know" reads as *less* alarming than the truth — the same class of
mistake as confusing `none` with `error`. Both are now reported, in
different id bands so they cannot collide.

**Source** PR #46 · issue #22 · `test_violation_survives_a_failing_arm`

### Change impact pairs two questions rather than using either alone

Batfish offers `compareFilters` and `differentialReachability` as separate
features. The design uses both, because neither answers the question on its
own: **a changed rule that moves no traffic is noise, and moved traffic
with no changed rule is exactly the case a rule-diff misses.**

**Source** PR #140 · US-18 (#30) · `analysis/change_impact.py`

### Change impact is not a check, and must not be registered as one

`CHECKS` hands a check one snapshot. `differentialReachability` needs two.
So `change_impact` is a separate entry point — `analyse_change(before,
after)` — and both the module docstring and the registry comment say it
must never be added to `CHECKS`. It was written to a shape the team agreed
*before* the code existed, and needed no amendment to fit.

**Source** `docs/design/pipeline-feature-shapes.md` (adopted, four
signatures) · `analysis/pipeline.py` — the `CHECKS` comment

### Change impact was given its own id prefix, before it had any findings

Both features defaulted to `PC-000` for their sentinel finding, so a clean
policy run beside a failed change-impact run produced the same id twice.
The pipeline guard **detects** that; it cannot prevent it. If a consumer
keys findings by id, one of the pair disappears — and if the one that
disappears is the `error`, the user reads "all clear" and never learns a
check did not run.

A distinct prefix makes the collision impossible rather than detectable.
Raised and written on day one of the sprint, before `change_impact`
existed, so no finding had to be renumbered — free then, a migration later.

**Source** PR #102 · amendment A-2 in `docs/finding-format.md`, ratified by
all four

---

## Part 3 — Found by understanding the tool

Three defects no test suite would have surfaced, because in each case the
code ran, returned a confident answer, and was wrong. Two were in other
people's features; one was my own.

### The question layer never crossed the firewall

`ai/query.py` asked Batfish about traffic *starting at* the router — a
**node** location, which an inbound ACL is never crossed by. So it returned
the same confident answer for a secure config and a wide-open one, both
marked `grounded: True`.

Evidenced, reproducible, and wrong: the worst possible shape for a wrong
answer. Every guard in that feature checks the *answer* is grounded in the
*query*; none of them check the query was the right one.

**Source** issue #108 · fixed in PR #141 · `CLAUDE.md` §7c

### The evidence text inverted its own policy

`_describe()` ended "policy forbids it" / "policy requires it". The
required action was left as a **pronoun**, and the nearest thing to resolve
it to is the traffic's *current* treatment — which is by definition the
opposite of what policy wants. So the reference resolves backwards.

Explanations inverted in **both** directions. `PC-005` was caught by three
readers independently. `PC-001` was found only when a fourth reader rated it
cold and reported nearly accepting it — which is why the fix unified both
wordings rather than fixing the one direction we had seen fail.

The tests that should have caught it held a **copy** of the wording, so both
sides could have drifted with the suite green. They now call `_describe()`
on real rules. Verified by reintroducing the pronoun: three fail.

**Source** issue #145 · PR #194 · `test_evidence_never_leaves_the_required_action_as_a_pronoun`

### My own direction bug, in change impact

I assumed every row `differentialReachability` returns means traffic was
**opened**. The question is symmetric — it reports tightening the same way.
Found by running the comparison backwards and reading what came out.

My first tests did not catch it: the mutation passed. The wiring tests
exist because of that, not before it.

**Source** PR #140 · PR #152

---

## Part 4 — What it still cannot do

### The policy is ours, not the user's

Every rule in Part 1 is written against our own test network. Rename the
device and change nothing else, and half the detection disappears —
measured across all fixtures with `tools/stranger_config.py`:

```
                    ours          a stranger's config
                   f/n/e          f/n/e
TOTAL           12 / 3 / 7      3 / 0 / 15
```

What survives is the two analyses that need no policy at all — dead rules
and undefined references. This is the largest gap in the product (#87), it
affects `access_control` the same way, and the first work on it is in
review.

**What the scoping work fixed is honesty, not coverage.** On a config the
rules do not apply to, the check reports `status="error"` — "could not
check" — rather than a green tick. A tool that says *"I did not check
this"* is not broken. A tool that says *"all clear"* when nobody looked is
the failure the whole finding format exists to prevent.

A related gap I filed while measuring this: when a user *does* supply a
policy, `access_control` and `routing` still report **our** device names and
**our** counts back at them, because those two checks do not read a supplied
policy yet. F-4 holds narrowly — it says `error`, not `none` — but *"we
could not check your rules"* and *"we never read your rules"* are different
claims (#196).

---

*Every claim above resolves to a pull request, an issue, a file in this
repository, or a command that can be re-run. Measurements were taken from
the repository rather than recalled; the live figures in Part 1 and Part 4
were re-run on the day this was written.*
