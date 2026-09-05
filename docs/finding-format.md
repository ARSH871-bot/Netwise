# Netwise — Finding Format (F-1)

**Status:** Agreed by all four members on 30 July 2026. Do not change without full team agreement.

**Purpose:** Every analysis in Netwise returns findings in this exact shape, so the AI layer and the dashboard handle all four features identically.

---

## The rule

Every check any of us writes returns a **list of findings**. Each finding is a dictionary with these fields — all required:

```python
{
    "id":       "AC-001",
    "check":    "access_control",
    "severity": "high",
    "device":   "rtr-us5",
    "summary":  "Guest subnet can reach the finance server",
    "evidence": {
        "detail": "permit ip 10.20.0.0 0.0.0.255 any",
        "source": "rtr-us5.cfg:14"
    },
    "status":   "found"
}
```

---

## Field definitions

| Field | Type | Meaning | Rules |
|---|---|---|---|
| `id` | string | Unique identifier for this finding | Prefix by feature: `AC-` access control, `RT-` routing, `PC-` policy compliance, `CH-` change impact, `RK-` risk. **One prefix per check — never shared.** Number within: `AC-001`, `AC-002` … |
| `check` | string | Which analysis produced it | One of: `access_control`, `routing`, `policy_compliance`, `change_impact`, `risk` |
| `severity` | string | How serious | `high`, `medium`, or `low` only. Set by the check as a **default**; `risk` may re-rate it (see below). **Never set by the AI.** |
| `device` | string | Which device it's on | The Batfish node name, e.g. `rtr-us5` |
| `summary` | string | One-line plain description | Written by the check author. Keep under ~100 chars. This is what the AI expands, not replaces. |
| `evidence` | object | The proof from Batfish | `detail` = the config line or Batfish result; `source` = `filename:line` where possible |
| `status` | string | Did the check run? | `found`, `none`, or `error` — **this is F-4** |

---

## The status field — read this carefully (F-4, safety-critical)

`status` is the most important field. It exists so we never tell a user they are safe when we actually did not check.

- **`found`** — the check ran and found a problem. The other fields describe it.
- **`none`** — the check ran successfully and found nothing. Good news. `summary` = "No issues found by [check]". `severity` can be `low`.
- **`error`** — the check failed to run (config did not parse, Batfish threw an error, etc.). **This is NOT the same as `none`.** `summary` must say what went wrong.

**The dashboard must display `none` and `error` differently.** "Nothing found" is a green tick. "Check failed" is an amber warning. If they look the same, the tool lies.

---

## The severity field — who sets it

Three parties could plausibly set `severity`, and exactly one of them may not.

- **The check sets a default.** The author of a statement knows what it was
  for, so they give it a severity when they build the finding. Every finding
  therefore carries a severity from the moment it exists — including the
  sentinels, where `none` is pinned to `low` and `error` to `high`.
- **`risk` may re-rate it.** Prioritisation means looking at every finding
  together, which no individual check can do. The rules are written down in
  [`docs/severity-rules.md`](severity-rules.md) and are deterministic, so any
  re-rating can be recomputed by hand from the finding alone.
- **The AI never sets it.** Severity is a judgement. The model's job is to
  rephrase what a check already found, grounded in `evidence` — not to decide
  how serious it is. This is the half of the original wording that was always
  right, and it is not up for negotiation.

Two limits on re-rating, enforced in `pipeline.run_post_processors()` rather
than trusted: `risk` may not downgrade a `status="error"` finding, and may not
drop one. An unrunnable check is a blind spot whatever a rule says about the
device.

> **Why this section exists.** This table used to read "Assigned by Samika's
> rules, not by the AI", which was accurate about the AI and wrong about the
> checks — they have set their own severity since the first one was written.
> The behaviour was settled when
> [`docs/design/pipeline-feature-shapes.md`](design/pipeline-feature-shapes.md)
> was adopted; §7 of that document flagged this sentence as a separate F-1 edit
> needing all four members, which is what this change is.

---

## Why one prefix per check (A-2)

`id` is called a unique identifier above, and everything downstream is entitled
to believe it — a dashboard keying findings by `id`, the AI layer referring to
one, a diff between two runs.

Two checks sharing a prefix makes that uniqueness a matter of **discipline**
rather than structure. `policy_compliance` and `change_impact` shared `PC-`,
and both take `SENTINEL_NUMBER = 0` by default, so a clean policy run beside a
failed change-impact run produces `PC-000` twice:

```
change_impact     error (defaults)  ->  PC-000
policy_compliance none  (defaults)  ->  PC-000
```

`pipeline.duplicate_id_findings()` **detects** that and reports it loudly. It
cannot **prevent** it, and a numbering convention split across two documents is
exactly the kind of agreement that holds until someone is in a hurry.

The failure it guards against is F-4 arriving through `id` instead of through
`status`: if a consumer keys by `id`, one of a colliding pair disappears — and
if the one that disappears is the `error`, the user reads "policy compliance:
all clear" and never learns that change impact did not run.

**A distinct prefix makes the collision impossible rather than detectable.**
The guards stay regardless: uniqueness is still not structurally enforced
*within* a check, so `duplicate_id_findings()` and the "never key findings by
`id`" rule in `web/static/app.js` remain correct and remain tested.


---

## Worked examples

**A real problem found:**

```python
{
    "id": "AC-001", "check": "access_control", "severity": "high",
    "device": "rtr-us5",
    "summary": "External interface permits unrestricted inbound traffic",
    "evidence": {"detail": "permit ip any any", "source": "rtr-us5.cfg:22"},
    "status": "found"
}
```

**A check that ran clean:**

```python
{
    "id": "RT-000", "check": "routing", "severity": "low",
    "device": "rtr-us5",
    "summary": "No unreachable destinations found",
    "evidence": {"detail": "all nodes reachable", "source": "rtr-us5"},
    "status": "none"
}
```

**A check that failed:**

```python
{
    "id": "PC-000", "check": "policy_compliance", "severity": "high",
    "device": "unknown",
    "summary": "Policy check could not run: config failed to parse",
    "evidence": {"detail": "parse error", "source": "firewall.cfg"},
    "status": "error"
}
```

---

## What this means for each of us

- **Arsh, Ankeet, Shubham** — your analysis code returns a list of these dictionaries. Whatever Batfish gives you, reshape it into this. Nothing else.
- **Ankeet (AI)** — you receive these dictionaries and expand `summary` into plain English, grounded in `evidence`. You never invent fields.
- **Samika** — `risk` re-rates `severity` by the rules in `docs/severity-rules.md`, and your dashboard renders these dictionaries, handling `found` / `none` / `error` distinctly.

---

## The one contract

If your code returns this shape, it fits the whole system. If it does not, it breaks. This file is the agreement. Changes need all four of us.

---

## Amendment record

Changes to this file need all four members. Recording that here means "agreed"
is a fact anyone can check, rather than something inferred from a PR having
been merged quietly — the same reasoning that put a sign-off table in
`docs/design/pipeline-feature-shapes.md`.

**Merging this PR means the wording is worth having. It does NOT mean the
amendment is ratified.** Ratification is the table below.

### A-1 — severity is set by the check and re-ratable by `risk`

Changes the `severity` row from "Assigned by Samika's rules, not by the AI" to
"Set by the check as a default; `risk` may re-rate it. Never set by the AI",
and adds the section explaining it. **No behaviour changes** — this describes
what the code has always done and what the adopted shapes proposal already
decided. It is the sentence catching up.

| Member | Why it touches them | Agreed |
|---|---|---|
| **Arsh** | Owns `pipeline.py`; enforces the two re-rating limits in `run_post_processors()` | ✅ |
| **Ankeet** | Owns the AI layer; the "never set by the AI" half is unchanged and still binding | ✅ |
| **Shubham** | `policy_compliance` sets its own severities and continues to | ✅ |
| **Samika** | Owns `risk` and `docs/severity-rules.md`, written against this wording | ✅ |

### A-2 — `change_impact` gets its own ID prefix (`CH-`)

Changes the `id` row so `PC-` means `policy_compliance` only and
`change_impact` uses **`CH-`**, and adds the section above explaining why a
shared prefix cannot be made safe by convention. Requires one line in
`analysis/findings.py`:

```python
-    "change_impact": "PC",
+    "change_impact": "CH",
```

**No finding changes id.** `change_impact` is not written — nothing emits a
`change_impact` finding today except `web/mock_findings.py`, which exists to
demonstrate the collision. That is precisely why now: the amendment is free
before the code exists and a migration afterwards.

`CH-` rather than `CI-`: this repository runs CI, and `CI-001` in a findings
list would read as a build identifier to anyone skimming.

Raised from #95, filed after review of #86 noted that #30 is blocked on an
amendment nobody had scheduled. A-1 took six days to collect four signatures.

| Member | Why it touches them | Agreed |
|---|---|---|
| **Shubham** | Owns both checks; `policy_compliance` is the one that collides, and `change_impact` is the one being renumbered | ✅ |
| **Arsh** | Owns `findings.py` and `pipeline.duplicate_id_findings()`, the guard this makes redundant for this pair | ✅ |
| **Samika** | The dashboard renders `id`, and `web/mock_findings.py` carries the colliding pair deliberately | ✅ |
| **Ankeet** | The AI layer refers to findings by `id` | ✅ |

> **A-2's code merged on 13 August while this table was incomplete**, which is
> the one thing #102's own header said not to do:
>
> > ⚠️ *Do not merge before the ratification table is complete.* A-1 could be
> > merged early because it was wording describing behaviour that already
> > existed. **This one carries a code change.** Merging it unratified puts the
> > contract and the code in exactly the disagreement A-1 existed to fix.
>
> That is what happened. `change_impact` uses `CH-` on `main` today, and this
> table says two of four had not agreed to it.
>
> **The agreement exists; only the record lagged.** All four approved on
> GitHub — @patelankeet2 22:35, @SamikaPerera 22:43, Arsh 22:51, and
> @shubhamkataria2005 as author. Arsh's tick above is therefore a *correction
> to the record*, not a new decision: it states here what his approving review
> already stated on the PR.
>
> **Ankeet's sat ⬜ from 13 to 31 August**, waiting on the one word #102 asked
> for rather than a guess on his behalf. Confirmed on #102: the approval was
> A-2 agreement, not just "the code looks right" — two different claims, and
> this table is the one that counts. **RATIFIED — four of four**, as of 31
> August.
>
> **The lesson is the mechanism, not the people.** An approval and a tick are
> two records of one fact, kept in different places, updated by different
> actions. That is the shape of every staleness bug this project has had. If a
> third amendment ever happens, the tick should be part of approving rather
> than a separate chore someone remembers.


### A-3 — an OPTIONAL `subject`, so findings can be joined without parsing prose

**PROPOSED, not ratified. Nothing depends on this yet and nothing should
until the table below is full.**

Raised because **#238** (attack-path chaining) cannot start without it, and
that issue's own acceptance criteria say so: *"Any finding-format change is
raised and ratified separately before it is used."* This is that.

#### The problem, measured

Chaining means recognising that finding A's traffic reaches the device
finding B is about. So something has to join them. Today, only one field is
machine-readable:

```
AC-001  keys = [check, device, evidence, id, severity, status, summary]
        device : 'rtr-us5'
        detail : 'Expected DENY but got PERMIT, decided by: permit ip any any'

structured rule / flow / policy / src / dst / port on ANY finding:  none
```

Everything except `device` is inside one free-text sentence. Joining findings
today means **parsing `evidence.detail` with a regex**, and this project has
been burnt by exactly that twice in a fortnight:

- **#145/#194** — `ai/explain.py` matched the evidence wording with
  `_POLICY_DETAIL_PATTERN`. Rewording the evidence silently stopped the guard
  matching anything; it degraded to the generic path rather than failing.
- **#205** — a test held a *copy* of that wording. It stopped matching either
  side and kept passing while proving nothing.

A prose parser at the centre of a *security* join would be the same mistake
with worse consequences: a chain that silently stops forming is a
vulnerability nobody is shown.

#### The change

One **optional** key on a finding:

```python
"subject": {"dst": "10.20.0.5", "dstPort": 443, "protocol": "tcp"}
```

Every key inside it is optional too. A check populates what it actually
knows and omits the rest.

```python
make_finding(..., subject={"dst": "10.20.0.5"})   # new, optional
make_finding(...)                                  # unchanged, still valid
```

#### What it deliberately does not do

- **It does not replace `evidence.detail`.** The prose stays exactly as it
  is, so `ai/explain.py`, the dashboard's `finding.evidence.detail`, and
  #194's guard are all untouched. `subject` is a second, machine-readable
  view of what the sentence already says — never the only copy.
- **It is not required.** No existing finding changes, no check must be
  edited, and a check that cannot fill it truthfully leaves it out. An
  optional field nobody populates is inert; a required one would force every
  check to invent a value, which is how `device="unknown"` already happens.
- **It carries no severity, no judgement, and no new vocabulary.** Only
  facts the check already had in hand before it wrote them into a sentence.

#### Why optional rather than required

Required would mean `routing`, `access_control` and `policy_compliance` all
producing a `subject` on day one, including for findings where the honest
answer is "this is about a config structure, not a flow" — an undefined ACL
reference has no destination. Forcing a value there invents one.

The cost is that a consumer must handle its absence. That is the correct
cost: **a chain that cannot be formed should not be formed**, and a missing
`subject` says so explicitly rather than by a parser finding nothing.

#### The alternative that was rejected

Parse `evidence.detail`. Cheaper today, no amendment, no signatures — and it
puts a regex between two findings whose combination is the whole point. The
two incidents above are the argument, and both were in code with tests.

| Member | Why it touches them | Agreed |
|---|---|---|
| **Shubham** | Raised it; #238 is blocked on it and `policy_compliance` would populate it first | ✅ |
| **Arsh** | Owns `analysis/findings.py`, where the optional field is validated, and `access_control` would be a second producer | ⬜ |
| **Ankeet** | The AI layer reads `evidence.detail`, which this deliberately does not touch — his sign-off is the check on that claim | ✅ |
| **Samika** | `risk` reads every finding and the dashboard renders them; an unrendered new field is his to decide about | ✅ |

> **NOT RATIFIED — three of four, as of 3 September.** Confirmed on #269: the
> specific claim this row depends on was checked directly rather than trusted
> — `subject` appears nowhere in `ai/` or in `analysis/findings.py` today, so
> "deliberately does not touch `evidence.detail`" holds exactly as written.
> Merging this PR means the wording is worth having. It does **not** mean the
> amendment is agreed, and **no code may populate or read `subject` until
> this table is full.** A-2 merged at two of four with its code already on
> `main`, and this file spends two paragraphs on why that was wrong. #238
> waits on @ARSH871-bot.
>
> **Samika's tick is dated 31 August, not today.** He posted *"Signing.
> Clean and genuinely optional -- doesn't touch evidence.detail, doesn't add
> severity or new vocabulary"* on #269 at 03:16 that morning; the PR merged
> at 03:54, thirty-eight minutes later, with his row still ⬜. The agreement
> existed the whole time and lived only in a comment.
>
> That is this file's own recurring lesson happening to this file: an
> approval and a tick are two records of one fact, kept in different places,
> updated by different people. A-2's note draws exactly that conclusion from
> Ankeet's row sitting blank for seventeen days after he had confirmed on
> #102 — and the same thing was already true here, two sections down, while
> that paragraph was being written.
>
> Recorded rather than backdated silently: the tick goes in now, the date it
> was actually given is stated, and the gap is left visible because the gap
> is the finding.
