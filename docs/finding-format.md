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
| `id` | string | Unique identifier for this finding | Prefix by feature: `AC-` access control, `RT-` routing, `PC-` policy/change, `RK-` risk. Number within: `AC-001`, `AC-002` … |
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
