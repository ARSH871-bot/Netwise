# Netwise — Finding Format (F-1)

**Status:** Agreed by all four members on ______________. Do not change without full team agreement.

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
| `severity` | string | How serious | `high`, `medium`, or `low` only. **Assigned by Samika's rules, not by the AI.** |
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
- **Samika** — you set `severity` by your rules, and your dashboard renders these dictionaries, handling `found` / `none` / `error` distinctly.

---

## The one contract

If your code returns this shape, it fits the whole system. If it does not, it breaks. This file is the agreement. Changes need all four of us.
