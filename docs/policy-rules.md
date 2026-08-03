# Netwise — Security Policy Rules (P-1)

**Status:** Rules, IDs, and the `findings.py` change agreed (Arsh).
**Severity values agreed (Samika). All decisions settled — clear to build.**
**Owner:** Shubham (policy compliance + change impact)
**Feeds:** `analysis/checks/policy_compliance.py` (US-17)

This document is the human-readable source of truth for the rules the
policy-compliance check tests. The check holds the same list as plain data, in
the style of the `POLICY` list in `analysis/checks/access_control.py`. If you
change a rule here, change it there — and vice versa.

Findings are returned in the F-1 shape defined by
[`docs/finding-format.md`](finding-format.md). Nothing here changes that contract.

---

## 1. Scope

Every rule below is asserted against **one device and one filter**:

| | |
|---|---|
| Device (Batfish node) | `rtr-us5` |
| Filter | `acl_in`, applied **inbound** on `GigabitEthernet0/0` |
| Interface address | `10.10.10.1/24` |

The fixtures contain exactly one router with one ACL, so the rules name that
device and filter explicitly rather than trying to discover filters
automatically. When real client configs arrive, each rule carries its own
`node` and `filter`, so the list extends without the check changing.

### The address space these rules talk about

| Address | What it is | Where it comes from |
|---|---|---|
| `10.10.10.0/24` | The internal user LAN behind `GigabitEthernet0/0` | The interface address in both fixtures |
| `218.8.104.58` | The one approved external DNS resolver | `permit udp … host 218.8.104.58 eq domain` |
| `10.20.0.5` | An internal server, intended to be HTTPS-only | `permit tcp … host 10.20.0.5 eq 443` |

Because `acl_in` is applied **inbound on the LAN interface**, the traffic it
filters originates *from* `10.10.10.0/24`. That is why every rule below is
written from the LAN's point of view.

---

## 2. How a rule becomes a Batfish question

Rules come in two directions, and the direction decides the query. This is the
mechanical part of the contract — get it wrong and the result inverts.

| Rule kind | Says | Query | Empty result means |
|---|---|---|---|
| **Prohibition** | "this traffic must be blocked" | `searchFilters(action="permit", headers=<the forbidden space>)` | Nothing in that space is permitted → **policy holds** |
| **Requirement** | "this traffic must be allowed" | `searchFilters(action="deny", headers=<the required space>)` | Nothing in that space is denied → **policy holds** |

`searchFilters` searches an entire **space** of flows, not one packet. An empty
answer is therefore a proof over that whole space, not a spot-check that missed
something — this is the capability Sprint 1 identified as our strongest.

### Why `searchFilters` and not `reachability`

The task brief suggests reachability checks. **Do not use bare `reachability`
for these rules.** `rtr-us5` has a single interface and no route to `10.20.0.5`,
so end-to-end reachability fails for a routing reason, not a policy reason.
Measured against the **insecure** fixture — the one containing `permit ip any any`:

```
reachability(actions="success", 10.10.10.0/24 -> 10.20.0.5, http)   ->  0 rows
reachability(actions="failure", same headers)                       ->  1 row
    Traces: ((ORIGINATED(default), NO_ROUTE(Discarded)))
```

Zero successful flows, because there is no route. A check that read "empty =
policy holds" would report **`status="none"` — a green tick — on the config that
permits everything.** That is exactly the failure F-4 exists to prevent.

`searchFilters` reasons at the filter level and needs no routing, so it is
correct on these fixtures and on any config where policy intent lives in ACLs.

### Why an empty result is safe to trust

With `searchFilters`, "empty" carries meaning, so it matters that empty cannot
also mean "we asked the wrong question". Measured: a wrong `nodes` or `filters`
name **raises `BatfishException`** rather than returning an empty frame.

So the check must let that exception surface as a `status="error"` finding and
must never wrap these calls in a bare `except: pass`. Empty then means exactly
one thing: the policy holds.

### Do not use `invertSearch` to express "everything except X"

`searchFilters` has an `invertSearch` flag that searches *outside* the given
headerspace. It looks like the natural way to write "anything to `10.20.0.5`
other than TCP/443". **It is not, and it produces false positives.**

`invertSearch` inverts the *whole* headerspace, including `srcIps` and `dstIps`,
so the destination constraint is inverted too and the search escapes to other
destinations entirely. Measured against the **secure** fixture:

```
searchFilters(action="permit", invertSearch=True,
              headers={src: 10.10.10.0/24, dst: 10.20.0.5, tcp/443})
  -> 1 row   permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain
             flow: 10.10.10.0 -> 218.8.104.58:53 UDP
```

That "violation" is the legitimate DNS traffic to a different server. On a clean
config. To exclude a port or protocol while pinning source and destination,
write the complement explicitly as separate queries instead — see POL-2.

---

## 3. The rules

Severity values are **agreed** — confirmed by Samika, who owns severity under
`docs/finding-format.md`.

| Rule | Finding ID | Kind | Severity |
|---|---|---|---|
| POL-1 | `PC-001` | Prohibition | high |
| POL-2 | `PC-002` | Prohibition | high |
| POL-3 | `PC-003` | Prohibition | medium |
| POL-4 | `PC-004` | Requirement | medium |
| POL-5 | `PC-005` | Requirement | medium |

### The severity model — why these values

Severity here is not graded on impact alone. It is graded on **how long the
problem survives without anyone noticing**, because that is what a config
analysis tool uniquely adds. `analysis/findings.py` already commits to this:
`error_finding()` is hardcoded `high` on the grounds that *"a blind spot in a
security tool deserves the user's attention rather than being quietly filed at
the bottom of the list."* The rules follow the same logic.

| Severity | Means | Rules |
|---|---|---|
| **high** | A **silent** security exposure. Nothing breaks, nobody complains, and it is still there at the breach. Only a tool finds it. | POL-1, POL-2 |
| **medium** | Either an **enabler** of other attacks rather than a breach in itself, or a **self-announcing** availability failure — one the helpdesk will hear about within minutes and someone will roll back. | POL-3, POL-4, POL-5 |
| **low** | Reserved for the `status="none"` sentinel, per `no_issues_finding()`. | — |

**On POL-4 and POL-5 specifically.** Samika reasonably asked whether an
availability rule should be `high`, since a DNS outage takes the whole site
down. Impact is indeed severe — but it is *loud*. A broken ACL gets reported and
reverted the same morning; `permit ip any any` does not, because nothing breaks.
Grading both tiers the same would dilute `high` until "drop everything" and
"someone will notice this shortly" looked identical on the dashboard, and the
severity filter would stop being useful.

This is a deliberate, documented position rather than a per-rule judgement, so
any rule added later grades itself: *silent and exploitable* → high; *noisy or
merely enabling* → medium.

> **This model is now project-wide.** Samika, as severity owner, has adopted it
> as the standard for the whole dashboard — not just these rules. Routing,
> risk, change impact and the remaining access-control checks will be graded the
> same way. Folding it into `docs/finding-format.md` would make it part of the
> F-1 contract; that document needs **all four** members to change, and Ankeet
> has not weighed in yet, so it stays recorded here for now.

> Blast radius was considered as an alternative basis — POL-4 is site-wide,
> POL-5 affects one service — which would argue for splitting them. It was
> rejected to keep severity derivable from a stated principle instead of
> argued rule by rule.

### Prohibitions

#### POL-1 — The LAN may reach only the two approved servers → `PC-001`

> Traffic from `10.10.10.0/24` to any destination other than `218.8.104.58` or
> `10.20.0.5` must be blocked.

**Why it matters.** This is the default-deny rule that gives every other rule
its meaning. Without it the ACL is advisory: a host on the LAN can talk to
anything on the internet, so data can leave and malware can call home. It is
also the rule that most directly catches the classic `permit ip any any` added
to "fix" a connectivity complaint and never removed.

**Applies to:** source `10.10.10.0/24`; destination everything except
`218.8.104.58` and `10.20.0.5`.

```python
searchFilters(nodes="rtr-us5", filters="acl_in", action="permit",
              headers=HeaderConstraints(
                  srcIps="10.10.10.0/24",
                  dstIps="0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)"))
```

Severity **high** — unrestricted egress is broad, silent exposure.

#### POL-2 — The internal server is reachable only over HTTPS → `PC-002`

> Traffic from `10.10.10.0/24` to `10.20.0.5` must be permitted only on TCP/443.
> **Every other protocol and port to that host must be blocked.**

**Why it matters.** `10.20.0.5` is an internal server, and the config's own
intent is HTTPS-only. Anything else reaching it is a way in that nobody
designed: plaintext HTTP exposes session data, management protocols (Telnet,
SSH, SMB, database ports) expose credentials and the host itself, and non-TCP
protocols can be used to tunnel or probe. This rule states the intent that the
single `eq 443` line only implies.

**Applies to:** source `10.10.10.0/24`; destination `10.20.0.5`; every protocol
and port except TCP/443.

**This rule takes two queries.** Their union is the forbidden space, and the
rule holds only if *both* are empty. It cannot be written as one query — see the
`invertSearch` warning in §2.

```python
# Arm A — any non-TCP protocol reaching the server (UDP, ICMP, GRE, ...)
searchFilters(nodes="rtr-us5", filters="acl_in", action="permit",
              headers=HeaderConstraints(
                  srcIps="10.10.10.0/24", dstIps="10.20.0.5",
                  ipProtocols=["!tcp"]))

# Arm B — TCP reaching the server on any port other than 443
searchFilters(nodes="rtr-us5", filters="acl_in", action="permit",
              headers=HeaderConstraints(
                  srcIps="10.10.10.0/24", dstIps="10.20.0.5",
                  ipProtocols=["tcp"], dstPorts="0-442,444-65535"))
```

Both arms produce **one** finding (`PC-002`); if both fire, the evidence names
whichever arm is reported first and notes that both did.

Severity **high** — direct exposure of an internal server.

#### POL-3 — Only LAN addresses may enter the LAN interface → `PC-003`

> `acl_in` must not permit traffic whose source address is outside
> `10.10.10.0/24`.

**Why it matters.** `acl_in` is applied inbound on the LAN interface, so the
only legitimate source is the LAN itself. A packet arriving there claiming any
other source address is spoofed. Blocking it is standard ingress filtering
(BCP 38): it stops a compromised host on the LAN from forging its identity to
bypass the other rules or to launch reflected attacks from your address space.

**Applies to:** every source address outside `10.10.10.0/24`, any destination.

```python
searchFilters(nodes="rtr-us5", filters="acl_in", action="permit",
              headers=HeaderConstraints(srcIps="0.0.0.0/0 \\ 10.10.10.0/24"))
```

Severity **medium** — an enabler of other attacks rather than direct exposure on
its own.

### Requirements

These two catch the opposite failure: an ACL tightened until the network stops
working. A policy-compliance check that only ever looks for "too open" is half a
check, and "we locked it down and broke DNS for the whole site" is a real
outage, not a hypothetical.

#### POL-4 — DNS to the approved resolver must work → `PC-004`

> UDP/53 from `10.10.10.0/24` to `218.8.104.58` must be permitted.

**Why it matters.** If name resolution breaks, essentially everything breaks,
and the cause is hard to trace back to a firewall edit. This rule pins the
intent of the first ACL line so a later change cannot quietly remove it.

**Applies to:** source `10.10.10.0/24`; destination `218.8.104.58`; UDP/53.

```python
searchFilters(nodes="rtr-us5", filters="acl_in", action="deny",
              headers=HeaderConstraints(
                  srcIps="10.10.10.0/24", dstIps="218.8.104.58",
                  ipProtocols=["udp"], dstPorts="53"))
```

Severity **medium** — a loud, recoverable availability failure. See the severity
model above.

> Verified: `applications=["dns"]` resolves to UDP/53 here and behaves
> identically, but UDP/53 is written out explicitly so the rule cannot shift
> meaning if Batfish's application list changes.

#### POL-5 — HTTPS to the internal server must work → `PC-005`

> TCP/443 from `10.10.10.0/24` to `10.20.0.5` must be permitted.

**Why it matters.** Same reasoning as POL-4, for the service the network exists
to reach. Together with POL-2 it states the full intent for `10.20.0.5`: this
port and no other.

**Applies to:** source `10.10.10.0/24`; destination `10.20.0.5`; TCP/443.

```python
searchFilters(nodes="rtr-us5", filters="acl_in", action="deny",
              headers=HeaderConstraints(
                  srcIps="10.10.10.0/24", dstIps="10.20.0.5",
                  ipProtocols=["tcp"], dstPorts="443"))
```

Severity **medium** — a loud, recoverable availability failure, graded
consistently with POL-4.

---

## 4. Finding IDs

Agreed with Arsh, and requiring no change to `docs/finding-format.md`:

- `analysis/findings.py` maps **both** `policy_compliance` and `change_impact` to
  the `PC` prefix, exactly as the finding format specifies. Left unmanaged, both
  checks would number from 001 and emit duplicate `id` values — and the
  dashboard uses `id` as a key.
- **`policy_compliance` uses `PC-001`–`PC-099`. `change_impact` uses
  `PC-101`–`PC-199`.**
- **IDs are pinned to rules, not to run order.** POL-1 is always `PC-001`,
  POL-2 always `PC-002`, and so on. A finding's `id` therefore means the same
  thing on every run, which is what will later let the dashboard show what
  changed since the previous upload.
- **A rule's number is never reused.** If a rule is deleted, its number is
  retired rather than given to a new rule.

### Sentinel IDs — agreed fix

The split above fixes the numbered findings but not the sentinels.
`findings.no_issues_finding()` hardcodes `number=SENTINEL_NUMBER` (0) and takes
no `number` argument, so a clean `policy_compliance` run and a clean
`change_impact` run **both emit `PC-000`** — the same duplicate-key problem, one
level down. `error_finding()` is unaffected: it already accepts `number`.

**Agreed fix (Arsh):** give `no_issues_finding()` an optional
`number: int = SENTINEL_NUMBER` parameter, so `change_impact` can use `PC-100`
as its clean sentinel while `policy_compliance` keeps `PC-000`. Backward
compatible, and it does not touch the F-1 contract.

`findings.py` is shared code. The edit is made on `feat/us17-policy-check` and
**must be called out explicitly in the pull request description** so the
reviewer knows a shared file changed.

---

## 5. Verified behaviour against the fixtures

Measured against the live Batfish container, both fixtures loaded as snapshots.

| Rule | `rtr-us5-secure` | `rtr-us5-insecure` | Matched line (insecure) |
|---|---|---|---|
| POL-1 | 0 rows → `none` | 1 row → `found` | `permit ip any any` |
| POL-2 arm A | 0 rows → `none` | 1 row → `found` | `permit ip any any` (UDP flow) |
| POL-2 arm B | 0 rows → `none` | 1 row → `found` | `permit ip any any` (TCP/80 flow) |
| POL-3 | 0 rows → `none` | 1 row → `found` | `permit ip any any` |
| POL-4 | 0 rows → `none` | 0 rows → `none` | — |
| POL-5 | 0 rows → `none` | 0 rows → `none` | — |

This satisfies the definition of done: the insecure fixture produces `PC-`
findings with `status="found"`, and the secure fixture produces `status="none"`.
The `unparseable` fixture never reaches the check — `pipeline.py` stops at
`fileParseStatus` and returns `status="error"` for every registered check.

### Known limitation — the requirement rules are untested in the failing direction

POL-4 and POL-5 hold on *both* fixtures, so neither fixture demonstrates that
they can actually fail. A third fixture — an over-tightened ACL that blocks DNS
— would prove it. Agreed with Arsh that this is **not needed for US-17**, and
recorded here deliberately: it belongs in the evaluation report as an honest
limitation rather than going unmentioned.

### Note on duplicate findings

On the insecure fixture, one careless line (`permit ip any any`) violates three
rules at once, producing three findings. That is not redundancy in the policy: a
config could violate POL-2 alone by adding `permit tcp any host 10.20.0.5 eq 22`,
or POL-3 alone by permitting a foreign source. Each rule is an independent
statement of intent, and reporting all three is the honest answer to "which of
our policies does this config break?"

---

## 6. Decision log

| # | Decision | Outcome |
|---|---|---|
| 1 | ID scheme — `policy_compliance` 001–099, `change_impact` 101–199 | **Agreed** (Arsh) |
| 2 | Pin IDs to rules for stability across runs | **Agreed** (Arsh) |
| 3 | POL-2 scope — all protocols, not TCP only | **Agreed** (Arsh); POL-6 dropped as redundant |
| 4 | Severity values, and the model behind them (§3) | **Agreed** (Samika); POL-4/5 stay `medium` — availability is loud, exposure is silent |
| 5 | Optional `number` arg on `no_issues_finding()` (§4) | **Agreed** (Arsh); edit lands on the feature branch, flagged in the PR |

### Related decision — change impact is not a check

Arsh has decided that **change impact will be a separate entry point, not a
fifth entry in the `CHECKS` registry.** `differentialReachability` requires a
reference snapshot supplied to `answer()`, and the registry contract is
`run(bf: Session)` with exactly one snapshot loaded, so it does not fit the
pattern. Arsh is taking the detailed shape to the team.

Recorded here only because §4 reserves `PC-101`–`PC-199` for change impact —
that reservation still stands, and the ID scheme is unaffected by where the code
lives. **Do not attempt to register change impact in `CHECKS`.**

**Dropped:** POL-6 ("DNS may only go to the approved resolver"). Its flow space
is fully covered once POL-2 spans all protocols — POL-1 catches DNS to an
unapproved destination, and POL-2 arm A catches DNS to `10.20.0.5`. Verified:
`udp/53 → 10.20.0.5` returns 1 row on the insecure fixture under POL-2 arm A.

---

## 7. Sign-off

| Member | Role in this decision | Agreed |
|---|---|---|
| Shubham | Author; owns the check | ✅ |
| Arsh | Registry, pipeline, `findings.py` impact | ✅ rules, IDs, and the §4 `findings.py` change |
| Samika | Severity values are hers | ✅ |
| Ankeet | Consumes findings in the AI layer | ⬜ |
