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

**On a snapshot that does not contain `rtr-us5`, no rule can be evaluated.**
The check reports that once, as `PC-050`, rather than once per rule — it used
to emit five "could not check" cards, which is correct under F-4 and unusable
in volume. It is reported, never skipped: a config nothing was checked against
must never come back clean. Naming devices in the policy at all is the deeper
problem, tracked as issue #29; this makes the current design usable, it does
not fix it.

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

**Widen the destination and a success row appears — do not be fooled by it.**
This is the half the paragraph above used to omit, and it is the half that
makes a live demo go wrong. Same query, same fixture, `dstIps` opened up:

```
reachability(actions="success", 10.10.10.0/24 -> 0.0.0.0/0)         ->  1 row
    Flow: start=rtr-us5 [10.10.10.0->10.10.10.0 ICMP (type=8, code=0)]
```

That "reachable" flow is the router reaching its own directly-connected LAN.
Batfish returns **one example flow per disposition**, so over a wide
headerspace the example it picks can be trivially local and say nothing about
the rule under test.

So the accurate statement is not *"reachability returns nothing"*. It is that
reachability answers a question about **paths**: the flow we care about is
filed under `failure` for the wrong reason, while a flow we do not care about
can surface as `success`. **Neither bucket means what a policy check needs it
to mean.**

`searchFilters` reasons at the filter level and needs no routing, so it is
correct on these fixtures and on any config where policy intent lives in ACLs
— and it cannot be fooled in either direction.

> Found by @ARSH871-bot re-running this section rather than reading it, after
> it was quoted in a team message. The measurement here was right and the
> headers were named; `policy_compliance`'s module docstring stated the same
> result *without* naming them, so anyone trying the obvious wide query would
> see a success row and conclude the claim was false. Fixed in both places.
> A measurement is only reproducible if the parameters travel with it.

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

- **`policy_compliance` owns the `PC-` prefix outright.** It used to share it
  with `change_impact`, which is why the bands below were split; amendment
  **A-2** in `docs/finding-format.md` gave `change_impact` its own `CH-`
  prefix, so the two can no longer collide with each other at all.
- The banding is kept anyway, because it does useful work *within* this check:
  it keeps a rule's violation, its partial-check error, and the check-level
  cards from ever landing on the same number.
- **IDs are pinned to rules, not to run order.** POL-1 is always `PC-001`,
  POL-2 always `PC-002`, and so on. A finding's `id` therefore means the same
  thing on every run, which is what will later let the dashboard show what
  changed since the previous upload.
- **A rule's number is never reused.** If a rule is deleted, its number is
  retired rather than given to a new rule.

### One rule, two findings — the error band

A rule with several query arms can have one arm **prove a violation** while
another **fails to run**. Both facts are true, and both are reported (see §3,
POL-2, and issue #22). They cannot share an `id` — `duplicate_id_findings()` in
the pipeline would correctly flag that as a broken contract — so every rule owns
two slots:

| | id | Meaning |
|---|---|---|
| Violation | `PC-00n` | rule *n* is broken by this config |
| Check error | `PC-0(n+50)` | rule *n* could not be fully evaluated |

Two check-level slots sit outside the per-rule numbering, and they mirror each
other — `PC-000` is "the whole check found nothing", `PC-050` is "the whole
check could not apply":

| id | Meaning |
|---|---|
| `PC-000` | every applicable rule ran and held |
| `PC-050` | the rules do not apply to this snapshot, or we could not tell |

`PC-050` is `SENTINEL_NUMBER + ERROR_NUMBER_OFFSET`. Rules are numbered from 1,
so nothing else can ever land there.

`ERROR_NUMBER_OFFSET = 50` in `analysis/checks/policy_compliance.py`. So POL-2
violated *and* partly unchecked yields **`PC-002` and `PC-052`**.

This keeps the pinning promise intact in both directions: `PC-002` always means
"POL-2 is violated" and `PC-052` always means "POL-2 could not be fully
checked", on every run. The offset caps the policy at 49 rules, which is far
more than the five we have, and a test asserts the two bands cannot overlap and
stay clear of `PC-999`, which `pipeline.duplicate_id_findings()` uses for its
own complaint.

### Sentinel IDs — agreed fix

The split above fixes the numbered findings but not the sentinels.
`findings.no_issues_finding()` hardcodes `number=SENTINEL_NUMBER` (0) and takes
no `number` argument, so a clean `policy_compliance` run and a clean
`change_impact` run **both emit `PC-000`** — the same duplicate-key problem, one
level down. `error_finding()` is unaffected: it already accepts `number`.

**Agreed fix (Arsh):** give `no_issues_finding()` an optional
`number: int = SENTINEL_NUMBER` parameter, so `change_impact` could use
`PC-100` as its clean sentinel while `policy_compliance` kept `PC-000`.
Backward compatible, and it did not touch the F-1 contract.

**Superseded by A-2.** `change_impact` now owns `CH-`, so it uses `CH-000` for
its own clean sentinel and the reservation of `PC-100`–`PC-199` is retired.
The `number` parameter stays — `policy_compliance` uses it for `PC-050`.

`findings.py` is shared code. The edit is made on `feat/us17-policy-check` and
**must be called out explicitly in the pull request description** so the
reviewer knows a shared file changed.

---

## 5. Verified behaviour against the fixtures

Measured against the live Batfish container, each fixture loaded as a snapshot.

| Rule | `rtr-us5-secure` | `rtr-us5-insecure` | `rtr-us5-messy` |
|---|---|---|---|
| POL-1 | `none` | **`found`** | `none` |
| POL-2 arm A | `none` | **`found`** | `none` |
| POL-2 arm B | `none` | **`found`** | `none` |
| POL-3 | `none` | **`found`** | `none` |
| POL-4 | `none` | `none` | **`found`** |
| POL-5 | `none` | `none` | **`found`** |

The two insecure columns fail in *opposite directions*, which is the point of
having both kinds of rule:

- `rtr-us5-insecure` is too **open** — `permit ip any any` — so the three
  prohibitions fire and the two requirements are satisfied.
- `rtr-us5-messy` is too **closed** — a blanket `deny ip 10.10.10.0 0.0.0.255
  any` at the top of the ACL — so the two requirements fire and the three
  prohibitions correctly stay quiet.

Neither config produces a false positive in the other direction.

This satisfies the definition of done: an insecure fixture produces `PC-`
findings with `status="found"`, and the secure fixture produces `status="none"`.
The `unparseable` fixture never reaches the check — `pipeline.py` stops at
`fileParseStatus` and returns `status="error"` for every registered check.

### Closed — the requirement rules are now proven to fail when they should

This section previously recorded a limitation: POL-4 and POL-5 held on both
fixtures, so nothing demonstrated they could actually fire. An assertion never
observed to fail is weak evidence that it works.

It needed no new fixture. `rtr-us5-messy` — added for the access-control
dead-rule analyses — puts a blanket `deny ip 10.10.10.0 0.0.0.255 any` at the
top of `acl_in`, which is exactly the over-tightened config the requirement
rules exist to catch. Measured:

```
PC-004  found  DNS to the approved resolver is blocked, so name lookups fail
        Flow 10.10.10.0:49152->218.8.104.58:53 UDP is denied but policy
        requires it. Decided by: deny   ip 10.10.10.0 0.0.0.255 any

PC-005  found  HTTPS to the internal server is blocked, so the service is unreachable
        Flow 10.10.10.0:49152->10.20.0.5:443 TCP (SYN) is denied but policy
        requires it. Decided by: deny   ip 10.10.10.0 0.0.0.255 any
```

Both name the exact line responsible. The three prohibitions stay `none` on the
same config, so tightening the ACL produces no false "too open" report.

That closes the last open question about this check: it is now demonstrated to
detect a config that is too open *and* one that is too closed, on real
configs rather than by argument.

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

Recorded here because §4 used to reserve `PC-101`–`PC-199` for change impact.
Amendment **A-2** replaced that reservation with a prefix of its own, `CH-`, so
`PC-` is now `policy_compliance`'s alone. The ID scheme is unaffected by where
the change-impact code lives. **Do not attempt to register change impact in
`CHECKS`.**

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
| Samika | Severity values are his | ✅ |
| Ankeet | Consumes findings in the AI layer | ⬜ |
