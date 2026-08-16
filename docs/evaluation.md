# Evaluation — does Netwise find the flaws it is meant to find?

**Measured:** 10 August 2026. **Re-run unchanged on 13 August** against `main`
at `94c1f7e` (304 tests passing), after the Sprint 3 queue and the converter
work landed. Every detection result below reproduced identically; only the
client-export section in "what this does not show" needed correcting, and it
had drifted in the direction of *understating* what the converter can now do.
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

| Fixture | Checked clean | Could not check | False positives |
|---|---|---|---|
| `rtr-us5-secure` | `AC-000`, `PC-000` | **`RT-050`** | **0** |
| `routing-secure` | `RT-000` | **`AC-001`, `PC-050`** | **0** |

> **This table used to omit the "could not check" column**, listing only the
> `none` findings. Found by @shubhamkataria2005 (#106), reading the document
> that describes his own check.
>
> **"0 false positives" was and is correct** — an `error` is not a false
> positive, and nothing here contradicts the headline. What was wrong is that
> the *Result* column understated what a user actually sees. A control fixture
> was shown producing a clean result when what it produces is one clean result
> and two checks that could not run.
>
> That is **F-4 being flattened inside the document whose subject is whether
> this tool tells the truth.** A reader saw full clean coverage; the tool's own
> output says two thirds of it was never exercised.

**No fixture in this repository exercises all three checks cleanly at once**,
and that bounds what these controls demonstrate. On `rtr-us5-secure`, `routing`
cannot run because `ROUTES` names `rtr-hq`/`rtr-branch`. On `routing-secure`,
`access_control` and `policy_compliance` cannot run because they name
`rtr-us5`.

So the controls show that **each check is quiet on a clean config it can
read** — not that the system as a whole is quiet on a clean config. That is a
weaker statement than the table implied, and it is the same root cause as #87:
policy hardcoded to fixture device names, surfacing in the evaluation rather
than in the product.

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
| Controls exercising **all three** checks at once | **0 of 2** |

The last row is there so a reader who takes only this table away is not left
with the impression the controls table used to give. Both controls also
produce "could not check" findings, because no fixture in the repository
names devices all three checks can read.

---

## What this evaluation does not show

Stated as prominently as the results, because a reader who takes only the table
away has the wrong impression.

1. **It does not show Netwise finds unknown flaws.** Every fault here was
   planted by us and known to the check author. This measures design intent, not
   discovery.

2. **The sample is tiny.** Five flaws across three configurations. No statistical
   claim is possible, and none is made.

3. **No real configuration has been analysed *by the pipeline*.** Every result
   here is on configs we authored.

   This is narrower than it was on 10 August, and the update matters. The client
   provided an anonymised export on 10 August and it **has** been examined —
   structurally, with `tools/pfsense_shape.py`, which reports element names and
   counts and never a value. What that established (#78):

   - **zero of seven rules are marked `quick`**, so PF Sense's last-match-wins
     applies to his whole rule set
   - his rules span four interface values across three interfaces
   - 1,998 elements against our fixture's 54, carrying `nat`, `openvpn`,
     `ipsec`, `aliases`, `dhcpd` and `shaper`

   **Two of those blockers are now gone (#104, 13 August), and this paragraph
   used to say otherwise.** It said our first-match-wins model "disagrees
   wherever two overlapping rules differ" and that the converter "refuses it
   earlier still" on multiple interfaces. Both were true when written and are
   not now:

   - **multi-interface rule sets are supported** — each interface gets its own
     ACL, checked independently
   - **rule order is modelled rather than refused.** With zero `quick` rules,
     "stop immediately" never fires, so PF Sense's decision for any flow is the
     action of the *last* matching rule — which is by construction the *first*
     match of the reversed list under first-match-wins. Same decision, every
     flow. Verified against Batfish on the exact pair `CLAUDE.md` §7 documents
     as the measured failure:

     ```
     emitted:  permit tcp any host 10.20.0.5 eq 443
               deny   tcp any host 10.20.0.5
     HTTPS -> PERMIT   (PF Sense permits: it is the last match)
     HTTP  -> DENY
     ```

   His export still refuses, and the refusal now names everything remaining in
   one message, each attributed to its real cause rather than one blanket
   reason:

   ```
   REFUSED: filter rules apply to interface(s) that cannot be modelled:
   ['wan'] have no static address configured (DHCP or unconfigured) -- a
   Cisco ACL needs an address to bind rules to; ['WireGuard', 'openvpn'] are
   not declared under <interfaces> at all -- most likely VPN/tunnel policy
   (e.g. OpenVPN, WireGuard), which this module does not parse and is out of
   scope, not LAN filtering
   ```

   What is left is a **DHCP WAN carrying rules** and **rules naming two VPN
   interfaces absent from `<interfaces>`**, plus the NAT decision and the
   field-omission questions still with him (#80). Neither of the first two was
   on #78's original item list, which was written before we knew which
   interfaces carried rules. The message used to call both "no static address
   configured", true only of the first, split once that was found to be
   actively misleading about the second rather than merely imprecise.

   **What the converter did not do is still worth as much as what it did not
   manage:** it has never produced a plausible, wrong ACL. It stops and names
   the construct it cannot handle, and it did that on the first real firewall
   it ever saw.

4. **The device-scoping errors are correct, but they are still gaps — and the
   gap is larger than this document originally implied.** Several runs report
   *"N assertions could not be checked against this config"*. That is honest —
   those policy statements name devices not in the snapshot — but it means the
   checks are not covering those configs.

   **Measured after this evaluation was first written.** Take `rtr-us5-messy`,
   rename the device, change nothing else:

   ```
   our device name      6 findings   access_control + policy_compliance
   a stranger's name    3 findings   access_control only
   ```

   **One rename removes half the detection**, because every policy assertion in
   the product is hardcoded to our fixtures and there is no way for a user to
   supply their own. What survives is the two analyses that need no policy —
   dead rules and undefined references. So the results above are not merely
   *measured on our configs*; several of them are **only obtainable** on our
   configs. Filed as #87, and the ordering is in
   `docs/design/product-roadmap.md`.

5. **Neither control exercises all three checks.** On `rtr-us5-secure`,
   `routing` cannot run because `ROUTES` names `rtr-hq`/`rtr-branch`. On
   `routing-secure`, `access_control` and `policy_compliance` cannot run
   because they name `rtr-us5`.

   **No fixture in this repository exercises all three checks cleanly at
   once.** So "0 false positives on clean configs" means *each check is quiet
   on a clean config it can read* — not that the system as a whole is quiet on
   a clean config. Those are different claims and only the weaker one is
   demonstrated.

   Raised by @shubhamkataria2005 (#106). It is stated here as well as in the
   controls section at his request, and he is right that this is its proper
   home: a reader who jumps straight to this section to find the limitations
   would otherwise miss it entirely.

   Same root cause as #87 — policy hardcoded to fixture device names —
   surfacing in the evaluation rather than in the product. A fixture that all
   three could read would need a policy that names its devices, which is the
   thing we cannot express yet.

6. **The explanation layer is not evaluated here.** Whether the plain-English
   text is *good* is a separate question from whether the findings are *correct*.
   That needs human judgement, and it should be its own evaluation.

7. **The explanation *wording* is still unevaluated.** See the section below for
   the question feature, which now is measured.

**The honest one-line summary:** *the checks reliably detect the faults they were
built to detect and do not fire on clean configurations — which is a necessary
result, not a sufficient one.*

---

## Part 2 — the natural-language question feature (US-11)

Measured 10 August, 20 questions across three fixtures. Four outcomes, and only
one of them is dangerous:

| Outcome | Count | |
|---|---|---|
| **Answered, correct** | 11 | 55% |
| **Refused, correctly** | 9 | 45% |
| **Refused, but should have answered** | 0 | 0% |
| **Answered, and wrong** | **0** | **0%** |

The last row is the one that matters. A tool that refuses too often is annoying;
a tool that answers confidently and wrongly about a firewall is the thing this
whole project is built to avoid.

The 45% refusal rate is **not** a failure figure. Nine of those questions genuinely
cannot be mapped — *"what is the weather today"*, a source given as an IP rather
than a device, a device not in the snapshot — and three are questions a real user
would plausibly type that we simply do not support yet:

```
"is port 443 open to the internal server"   -> refused
"which rule blocks DNS"                     -> refused
"is my firewall secure"                     -> refused
```

Each refusal names what it could not do rather than failing vaguely. That is the
designed behaviour, not a gap in it — but the three above are the best available
list of what to build next.

### This evaluation found a real bug — since fixed

Worth recording, because it is the strongest argument for having done it at all.

```
can rtr-hq reach 10.20.20.5      ->  Yes.
can rtr-hq reach 10.20.20.0/24   ->  No.   <-- same network, same fixture
```

Asking about a **subnet** reports unreachable while every **host** in it reports
reachable. Batfish resolves a CIDR to the network address, which is not a live
host, so the trace ends in `EXITS_NETWORK` — which we deliberately treat as
failure elsewhere for good reasons.

**Nothing hallucinated and no guard failed.** The query was well-formed, really
ran, was answered truthfully, and `question_understood` echoed exactly what was
asked. It was simply not the question the user meant — which is precisely the
failure `docs/design/query-grounding-problem.md` predicted before this code
existed. Filed as **#70**, fixed by @patelankeet2 in **#73**, and re-measured
here rather than assumed:

```
can rtr-hq reach 10.20.20.5      ->  Yes. Traffic from rtr-hq reaches 10.20.20.5.
can rtr-hq reach 10.20.20.0/24   ->  Yes. Traffic from rtr-hq reaches a host in
                                     10.20.20.0/24 (checked 10.20.20.1).
```

**The top-line counts are unchanged — 11 / 9 / 0 / 0 — but one of them changed
meaning.** Before the fix, that case scored answered-correct only because the
tool faithfully reported what Batfish said; judged by what a *user* meant it was
wrong, and this document recorded both readings rather than the flattering one.
After the fix the two readings agree, and the substitution is disclosed in both
the restated question and the answer text.

That is the sequence worth keeping: an evaluation found a defect in shipped
code, the defect was fixed the same day, and the evaluation was re-run rather
than edited to match.
