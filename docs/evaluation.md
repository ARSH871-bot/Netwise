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

   **UPDATE, 23 August.** "His export still refuses" above is no longer
   accurate as a whole-file statement, and is left as the historical record
   rather than edited. The two interface-modelling cases stopped refusing
   everything: rules naming an unmodellable interface are now skipped and
   named individually, and every other interface in the same file converts.
   Nothing here is guessed at any point -- the unmodellable rules are still
   refused, one by one, just no longer at the cost of interfaces that were
   never the problem. Verified live on a synthetic client-shaped file:
   two good interfaces converted and parsed cleanly against real Batfish
   with zero problems, alongside a `skipped` list naming the DHCP and VPN
   interfaces excluded. The NAT decision and #80's field-omission question
   are unaffected and remain open.

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

   > **UPDATE, 12 September 2026.** #87 is closed — `access_control` (#316)
   > and `routing` (#319) now read a user-supplied policy, so "there is no way
   > for a user to supply their own" is no longer true.
   >
   > **The figures above are NOT reworded**, because `CONTRIBUTING.md` §5c is
   > explicit that a measurement is re-run rather than edited. They remain a
   > correct record of what was measured when they were taken. **A re-run of
   > this evaluation against the new behaviour is owed**, and until it happens
   > the honest reading of the block above is *this is what the product did
   > before #316 and #319*, not *this is what it does*.

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

---

## Part 3, is the explanation text any good? (#90)

Part 1 measures whether the findings are *correct*. It does not, and per its
own item 6 above cannot, measure whether the plain-English text explaining
them is *good*. Those are different questions. We have structural evidence
the text is not wrong (#52, `ai/explain.py`'s two safety nets), and no
evidence yet that it is useful, and the person who wrote a check is the worst
judge of whether its own explanation is clear, because the finding already
makes sense to them before they read a word of the prose.

**This section is a first round, not a finished evaluation.** One rating
below is filled in (mine). The other three are blank on purpose, per the
issue's acceptance criteria: rate independently, before discussing, and
record disagreement rather than average it away, since a finding two people
read differently is the interesting result. @ARSH871-bot @shubhamkataria2005
@SamikaPerera, your ratings and reasoning go in the table under your own
name, added by you rather than relayed by anyone else, then we discuss.

### Method

Not changing the prompt or `ai/Modelfile`, measuring first, per the issue's
own scope note; a change made before the measurement has nothing to be judged
against.

Five real findings, generated from the pipeline against real fixtures, not
invented for this exercise. Spans three checks, both a `found` and an
`error`, and since I wrote `routing` and the AI layer, not
`access_control` or `policy_compliance`, four of the five are explanations
of a check I did not write, so I am not grading my own homework on this
round.

| id | check | status | wrote the check? |
|---|---|---|---|
| RT-050 | routing | error | Ankeet |
| AC-001 | access_control | found | Arsh |
| PC-001 | policy_compliance | found | Shubham |
| AC-002 | access_control | found | Arsh |
| PC-005 | policy_compliance | found | Shubham |

### The five findings, exactly as generated

Regenerate with `python -m ai.explain` against these fixtures, or the snippet
below, if you want to confirm these are still current rather than trusting
the paste, `explain()` retries once against the model, so wording can vary
slightly between runs even for the same finding.

**RT-050** (`tests/fixtures/rtr-us5-insecure`, status=`error`)
```
summary: 2 route assertion(s) could not be checked against this config
evidence.detail: They are written about rtr-branch, rtr-hq, which are not
                  in this snapshot. Nothing is claimed about them either way.
explanation_source: fallback
explanation: This check could not be completed, so nothing is confirmed
             about the network either way. The underlying reason: They are
             written about rtr-branch, rtr-hq, which are not in this
             snapshot. Nothing is claimed about them either way.
```

**AC-001** (`tests/fixtures/rtr-us5-insecure`, status=`found`)
```
summary: Unencrypted web traffic reaches the internal server
evidence.detail: Expected DENY but got PERMIT, decided by: permit ip any any
explanation_source: model
explanation: The device's rule set currently allows all traffic through
             with no restriction, which is what let unencrypted web traffic
             reach the internal server.
```

**PC-001** (`tests/fixtures/rtr-us5-insecure`, status=`found`)
```
summary: The internal network can reach servers it should not
evidence.detail: Flow start=rtr-us5 [10.10.10.0:49152->8.8.8.8:80 TCP (SYN)]
                  is permitted but policy forbids it. Decided by:
                  permit ip any any
explanation_source: model
explanation: The device rtr-us5 has a rule that allows all traffic to pass
             through with no restriction, which is what let the internal
             network reach servers it should not. The policy currently
             permits this unauthorized access.
```

**AC-002** (`tests/fixtures/rtr-us5-messy`, status=`found`), a dead-rule
finding, the reasoning shape `_compute_dead_rule_outcome()` exists for (see
`ai/explain.py`'s module docstring for the real bug it once caught here).
```
summary: ACL rule never takes effect in acl_in
evidence.detail: Unreachable line: permit udp 10.10.10.0 0.0.0.255 host
                  218.8.104.58 eq domain (action PERMIT). Blocked by:
                  deny ip 10.10.10.0 0.0.0.255 any. Reason: BLOCKING_LINES
explanation_source: model
explanation: The ACL rule on the unreachable line in the rtr-us5's acl_in
             configuration never takes effect, because it is overridden by
             a blocking rule that evaluates first. As a result, traffic
             matching the unreachable line's pattern is actually denied,
             rather than allowed. The blocking rule, which denies all
             traffic to the specified IP range, supersedes the action of
             the unreachable line, making its own permit action irrelevant.
```

**PC-005** (`tests/fixtures/rtr-us5-messy`, status=`found`)
```
summary: HTTPS to the internal server is blocked, so the service is
         unreachable
evidence.detail: Flow start=rtr-us5 [10.10.10.0:49152->10.20.0.5:443 TCP
                  (SYN)] is denied but policy requires it. Decided by:
                  deny ip 10.10.10.0 0.0.0.255 any
explanation_source: model
explanation: The internal server can be reached over HTTPS, but the
             device's policy currently blocks this traffic.

             This check found that a specific rule on the rtr-us5 device
             denies HTTPS traffic to the internal server, even though the
             service is required. The evidence shows that the reason for
             this denial is due to a specific policy statement that
             requires blocking of HTTPS traffic.
```

### Ratings

Scale: 1 (poor) to 5 (excellent). **Accuracy**: does the text claim only what
the evidence actually shows. **Usefulness**: would this sentence, alone, tell
someone who has never read `evidence.detail` what is actually wrong.

| id | rater | accuracy | usefulness | notes |
|---|---|---|---|---|
| RT-050 | Ankeet | 5 | 4 | Accurate, and correctly refuses to guess at rtr-branch/rtr-hq. Slightly repeats the raw evidence text verbatim in the second sentence rather than rephrasing it, reads a little mechanical for a fallback but that is exactly what it is, not model prose, and it says so nowhere near confidently enough to mislead. |
| AC-001 | Ankeet | 5 | 4 | Correct and specific about the rule (`permit ip any any`) and the consequence. Slightly generic phrasing, "allows all traffic through with no restriction" is the evidence text lightly reworded rather than genuinely explained in different words. |
| PC-001 | Ankeet | 4 | 3 | Accurate, but the second sentence, "the policy currently permits this unauthorized access", is a little confusing on a first read: it sounds like it could mean the *written* policy permits it, when the actual finding is that the *live config* violates the policy. Worth someone else's eyes on whether this reads clearly cold. |
| AC-002 | Ankeet | 5 | 5 | This is the one I most wanted rated by someone who did not write `_compute_dead_rule_outcome()`. Correctly states the shadowing direction (permit shadowed by an earlier deny, so the line is denied not permitted) and explains why in one pass, matches the exact computed fact fed to the model. |
| PC-005 | Ankeet | 3 | 2 | **The one I'd flag as a concrete problem, not just a style note.** First sentence: "The internal server can be reached over HTTPS, but the device's policy currently blocks this traffic" reads as self-contradictory on a first pass, "can be reached" then "blocks this traffic" in the same breath, before the reader has enough context to know one is describing the requirement and the other the actual (wrong) behaviour. Second paragraph's last sentence, "requires blocking of HTTPS traffic", inverts it further, the policy requires the opposite, that HTTPS be *allowed*. Accurate in substance (nothing invented, matches evidence.detail), but the phrasing risks a reader walking away with the causality backwards. |
| RT-050 | @ARSH871-bot | 5 | 4 | Agree with Ankeet. The thing worth naming explicitly is that this is the *only* one of the five where the text is deterministic, and it is also the only one where nothing can be inverted, because it does not attempt a causal sentence at all. Mechanical reads as a cost here; it is also the reason it cannot be wrong. |
| AC-001 | @ARSH871-bot | 5 | 4 | Agree. Rating my own check's output, so treat this as the least independent row I have; Shubham's and Samika's numbers on this one are worth more than mine. |
| PC-001 | @ARSH871-bot | 2 | 3 | **Lower than Ankeet's 4, and for a reason that connects to PC-005.** "The policy currently permits this unauthorized access" is not merely confusing, it states the opposite of the finding. The finding is that the live config permits traffic the policy forbids. A reader who takes that sentence at face value concludes the policy is at fault, and that the config is doing what it was told. Same inversion as PC-005, one notch less blatant. |
| AC-002 | @ARSH871-bot | 5 | 5 | Agree, and this is the one Ankeet most wanted an outside reading of — but `access_control` is mine, so I am the wrong person to give it. Correct on the shadowing direction, which is the easy thing to get backwards. **@shubhamkataria2005 / @SamikaPerera, this row needs one of you more than the others do.** |
| PC-005 | @ARSH871-bot | 1 | 2 | **I think this is a grounding failure, not a phrasing risk, and that the rating should be 1.** See the disagreement below — the short version is that "a specific policy statement that requires blocking of HTTPS traffic" is not an awkward rendering of the evidence, it contradicts it. |
| RT-050 | @shubhamkataria2005 | 5 | 4 | Nothing here can be wrong, and that is not faint praise: it is the only one of the five that makes no causal claim, so there is no relationship between two facts for it to get backwards. Accuracy is 5 by construction. Usefulness 4 because it quotes `evidence.detail` verbatim rather than translating it — a reader still has to know what a "route assertion" is. The fallback's job is to be safe, and it is; making it plainer is a separate piece of work from making it honest. |
| AC-001 | @shubhamkataria2005 | 5 | 4 | Exact. "Allows all traffic through with no restriction" is the Modelfile's own prescribed rendering of `permit ip any any`, so calling it lightly reworded is a little unfair — it is following an instruction, not paraphrasing lazily. The causality runs the right way: the blanket permit is the cause, the traffic reaching the server is the effect. Usefulness 4 rather than 5 only because it stops at what happened and says nothing about what it means, which rule 2 requires of it. |
| PC-001 | @shubhamkataria2005 | 2 | 2 | **With @ARSH871-bot at 2, not @patelankeet2 at 4, and this is my own check's output.** First sentence is correct and good. The last one — "The policy currently permits this unauthorized access" — is not confusing, it is the negation of `evidence.detail`, which says the flow "is permitted but policy **forbids** it". Usefulness 2 rather than 3 because the error is directional: a reader concludes the *policy* is at fault and the config is doing as told, so the action it invites is editing the policy, which is the one thing that is already correct. |
| AC-002 | @shubhamkataria2005 | 5 | 4 | Taking this row as the outside reader @ARSH871-bot asked for, since `access_control` is his and `_compute_dead_rule_outcome()` is @patelankeet2's. The shadowing direction is right, and it is the thing most easily got backwards: a permit that never runs means the traffic is **denied**, and the text says so plainly. It also leaves `BLOCKING_LINES` alone rather than treating it as a rule name, which the prompt specifically warns about. Usefulness 4 — the third sentence largely restates the second, so it reads longer than it needs to. |
| PC-005 | @shubhamkataria2005 | 1 | 2 | **Agreeing with @ARSH871-bot's 1 on accuracy.** Two of three sentences contradict the finding's own fields: "can be reached over HTTPS" against a summary that says "unreachable", and "a policy statement that requires blocking" against a detail that says "policy **requires** it". The middle sentence — "denies HTTPS traffic ... even though the service is required" — is correct, which is the only reason usefulness is 2 rather than 1: a careful reader can recover the truth from one clause out of three. This is my check's evidence format causing it, see #145. |
| RT-050 | @SamikaPerera | 5 | 4 | Agree. Mechanical, and it is the only one of the five with nothing to invert because it makes no causal claim at all. Reads as a cost until you notice that is exactly why it cannot be wrong. |
| AC-001 | @SamikaPerera | 5 | 4 | Agree. Names the rule and the consequence in one sentence, and a reader who has never seen `evidence.detail` still learns what is wrong. Usefulness 4 because the phrasing is close to the evidence rather than genuinely re-explained. |
| PC-001 | @SamikaPerera | 2 | 2 | **The explanation's final sentence attributes the violation to the policy rather than to the rule that is ignoring it — the same inversion pattern @shubhamkataria2005 found.** "The policy currently permits this unauthorized access" says the opposite of the evidence, which is that the config permits what the policy forbids. Reading it cold, as the outside reader asked for: the first sentence is good enough that I nearly accepted the second, which is the part worth recording — the quiet inversion is the one that survives review. Usefulness 2 because it points the reader at the policy, the one thing here that is already correct. |
| AC-002 | @SamikaPerera | 5 | 4 | Taken as the second outside reader, since @ARSH871-bot wrote the check. The shadowing direction is right and stated plainly — a permit that never runs means the traffic is denied — and `BLOCKING_LINES` is left alone rather than rendered as a rule name. 4 not 5 because the third sentence restates the second. |
| PC-005 | @SamikaPerera | 1 | 2 | **Same inversion as PC-001, and here it is not quiet: the final sentence attributes the denial to a policy that "requires blocking of HTTPS traffic", when the evidence says the policy requires that traffic through.** A reader who trusts it closes the card as working-as-intended, which is the whole finding lost. Accuracy 1 with @ARSH871-bot and @shubhamkataria2005 rather than 3: a false claim about what the policy says is a false claim, not a phrasing risk. Usefulness 2 only because the first clause does correctly say something is blocked. |

### Disagreements

Record here rather than averaging the numbers away: which finding, whose
ratings differed and by how much, and what each rater actually meant by their
number, since two people can give the same score for different reasons just as
easily as different scores for the same finding.

#### PC-005 — accuracy, Ankeet 3 against Arsh 1

Not a difference of taste about phrasing. We disagree on whether the text is
**accurate**, which is the one axis where a disagreement has consequences.

Ankeet's note says *"Accurate in substance (nothing invented, matches
evidence.detail)"*, and grades the problem as a readability risk. Set the two
side by side:

```
evidence.detail  ... is denied but policy requires it.
explanation      ... the reason for this denial is due to a specific policy
                     statement that requires blocking of HTTPS traffic.
```

The evidence says the policy requires the traffic **through**. The explanation
says the policy requires it **blocked**. That is not the evidence lightly
reworded, it is the evidence reversed. Nothing was invented in the sense of a
new device or a new rule, but a false claim about what the policy says is
still a false claim, and it is the specific claim the finding exists to make.

What it costs the reader is the whole finding. `PC-005` means *the config
contradicts the policy*. The explanation reads as *the config is enforcing the
policy*. A reader who trusts it closes the card as working-as-intended. Under
CLAUDE.md constraint 2 that is the failure the grounding rules exist to
prevent, arriving through rephrasing rather than through invention — which is
worth noticing on its own, because every guard we built watches for invention.

Hence accuracy 1. Usefulness 2 rather than 1 because the first clause does
correctly say something is blocked.

#### Is it general or specific — the question Ankeet left for a second rater

**General to `policy_compliance`, and the mechanism is not what I first
guessed.** My first hypothesis was that a two-clause "X but Y" detail is what
the model collapses. Checked across every `found` finding in both fixtures,
and that is wrong: `AC-001`'s detail is also two-clause and its explanation is
one of the two rated 5.

The difference is an **unresolved pronoun**, not clause count:

```
access_control     Expected PERMIT but got DENY, decided by: ...
policy_compliance  ... is denied but policy requires it.
```

`access_control` names both actions outright, so there is nothing to resolve.
`policy_compliance` compresses the required action into "it", whose antecedent
is the flow being *permitted* — several words back, and never stated as an
action at all. The model resolved "it" as the nearest available noun phrase,
the denial. `PC-001` shows the same slip in the mirror direction.

**So the fix may not belong in `ai/Modelfile`.** Making
`policy_compliance`'s detail name the required action the way `access_control`
already does — *"is denied but policy requires it to be PERMITTED"* — removes
the ambiguity at the source, for every consumer, instead of asking the model to
resolve a reference correctly every time. A prompt change asks the model to be
careful; this makes the sentence unambiguous, and the check whose output it is
can no longer be misread by a human reader either.

**Tracked as [#145](https://github.com/ARSH871-bot/Netwise/issues/145)**, which
@patelankeet2 had already filed the day before this rating was written. Not
fixed here — this exercise is measurement only, and @shubhamkataria2005 owns
that check and should have the call. Two independent raters is also still a
small sample: `PC-001` and `PC-005` are two findings from one check.

**#145 carries a constraint this section did not, and it matters:** do not
apply the fix until this round of ratings is complete. Changing
`policy_compliance`'s evidence format now would mean the ratings above refer
to text that no longer exists, which destroys the comparison they were made
for. An improvement identified by a measurement can still invalidate it.

#### PC-001 — accuracy, Ankeet 4 against Arsh 2 and Shubham 2

The same disagreement as PC-005, one notch quieter, and worth recording
separately because the quieter version is the one that survives review.

```
evidence.detail  ... is permitted but policy forbids it.
explanation      The policy currently permits this unauthorized access.
```

The evidence says the policy **forbids** the flow and the config permits it
anyway. The explanation says the policy **permits** it. Ankeet's note calls
this *"a little confusing on a first read"* and flags that it *"sounds like it
could mean the written policy permits it"*. It does not merely sound like
that; it is what the sentence says.

**Two of three raters put this at 2, and the check's own author is one of
them.** Recorded because `PC-001`'s first sentence is genuinely good — the
blanket permit named as the cause, the consequence stated plainly — so the
finding reads as mostly right, which is what makes the last sentence easy to
wave through. `PC-005` announces itself by being self-contradictory in its
first line. `PC-001` does not.

That matters for the fix in #145: **both directions of the pronoun are
affected**, not just the requirement one. `"is permitted but policy forbids
it"` and `"is denied but policy requires it"` have the same unresolved
reference, and a fix that names the required action for requirements only
would leave `PC-001` exactly as it is.

---

### At least one concrete improvement

**PC-005's phrasing risks the causality reading backwards** (see the rating
note above). If this holds up once someone else reads it cold, worth raising
as a `ai/Modelfile` prompt change, not fixed here since this exercise is
measurement only, per its own scope note. Whether it is a real, general
problem (the model tends to garble "policy requires X but config denies X"
into something that reads as "policy requires denying X") or specific to
this one finding is exactly the kind of thing a second rater's independent
note would settle.

**It held up, and it settled differently than expected** — a second rater
read it cold and rated it a grounding failure rather than a phrasing risk,
and locating the mechanism moved the likely fix out of `ai/Modelfile`
entirely. See the disagreement above. The improvement now on the table is
that `policy_compliance` should name the required action in
`evidence.detail` the way `access_control` already does, rather than
compressing it into a pronoun. Left as a proposal for
@shubhamkataria2005 — still measurement only here, and tracked in
[#145](https://github.com/ARSH871-bot/Netwise/issues/145) rather than in this
document, so the fix is not driven from an evidence file.

**Two raters reached this independently and it is worth saying so**, because
it is the strongest thing this round produced. @patelankeet2 filed #145 from
`PC-005` and `PC-004`; the rating above reached the same mechanism from
`PC-005` and `PC-001` while checking whether a two-clause detail was to blame
— it is not, `AC-001` is two-clause and reads correctly. Same conclusion, two
routes, four findings between them. That is a better result than agreement
would have been.
