# Sprint 5 — what landed, what did not, and why this record is late

**Written 31 August 2026, five days after the sprint's due date.**

---

## The first finding is this file

`docs/sprint1/` through `docs/sprint4/` each carry a record written *inside*
the sprint. Sprint 3's entry says its record was written the day after the
sprint ended "rather than reconstructed later", and named that as the point.

**That practice then lapsed for two sprints.** This file is being written on
31 August for a sprint due on the 26th, and Sprint 6 has no record at all.

It is the same failure family the rest of this project keeps finding, arriving
through process rather than code: a documented practice standing in for a
performed one. The release tags did it before 13 August. A-2's ratification
did it this week. Recording it at the top rather than at the bottom, because a
retrospective item buried under a list of achievements is one nobody acts on.

---

## Measured, not recalled

Read from the milestones API and from `pytest`, on 31 August:

```
Sprint 5     35 / 43 closed  (81%)   due 2026-08-26   OVERDUE by 5 days
Sprint 4     27 / 27         (100%)  closed
Sprint 3      8 / 8          (100%)  closed

tests   384 at sprint start (e3b3e81, 19 Aug)
        1030 on 31 Aug                        +646
```

Pull requests merged 20–31 August:

```
Arsh      36        Shubham   11
Ankeet    10        Samika     5        62 total
```

**Arsh authored 58% of them.** That is not a throwaway number — it was measured
inside this sprint as #249, and it is the sprint's most important process
finding. More on it below.

---

## What landed

Ten issues closed in the milestone. The four that changed what the product
*is*, rather than how well it does what it already did:

| | |
|---|---|
| **#13 / #14** | **The AI's second direction.** The client asked for two: explain findings, and take a plain-English instruction and propose a config change, pushing back when it would open something. The second one now exists. `allow any to any` on a secured config returns a **warning** with two high-severity simulated impacts; on an already-open config it correctly reports no change. |
| **#181** | **A user's own policy reaches a check.** `policy_compliance` asserts *your* rules instead of our examples, and every finding says which of the two produced it. Policy-driven detections on a network that is not ours: **3 → 8**. |
| **#216** | **The client's own vendor produces a finding.** A converted PF Sense export used to report three "could not check" cards and nothing else. With a policy naming the converted device it now returns a real, evidenced, model-explained `PC-001`. |
| **#196** | **A check says when it ignored your policy.** Two of three checks still do not read one; they used to report *our* device names in a message about *your* rules. |

Also closed: **#225** (explanations cost 10s per page load with Ollama absent —
now 0.4s), **#182** (how a Policy reaches a check — the decision that unblocked
#181), **#192**, **#195**, **#138**, **#127**.

---

## What did not land, and the shape of it

Eight issues remain. **Five of them are unassigned:**

```
#78    @patelankeet2   the client's real export -- PR #206, changes-requested
#191   @patelankeet2   convert policy module-level state to an explicit argument
#227   @ARSH871-bot    verify_docs.py cannot catch a stale contrib.json

#80    UNASSIGNED      a rule with no <protocol> silently widens to 'ip'
#87    UNASSIGNED      the policy is ours, not the user's
#92    UNASSIGNED      explanations regenerated on every /api/findings call
#93    UNASSIGNED      widen the lint rules
#185   UNASSIGNED      policy.py's did-you-mean can never fire
```

**An unassigned issue in a sprint is not late work. It is work nobody started.**
`docs/work-distribution.md` says an issue without an assignee "is a note, not
an assignment" — and that sentence is mine. Five of them went into a sprint
anyway, and every one of them is exactly as unstarted now as on day one.

**#87 has now been carried through two sprints without being begun.** It is not
a sprint-sized item: "two of three checks ignore a user policy" means rewiring
`access_control` and `routing`. Putting it in a third sprint it cannot finish
is how it has drifted this far.

---

## The two things that were not on the plan and mattered more than half of it

**1. The review bottleneck, measured on ourselves (#249).**

```
PRs authored by Arsh      61%
reviews given by Arsh     24%       ratio 0.61
everyone else                        ratio 2.8 - 3.15
team review effort spent on Arsh's PRs   62%
```

Not a backlog — median time to first review on his PRs was 3.7 hours. The
problem was the opposite shape: he consumed most of the team's review capacity
while supplying least of it. The rule adopted from it — **review before
authoring** — is the reason four of someone else's PRs were reviewed on the
last two days of the sprint rather than four more being opened.

**2. Two false claims about team agreement, both found on the last day.**

```
CLAUDE.md said   "F-1 amendment A-2 -- RATIFIED by all four"
the contract      Shubham OK  Arsh OK  Samika OK  Ankeet NOT AGREED   3 of 4

CONTRIBUTING.md   M-2 cited as settled in CLAUDE.md section 7b
the table         1 of 4 at the time it was being quoted in reviews
```

Both were being *used* — M-2's three rules were cited in reviews and merges all
week by someone whose own row was blank. A contract ratification recorded as
complete when it is not is the highest-stakes place this project's recurring
fault has landed, and it sat under the heading "Settled — do not reopen without
the team", which is the one heading that stops anyone checking.

---

## What this sprint's own process got wrong

Three, all of them mine as SCRUM Master:

1. **Five unassigned items entered the sprint.** Against a rule I wrote.
2. **The record was not written inside the sprint.** Against a practice Sprint 3
   explicitly established and boasted about.
3. **The sprint was allowed to run five days past its due date without a
   decision.** Not "we are extending it" and not "we are moving the
   remainder" — just open. Drift is a decision nobody makes.

The counter-weight, and it is real: **the tests went 384 → 1030**, the client's
own vendor started producing findings, and the second half of what the client
actually asked the AI to do now exists. The sprint delivered. It was *run*
badly.

---

## For the retrospective

- **Do not put an unassigned issue in a sprint.** If nobody owns it on day one,
  it belongs in the backlog where its not-being-done is honest.
- **#87 should leave sprint planning.** It belongs in Phase 1, alongside the
  capabilities it blocks. Two sprints of carrying it is the evidence.
- **A ratification table needs a mechanism, not a convention.** A-2 has waited
  on one signature since 13 August and nobody was notified — that is #231's
  gap, one document further out.
- **Write the record on the closing day.** This one is proof of what happens
  otherwise; it had to be reconstructed from the API rather than remembered.

---

## Closing

Proposed on #175, deadline Wednesday midday: close Sprint 5 at what it reached,
move #80, #92, #93, #185, #191 and #227 to Sprint 6, and take **#87** out of
sprint planning entirely.

**A sprint that closes at 81% honestly is worth more than one held open until
it reads 100%.** Sprints 3 and 4 closed at 100% because they were scoped to
what fitted. This one was not, and saying so is the useful part of the record.
