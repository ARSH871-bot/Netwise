# Netwise — severity rules (US-17, `risk`)

**Owner:** Samika
**Implements:** `analysis/checks/risk.py`, registered in `POST_PROCESSORS`
**Shape:** post-processor — `refine(results) -> results`, per
[`docs/design/pipeline-feature-shapes.md`](design/pipeline-feature-shapes.md)
(ADOPTED, all four rows ticked)

This document is the ruleset. The code implements it; if the two disagree, one
of them is a bug. Written as a decision record in the same spirit as
[`docs/policy-rules.md`](policy-rules.md).

---

## 1. Why re-rating exists at all

Each check sets a severity when it builds a finding. That is a sensible
default — the check author knows what the statement was for — but it is decided
in isolation. `access_control` cannot see that `policy_compliance` found the
same blanket permit from another angle, and no check can see the whole list.

Prioritisation is the job of looking at every finding together and asking
"which of these should someone fix first?". That is why `risk` is a
post-processor and not a check: `run(bf)` would hand it a Batfish session when
what it needs is everyone else's findings.

## 2. What `risk` may and may not do

| | |
|---|---|
| **May** | change `severity` on `status="found"` findings; re-order the list |
| **Must not** | change `status`; change anything on a `status="error"` finding; add or remove findings |

The first two prohibitions are enforced in `pipeline.run_post_processors()`,
not merely written here — a violation restores the original finding *and* adds
an error finding saying what was attempted. The rules below are written to stay
inside those limits anyway; the enforcement is a backstop, not the design.

**`status="error"` findings are left completely alone.** An unrunnable check is
a blind spot regardless of what any rule says about the device, and a scoring
pass has no information bearing on whether a check ran. Re-rating one could only
move it down the page, which is the F-4 failure by another route.

## 3. The rules

Applied in order. The first that matches wins; anything unmatched keeps the
severity its check assigned.

### R-1 — A dead rule is low, whatever it says

**Matches:** `status="found"` and the evidence describes an unreachable /
shadowed ACL line.
**Sets:** `low`

A line that can never match cannot expose anything. It is a hygiene problem —
someone believes a rule is in force when it is not — and it is worth reporting,
but it is not an exposure and should not sit above one.

This rule is deliberately **first**, because a dead-rule finding usually quotes
the line that shadows it, and that line is very often a blanket permit. Without
the ordering, R-2 would match the quoted blocker and rate the dead rule `high`.
The exposure is not lost by rating it low: the blanket permit is reported
separately, on its own finding, by R-2.

### R-2 — A blanket permit is high

**Matches:** `status="found"` and the evidence mentions a permit of any source
to any destination **as its subject** — that is, a mention not preceded by an
attribution phrase (`decided by:`, `allowed by:`, `blocked by:`).
**Sets:** `high`

**The attribution exclusion is the whole of the rule's precision.** Our checks
end a violation's evidence by naming the ACL line responsible for it — *"…
Decided by: permit ip any any"*. There the permit is a **citation**: the reason
some *other* violation happened, not the thing being reported. A finding about
the permit itself names it as its subject instead.

Matching either way is the difference between prioritising and flattening —
see §6.2, where it is measured.

This is the client's own example of a serious misconfiguration, and it is the
one that most often appears innocuously — added to fix a connectivity complaint
and never removed. It defeats every rule after it on the same filter, so
whatever else the config says, this is what the device actually does.

### R-3 — A reachability failure is medium

**Matches:** `status="found"` and `check="routing"`.
**Sets:** `medium`

`routing` rates its violations `high`, which is right from inside that check: a
network that cannot reach itself is broken. But Netwise is a security tool, and
ranking an outage above an open firewall misprioritises the list a user reads
top-down. A path that does not work is also, sometimes, a control doing its job.

This is the one rule that routinely rates a finding *lower* than its check did,
and it is the one most worth arguing about. It is written here rather than
buried in code so that argument can happen.

### R-4 — Everything else keeps its default

No rule fires; the check's own severity stands. This is the common case and it
should stay the common case. A ruleset that overrides everything is not
prioritising, it is just moving the judgement somewhere less visible.

## 4. Ordering

After re-rating, findings are sorted worst-first: `error`, then `found` by
severity, then `none`. The sort is stable, so findings of equal rank stay in the
order their checks produced them.

This mirrors what the dashboard already does when it groups cards, so on screen
it changes nothing. It matters for every *other* consumer — the AI layer, the
JSON API, anyone diffing two runs — which would otherwise see findings in
registry order, which is alphabetical by accident rather than meaningful.

## 5. What this ruleset does NOT do

- **It does not read the config.** It only reads findings. Every input is
  something a check already observed and recorded as evidence.
- **It does not ask a model anything.** Severity is a judgement, and
  `docs/finding-format.md` is explicit that the AI never sets it. These rules
  are deterministic and testable precisely so that stays true.
- **It does not weight by device.** "This router is more important than that
  one" is real, but we have no source for it that is not guesswork, and
  inventing one would be exactly the unfounded claim the rest of this project
  avoids. If the client tells us, it becomes data, not a rule.

## 6. Open, and deliberately not settled here

1. ~~**`docs/finding-format.md:36` still says severity is "Assigned by Samika's
   rules, not by the AI".**~~ **SETTLED.** Amendment **A-1** merged in #59 with
   all four signatures, and `docs/finding-format.md` now says what this ruleset
   was always written against: the check sets a **default**, `risk` may
   **re-rate**, the AI never sets it. Its "The severity field — who sets it"
   section is the authority; this document implements it rather than
   anticipating it.

   Kept as a struck-through entry rather than deleted, because this item was
   cited as an open question in review and a reader who followed that citation
   needs to find the answer, not a gap.
2. ~~**R-2 flattens the list when one blanket permit causes everything.**~~
   **FIXED — R-2 now ignores a permit that is merely cited.** Recorded rather
   than deleted, because the measurement is the argument for the current rule.

   R-2 was a bare substring test, so it fired on the trailing *"Decided by:
   permit ip any any"* clause that names the line responsible for a violation.
   On `rtr-us5-insecure` all five findings carry that clause, quoting the same
   line, so all five were promoted. Measured, not predicted:

   | Fixture | `found` before | after (old R-2) | after (current R-2) |
   |---|---|---|---|
   | `rtr-us5-insecure` | 4 high, 1 medium | **5 high** | **4 high, 1 medium** |
   | `rtr-us5-messy` | 1 high, 5 medium | 1 high, 3 medium, 2 low | 1 high, 3 medium, 2 low |

   The spread is restored on `rtr-us5-insecure` and `rtr-us5-messy` is
   untouched — R-2 never fired there in either version, so the change is
   provably confined to the case it was aimed at.

   **What this leaves open, and it is a real question:** on both fixtures R-2
   now promotes **nothing at all**. The four `high` values on
   `rtr-us5-insecure` are the checks' own defaults, reached through R-4. So the
   rule the client explicitly asked for currently has no observed effect on any
   fixture we have.

   That is not evidence the rule is wrong — a finding whose *subject* is a
   blanket permit is exactly what `access_control`'s `undefinedReferences` and
   `searchFilters` arms would produce on a config shaped slightly differently,
   and it is tested directly in `tests/test_severity_rules.py`. But it does
   mean **R-2 is unexercised by our fixtures**, and a rule that never fires is
   indistinguishable from a rule that does not work. A fixture whose evidence
   names the permit as its subject would close that gap, and is worth adding
   before anyone relies on R-2 in a review.

3. **F-1 has no informational status.** A record of "these three findings were
   re-rated, and why" is not `found`, not `none`, and not `error`, so there is
   nowhere to put it. Rather than force it into one of the three and mislead,
   `risk` records nothing and this document plus the tests are the audit trail —
   the rules are pure functions of a finding, so any re-rating can be recomputed
   by hand. If the team wants re-ratings visible on screen, F-1 needs a fourth
   status and that needs all four members.
