# Who is doing what, and the rules that keep it that way

Written 27 August 2026, from the next-phase document and measured against the
board rather than remembered. **The distribution is the easy half. The rules
below are the half that failed twice this week.**

---

## 1. The distribution

Every item is a real GitHub issue with an assignee, a size label, a phase
label, acceptance criteria, and its dependencies named. Nothing here lives only
in a document.

### Phase 0 — finish what is nearly done

Already in flight. Nothing new is invented, and everything else waits on it.

| Item | Owner | Where |
|---|---|---|
| User's own policy, end to end | Arsh | #181, #196 — in review |
| PF Sense converter reachable from the upload | Ankeet | #211 — approved, needs a merge with `main` |
| A report that can leave the screen | **Samika** | #222 — see §3, I built #233 against his issue |

### Phase 1 — the four capabilities

Milestone: **Phase 1 - the four capabilities**.

| # | Item | Owner | Size |
|---|---|---|---|
| #235 | Coverage & Certainty Report | Arsh | M |
| #236 | Explanation provenance | Ankeet | M |
| #237 | Business-context risk scoring | Samika | M |
| #238 | Attack-path chaining | Shubham | L |
| #239 | CVE mapping | Samika | L |
| #220 | CIS Cisco IOS benchmark pack | Shubham *(move proposed)* | M |

### Phase 2 — direction only

**#240.** Four algorithmic problems, one per person, deliberately unscoped:
whole-network dependency graph (Arsh), multi-step deterministic reasoning
(Ankeet), content fingerprinting of findings (Samika), policy conflict
detection (Shubham).

Not assignments. If one becomes urgent it gets its own issue with acceptance
criteria first.

### What the board actually says

Measured, not asserted:

```
person      open issues   sized pts   phase-1 pts
Arsh                  6           2             2
Ankeet                8           2             2
Shubham               6           3             3
Samika                6           5             5
```

**This is even by count and uneven by weight, and that is deliberate rather
than sloppy.** Samika carries the most Phase 1 weight because CVE mapping
belongs next to risk scoring — both derive a severity that feeds the same
ordering, and splitting them across two people creates a seam that goes wrong
later. Ankeet's count is highest because he carries the Sprint 5 backlog
(#13, #14, #78, #182, #191) that the sized columns do not show.

If Samika would rather swap #239 for #236, the swap costs nothing today.

---

## 2. The version-control rules

Most of these already existed. Two are new, and both come from a failure this
week rather than from theory.

### Branches

```
feat/<issue>-<slug>     new capability
fix/<issue>-<slug>      a defect
docs/<slug>             documentation only
tools/<slug>            a standalone helper
```

Branch from `main`, never from another feature branch. **`tools/stacked_prs.py`
enforces this** — it exits 2 if it cannot check, which is not the same as
exiting 0.

### Pull requests

- **Nobody merges their own work.** M-1: a merge needs a *current* approving
  review — no commits pushed since it. Whether a merge-only push invalidates an
  approval is an open decision: **#230**.
- **One PR, one concern.** A PR that fixes a bug and tidies a docstring is two
  reviews pretending to be one.
- **The description carries the evidence**, not a summary of it. Numbers come
  from a command that was run, pasted as output.
- **Never rebase or force-push someone else's branch.**

### Reviews

- **Run it, do not read it.** Reproduce the claims. Both of this week's real
  finds came from executing a branch, neither from reading a diff.
- **Mutate the real guard**, not a re-implementation of it. `ast.parse` every
  mutant before trusting the result — three false survivors this week came from
  string-replacing a literal that also appears in a comment.
- **Ask what states the input can actually be in** before approving. The one
  bug that got past a review this month was a state nobody had tried.
- **A pushed fix does not re-request review.** See §3.

### Issues

Every issue carries an assignee, a `size:` label, a `phase:` label, acceptance
criteria as checkboxes, and its dependencies named as issue numbers. An issue
that says only what to build is a note, not an assignment.

---

## 3. The two rules that are new, because I broke both

Neither of these is theoretical. Both cost the team real time this week, and
both were mine.

### Before starting anything, check whether it is already taken

```bash
gh issue list --assignee "@me" --state open
gh pr list --state open --json number,title,author
gh issue list --search "<the thing you are about to build>"
```

Twice in two days I built something somebody already had:

```
#215 (mine)  duplicated  #211 (Ankeet's)   opened 15 hours earlier
#233 (mine)  duplicated  #222 (Samika's)   which I had assigned to him 19 hours earlier
```

The second is worse than the first. I handed out the work and then took it back
without saying anything. **One command before opening an editor would have
caught both.** Tracked as its own issue rather than a promise in a comment.

### When you push a fix for a changes-requested, re-request the review

```bash
gh pr edit <number> --add-reviewer <the reviewer who blocked it>
```

A comment does **not** put a PR back in anyone's queue. Measured:

```
#181  blocked 3.1 days   4 commits pushed since   0 reviews   NO pending request
#183  blocked 3.1 days   3 commits pushed since   0 reviews   NO pending request
```

I chased both with comments — eight on one, five on the other — into a thread
nobody was notified to reload. Review latency across 142 merged PRs is fine
(everyone's median is under eight hours); **re-review after a fix had no
mechanism at all.** Tracked as **#231**.

And the reciprocal, which is the half that is mine to own: **a
changes-requested you filed is an obligation with a clock.** If you cannot
re-review within a day of being re-requested, hand it to someone else
explicitly rather than leaving it.

---

## 4. What this document is not

It is not a plan the client has approved. The next-phase document asks Senaka
to choose between proceeding with the four, reprioritising them, or redirecting
us. **Phase 1 is provisional until he answers**, and the issues exist so that
the answer can be acted on the same day rather than three days later.
