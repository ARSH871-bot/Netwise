# What is my own work, and where is the proof?

**Slice** access control · the shared pipeline · SCRUM Master
**Owner** Arsh Vhora
**Format** Shubham's, from his Evidence Portfolio. One rule matters: *every
row and every entry must name something a reader can open and check.*

> Batfish answers questions about a network. It has no idea what your
> security policy is, which question to ask, or what the answer means. My
> slice is the layer that decides what a problem *is*, and the layer that
> guarantees a check which could not run is never mistaken for one that ran
> and found nothing.

---

## Part 1 — Traceability

Read left to right: somebody asked for this → it became a story → here is the
code → here is the test that proves it. A row that cannot be completed is
work that was never really finished.

| What was asked for | Rule | Implemented in | Proved by |
|---|---|---|---|
| Does this filter permit or deny one specific flow, and which line decided? | US-9 | `access_control.py` — `testFilters` | `tests/test_device_scoping.py` |
| Prove a property across a whole space of flows, not one example | US-9 | `access_control.py` — `searchFilters` | `tests/test_device_scoping.py` |
| Find rules that can never fire because an earlier line shadows them | US-9 | `access_control.py` — `filterLineReachability` | `tests/test_device_scoping.py` |
| Find config pointing at an ACL that was never defined | US-9 | `access_control.py` — `undefinedReferences` | `tests/test_device_scoping.py` |
| A broken check must never break the other three | F-3 | `pipeline.py` — `run_check()`, the `except` arm | `tests/test_f4_invariants.py` |
| **A check that returns nothing must not read as "found nothing"** | F-4 | `pipeline.py` — `run_check()`, the empty-result arm | `test_a_check_returning_nothing_becomes_an_error_not_silence` |
| `none` and `error` must be distinguishable | F-4 | `findings.py` — three statuses, validated | `test_the_two_are_distinguishable_which_is_the_whole_point` |
| Two findings must never share an id | A-2 | `pipeline.py` — `duplicate_id_findings()` | `tests/test_finding_ids.py` — 24 tests |
| An unreachable Batfish must report, not crash | F-4 | `pipeline.py` — `_every_check_failed()` | `tests/test_batfish_unreachable.py` |
| "Could not find out" ≠ "found out, nothing there" | F-4 | `snapshot.py` — returns `None`, not `set()` | `tests/test_device_scoping.py` |
| A policy naming absent devices is reported once, not per rule | #45 | `access_control.py` — device scoping | `tests/test_device_scoping.py` |

All four Batfish questions confirmed present in the module by reading it, not
from memory. All test files confirmed to exist.

---

## Part 2 — Decisions, and why

Each entry is a choice that could have gone the other way, the reason it did
not, and a source.

### A check that returns nothing is an error, not a pass

The obvious pipeline collects what each check returns. A check that crashes
contributes nothing — and **nothing is indistinguishable from "no problems
found"**.

Batfish cannot help here: it answers, or it raises. It has no third answer.
So every green tick this product shows depends on a distinction the analysis
engine does not have.

```
                        WITHOUT the guards        WITH them
a check that CRASHES    0 findings                AC-000 error:
                        "NO PROBLEMS FOUND"       "failed to run"

a check that RETURNS [] 0 findings                AC-000 error:
                        "NO PROBLEMS FOUND"       "returned no findings"
```

Both guards are pinned by tests, checked by removing each from the real
function:

```
the crash guard removed     1 failed
the silence guard removed   2 failed
```

Identical with Batfish up and down.

**Source** `tools/why_the_pipeline.py` (runnable, needs neither Batfish nor
Ollama) · `analysis/pipeline.py` `run_check()` · `tests/test_f4_invariants.py`

### A post-processor may not downgrade or drop an error

`risk` re-rates severity. It is structurally forbidden from lowering or
removing a `status="error"` finding — and a violation is restored *and*
reported, rather than trusted not to happen.

The reason is F-4 reached from a different direction: if the finding that
vanishes is the one saying a check never ran, the user reads "all clear".

**Source** `analysis/pipeline.py` `run_post_processors()` · A-1, ratified ×4
in `docs/finding-format.md`

### Three shapes for a feature, not one

`change_impact` needs **two** snapshots, so it cannot satisfy `run(bf)`.
Rather than widening the contract for one feature, it became a separate entry
point and the contract stayed fixed.

The decision was written and agreed **before** the code existed, and needed
no amendment when it was built — which is the only real test of an
architectural decision.

**Source** `docs/design/pipeline-feature-shapes.md`, adopted ×4 · `#140`

### A distinct id prefix rather than a better guard

`duplicate_id_findings()` detects collisions; it cannot prevent them. Giving
`change_impact` its own `CH-` prefix makes one whole class impossible rather
than detectable.

**The guard stays anyway.** A prefix removes collisions *between* checks;
uniqueness *within* one check is still discipline, because `make_finding()`
takes `number` as an argument and both sentinel helpers default to 0. Defence
in depth, not duplication.

**Source** A-2, ratified ×4 · `tests/test_finding_ids.py` · `#130`

### Removed two scripts of my own that bypassed the contract

`analysis/smoke_test.py` and `us5_load_and_analyse.py` called Batfish and
printed results raw — no `found`/`none`/`error` distinction at all. Someone
running them got output that looked authoritative and carried none of the
guarantees everything else is held to.

Deleting my own working code was the right call precisely because a visitor
grepping the repo could have copied that pattern.

**Source** `#146` · recoverable from `v0.2.0` and `v0.3.0`

---

## Part 3 — Found by understanding the tool

Three defects where the code ran, returned a confident answer, and was wrong.

### `preflight` reported "all importable" while five of seven packages were wrong

The environment check confirmed packages *import*. It did not check the
*versions* matched what the project declares.

```
pandas            installed 2.3.3    declared >=3.0.5
fastapi           installed 0.128.0  declared >=0.141.1
uvicorn           installed 0.40.0   declared >=0.52.1
python-multipart  installed 0.0.21   declared >=0.0.32
pytest            installed 9.0.2    declared >=9.1.1
```

**CI was testing pandas 3.x while the same suite locally tested 2.x — both
green, and not the same test.** Every local number quoted that week was
measured against a different dependency set from the one CI used.

**Source** `#162` · `tools/preflight.py`

### A fix applied to the file rather than to the property

`#172` fixed `python tools/preflight.py` failing to import the package.
`tools/` had three scripts. Probing all of them:

```
preflight.py          ok           ok            (fixed by #172)
stranger_config.py    ok           IMPORT FAILS
```

The tool that measures the largest gap in the product could not be run one of
its two documented ways, and nobody noticed. The fix enumerates `tools/*.py`
rather than naming a script, so the next tool added is covered on the day it
lands.

**Source** `#176` · `tests/test_tools_invocation.py`

### I broke my own rule forty-eight minutes after writing it

`#188` added: *retarget a stacked PR to `main` before merging its parent.*

```
20:43:37Z   #188 merged — the rule lands on main
21:31:13Z   I merge #180 with --delete-branch
21:31:15Z   #190 closes automatically
```

#190 was Ankeet's, approved, and takes the client's real firewall from 0 of 7
rules analysed to 3 of 7. Recovering it is impossible — `gh` refuses both
`pr edit --base` and `pr reopen` — so it was reopened as `#197`, which has
since merged.

**A rule that lives only in prose is not a control.** `tools/stacked_prs.py`
is the control, and it found a third case on its first run: `#184` is stacked
on `#183`.

**Source** `#188` · `#197` · `#199` · `tools/stacked_prs.py`

---

## Part 4 — The gap I have not closed

**The policy is ours, not the user's.** Measured across every readable
fixture with `tools/stranger_config.py` — the same config, device renamed:

```
ours       12 found /  3 none /  7 error
stranger    3 found /  0 none / 15 error
```

One rename removes three quarters of the detection. What survives is the two
analyses that need no policy at all.

`#181` wires one check to a user-supplied policy and is **blocked on `#182`**,
which asks the team how a policy should reach a check — I implemented an
answer before that question existed and have not merged it, because the seam
is not mine to settle by merging first.

Stating it here because a portfolio that lists only what works is marketing.

**Source** `tools/stranger_config.py` · `#181` · `#182` · issue `#87`
