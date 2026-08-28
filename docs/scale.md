# Netwise at scale — what fifty devices actually costs

**Issue:** #218. **Measured:** 28 August 2026, on `main` at `cfec2fa`.
**Owner:** Shubham (policy compliance · change impact)

Every fixture in this repository was one or two devices. Real networks arrive
as a folder of fifty, and #218 recorded this as *"the one gap where we
genuinely do not know how bad it is"*.

There is now a figure. It is reassuring about speed and alarming about
coverage, and the second half is the part worth reading.

---

## Runtime

Full `analyse()` — every registered check, against live Batfish — on snapshots
built by [`tools/make_scale_fixture.py`](../tools/make_scale_fixture.py):

| devices | load + analyse |
|---|---|
| 1 | 3.3 s |
| 5 | 3.4 s |
| 10 | 4.3 s |
| 25 | 5.1 s |
| 50 | 6.9 s |

**Roughly linear, and fast.** Fifty devices in seven seconds. Scale is not the
problem, and that is worth knowing because it was the thing nobody could
answer.

### What this figure is not

These are **not** a realistic network. Every device is the same router with a
different name and LAN; there is no routing between them and no device
references another. A real fifty-device network is harder in ways this cannot
show — topology, convergence, cross-device reachability.

**Read the number as a floor, not an estimate.** What it rules out is an
order-of-magnitude surprise in snapshot handling at the sizes we discuss. What
it says about a real client network is nothing.

---

## Coverage — the finding that matters

The same runs, looking at what was actually *checked*:

| devices | findings | what policy compliance reported |
|---|---|---|
| 1 | 3 | — |
| 5 | 3 | `PC-049` 4 of 5 not covered |
| 10 | 3 | `PC-049` 9 of 10 not covered |
| 50 | 3 | `PC-049` 49 of 50 not covered |

**Three findings at fifty devices, the same as at one.** The analysis does not
grow with the network, because every rule names a specific device (#87). Fifty
devices in, one device examined.

`PC-049` (#228/#229) is why that is visible rather than silent. Before it, this
snapshot reported a green tick.

### It is still silent for two of the three checks

On the committed ten-device fixture, today:

```
PC-049  error  9 of 10 device(s) in this config are not covered by any policy rule
RT-050  error  2 route assertion(s) could not be checked against this config
AC-000  none   No issues found by access control
```

**`access_control` reports "no issues found" on a snapshot where it examined
one device in ten.** That is #228 in the two checks I did not fix — I own
`policy_compliance` and flagged the others rather than reaching into them.

This fixture is the regression test for when they are.

---

## Reproducing it

```bash
python -m tools.make_scale_fixture                      # the committed 10
python -m tools.make_scale_fixture --devices 50 --out /tmp/n50
python -m analysis.pipeline /tmp/n50
```

The committed fixture is `tests/fixtures/multi-device-10/`. Ten rather than
fifty because ten exercises every behaviour that needs more than one device and
forty more identical files would add none — see the generator's docstring.

---

## What #218 asked for, and what is left

| | |
|---|---|
| a snapshot with a realistic device count | **done** — committed, plus a generator for larger |
| a measured runtime | **done** — the table above |
| behaviour at scale understood | **partly.** Speed is answered. Coverage is answered and is bad, and the fix is #87 rather than anything about scale |

The honest summary: **Netwise does not get slow on a large network. It gets
irrelevant**, because it has nothing to say about devices no rule names. That
is the same conclusion #87 reached from a different direction, now with a
number attached.
