"""Netwise -- what changed since the last scan? (US-22, #315)

Storage-agnostic on purpose. Scans are plain dicts passed in memory, shaped
like the row proposed on #223. Where they are kept, what a "target" is and how
long history lives are open team decisions; none of them change what a
difference between two scans means, so this does not wait for them.

THE ONE RULE
    A finding may only be called RESOLVED if its check actually ran on that
    device in the later scan.

    `analysis.identity.compare()` says which findings were reported in one
    scan and not the other. It cannot say why. Measured against real Batfish
    on rtr-us5-insecure, with Batfish then unreachable for the later scan:

        earlier   5 found
        later     error, error, error        coverage.checked == []
        compare() "disappeared": 6, five of them status=found

    Calling those resolved reports five fixes when nobody looked. Here they
    are UNVERIFIED, and the three checks that went dark are NEWLY BLIND.

WHY A GAP OVERRIDES A RESULT FOR THE SAME CHECK AND DEVICE
    `coverage.summarise()` marks (check, device) as checked if ANY finding
    for it is found or none. But one check runs several analyses:
    access_control reports dead rules and policy statements separately, and
    a statement that fails reports `device=node` -- the real device. So one
    scan can hold (access_control, rtr-us5) in `checked` AND in `gaps`.

    A policy-statement finding that disappeared in that scan did not get
    fixed; its analysis did not run. A dead-rule result for the same device
    says nothing about it. So a covering gap -- same check, same device or
    device "unknown" -- wins over `checked`.

    Stated precisely: that same-device case is known from READING the code
    (`device=node` on every per-item error in access_control and routing).
    No committed fixture produces it today, so the tests build one with the
    real `findings.error_finding()` helper rather than claim a measurement.

THE COST OF THAT, MEASURED AND ACCEPTED
    It is conservative, and on some snapshots it means "resolved" can never
    be reported. Measured, searching every fixture for a check that has a
    result on a device AND a gap for the same check: exactly one case.

        multi-device-10, with a user policy naming one of its ten devices
          checked  (policy_compliance, stranger-rtr-dev001)
          gap      (policy_compliance, unknown)
                   "9 of 10 device(s) in this config are not covered ..."

    The gap's summary is about the OTHER nine devices, but its `device` field
    is "unknown", so nothing structural says it does not cover dev001. A
    policy_compliance problem on dev001 that really is fixed is therefore
    reported UNVERIFIED, not RESOLVED, for as long as the policy names one
    device of ten.

    That is the right direction to be wrong in. Under-reporting a fix costs
    a user a second look; over-reporting one tells them to stop looking. The
    better fix is for PC-049 to name the uncovered devices structurally,
    which is a change to that check, not to this module.

WHY "UNVERIFIED" AND NOT "NEWLY BLIND" FOR FINDINGS
    #315 asks that a check that has newly gone blind be its own category.
    That is `newly_blind` here, and it is about COVERAGE: a (check, device)
    that ran before and does not now.

    A disappeared finding under a gap is a different claim, and often not a
    new one -- the multi-device-10 gap above exists in both scans, so calling
    its findings "newly blind" would itself overclaim. So findings that
    cannot be confirmed fixed are `unverified`, each with a reason.

ONLY status="found" IS A PROBLEM
    resolved, unverified, new and newly_visible are about PROBLEMS, so they
    only ever hold status="found" findings. An `error` finding appearing is a
    blind spot opening; one vanishing is coverage coming back. A `none`
    sentinel is a coverage statement too. Both are expressed through
    `newly_blind` and its mirror `newly_checked`, never as problems.

    Found by measurement, not foresight. Against a genuinely stopped Batfish
    the first version filed the three "Analysis could not run" errors as
    newly visible PROBLEMS, and on recovery filed their disappearance as
    fixes that could not be confirmed.

THE MIRROR
    A finding that appears is only NEW if its check ran on that device in the
    earlier scan with no covering gap. Otherwise it was there all along and
    Netwise could not see it: NEWLY VISIBLE. Measured against real Batfish,
    stopped and then started again: five found findings reappear as five
    newly visible, zero new, and the two checks that came back are listed in
    `newly_checked`.

WHAT ELSE STOPS A CLAIM
    - The user's policy changed between scans (`policy_hash` differs): a
      finding can vanish because nobody asserts it any more. Nothing is
      resolved and nothing is new; every difference is attributed to the
      policy.
    - The device is not in the later snapshot at all (`devices`): absent is
      not fixed.
    - The later scan dropped pfSense rules in conversion
      (`conversion_skips`): `coverage.summarise()` cannot see those, and #306
      is still open, so a skipped rule may be exactly why a finding vanished.

    A changed Netwise build, or an unchanged config fingerprint, does not
    reclassify anything; it is reported in `caveats` so a reader knows why a
    rewording or a policy-only change produced the difference.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from analysis import coverage as coverage_module
from analysis import identity

Pair = Tuple[str, str]


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def make_scan(findings: Sequence[Mapping[str, Any]], **fields: Any) -> Dict[str, Any]:
    """Build a scan in the #223 row shape from a findings list.

    `coverage` is always computed from the findings rather than accepted from
    the caller, so a stored scan cannot carry a coverage claim its own
    findings do not support. The optional fields are passed through:
    `policy_hash`, `netwise_build`, `config_fingerprint`, `devices`,
    `conversion_skips`, `created_at`, `target`.
    """
    scan = dict(fields)
    scan["findings"] = [dict(f) for f in findings]
    scan["coverage"] = coverage_module.summarise(scan["findings"])
    return scan


def _checked(scan: Mapping[str, Any]) -> Set[Pair]:
    return {(_norm(r["check"]), _norm(r["device"]))
            for r in scan["coverage"]["checked"]}


def _gap_covers(scan: Mapping[str, Any], check: str, device: str) -> Optional[str]:
    """The summary of a gap that could hide this (check, device), or None."""
    for gap in scan["coverage"]["gaps"]:
        if _norm(gap["check"]) == check and _norm(gap["device"]) in (device, "unknown"):
            return gap["summary"]
    return None


def _ran_cleanly(scan: Mapping[str, Any], check: str, device: str) -> bool:
    """The check produced a result for this device AND nothing hides it."""
    return (check, device) in _checked(scan) and _gap_covers(scan, check, device) is None


def _policy_changed(earlier: Mapping[str, Any], later: Mapping[str, Any]) -> bool:
    a, b = earlier.get("policy_hash"), later.get("policy_hash")
    return a is not None and b is not None and a != b


def diff(earlier: Mapping[str, Any], later: Mapping[str, Any]) -> Dict[str, Any]:
    """Classify every difference between two scans.

    Returns:
        unchanged      findings reported in both
        resolved       reported earlier, not later, and the check ran cleanly
                       on that device later
        unverified     reported earlier, not later, but a fix cannot be
                       confirmed: [(finding, reason), ...]
        new            reported later, not earlier, and the check ran cleanly
                       on that device earlier
        newly_visible  reported later, not earlier, but Netwise could not
                       have seen it before: [(finding, reason), ...]
        newly_blind    (check, device) pairs that ran cleanly earlier and do
                       not now: [(check, device, reason), ...]
        newly_checked  (check, device) pairs that run cleanly now and did not
                       earlier -- coverage coming back

    resolved/unverified/new/newly_visible only ever hold status="found"
    findings; errors and "none" sentinels are coverage, not problems.
        possibly_same  passed through from identity.compare()
        caveats        plain-language notes that reclassify nothing
    """
    for name, scan in (("earlier", earlier), ("later", later)):
        if "findings" not in scan or "coverage" not in scan:
            raise ValueError(f"{name} scan has no findings/coverage -- build it with make_scan()")

    base = identity.compare(earlier["findings"], later["findings"])

    def _problems(items: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
        return [f for f in items if f.get("status") == "found"]
    policy_changed = _policy_changed(earlier, later)
    later_devices = {_norm(d) for d in later["devices"]} if later.get("devices") is not None else None
    skips = later.get("conversion_skips") or []

    resolved: List[Mapping[str, Any]] = []
    unverified: List[Tuple[Mapping[str, Any], str]] = []
    for f in _problems(base["disappeared"]):
        check, device = _norm(f.get("check")), _norm(f.get("device"))
        gap = _gap_covers(later, check, device)
        if policy_changed:
            unverified.append((f, "the policy changed between these scans"))
        elif later_devices is not None and device not in later_devices:
            unverified.append((f, "the device is not in the later snapshot"))
        elif skips:
            unverified.append((f, "the later scan skipped pfSense rules in conversion"))
        elif gap is not None:
            unverified.append((f, f"the later scan could not check this: {gap}"))
        elif (check, device) not in _checked(later):
            unverified.append((f, "the check did not report on this device in the later scan"))
        else:
            resolved.append(f)

    new: List[Mapping[str, Any]] = []
    newly_visible: List[Tuple[Mapping[str, Any], str]] = []
    for f in _problems(base["appeared"]):
        check, device = _norm(f.get("check")), _norm(f.get("device"))
        gap = _gap_covers(earlier, check, device)
        if policy_changed:
            newly_visible.append((f, "the policy changed between these scans"))
        elif gap is not None:
            newly_visible.append((f, f"the earlier scan could not check this: {gap}"))
        elif (check, device) not in _checked(earlier):
            newly_visible.append((f, "the check did not report on this device in the earlier scan"))
        else:
            new.append(f)

    newly_blind: List[Tuple[str, str, str]] = []
    for check, device in sorted(_checked(earlier)):
        if not _ran_cleanly(earlier, check, device):
            continue
        if later_devices is not None and device not in later_devices:
            continue  # absent, not blind -- reported via `unverified` findings
        gap = _gap_covers(later, check, device)
        if gap is not None:
            newly_blind.append((check, device, gap))
        elif (check, device) not in _checked(later):
            newly_blind.append((check, device, "reported nothing for this device"))

    newly_checked: List[Tuple[str, str]] = []
    for check, device in sorted(_checked(later)):
        if _ran_cleanly(later, check, device) and not _ran_cleanly(earlier, check, device):
            newly_checked.append((check, device))

    caveats: List[str] = []
    if policy_changed:
        caveats.append("The policy changed between these scans, so no difference is "
                       "attributed to the network.")
    if earlier.get("netwise_build") and later.get("netwise_build") \
            and earlier["netwise_build"] != later["netwise_build"]:
        caveats.append("Netwise itself changed between these scans; reworded findings "
                       "appear in possibly_same.")
    if earlier.get("config_fingerprint") and \
            earlier.get("config_fingerprint") == later.get("config_fingerprint"):
        caveats.append("The configuration is byte-identical in both scans; every "
                       "difference came from the policy, Netwise, or what could run.")
    if skips:
        caveats.append(f"The later scan skipped {len(skips)} pfSense rule(s) in conversion.")

    return {
        "unchanged": _problems(base["unchanged"]),
        "resolved": resolved,
        "unverified": unverified,
        "new": new,
        "newly_visible": newly_visible,
        "newly_blind": newly_blind,
        "newly_checked": newly_checked,
        "possibly_same": base["possibly_same"],
        "caveats": caveats,
    }
