"""Mechanical coverage statements derived from F-1 findings (#235).

This module does not decide whether the network is safe. It only restates the
part of the finding contract a reader otherwise has to infer: which reported
check/device pairs produced evidence, and which ones were blind spots.

The important asymmetry is deliberate:

* status="found" and status="none" both mean a check ran and produced a
  definite result for the device named by the finding.
* status="error" means Netwise could not check something. That row must remain
  visible even when the main finding sections are skimmed, exported, or sorted
  elsewhere.

CONVERSION GAPS ARE A SEPARATE THING FROM A CHECK GAP, AND THEY ARE PASSED IN
SEPARATELY RATHER THAN INFERRED (#302 review, @SamikaPerera)
    A finding-based gap means a CHECK could not run. A conversion gap means
    part of the SOURCE FILE was never turned into anything a check could see
    at all -- today, a pfSense rule `analysis/pfsense_convert.py` could not
    convert (#78). Neither this module nor its caller can derive that from
    the findings list, because a converter-excluded rule leaves no finding
    behind to derive it from -- that is exactly the gap.

    Before this parameter existed, `summarise()` had no way to know a
    conversion had dropped anything, so a config with every CHECK running
    cleanly reported "Every reported check ran. Nothing was skipped." even
    when real rules from the uploaded file were never analysed. Not false
    about the checks -- every one of them did run -- but read by a person as
    a single claim, and the wrong one: skipping a `pass` rule makes the
    emitted config STRICTER than the real device, which can make a policy
    check that should report a violation report `none` instead. See
    `CLAUDE.md` section 7 for the direction analysis. A reader who trusted
    "nothing was skipped" would have no way to know that risk exists for
    this specific report.

`None` MEANS SOMETHING DIFFERENT FROM `()`, AND FROM A NON-EMPTY LIST
(#302 review, @ARSH871-bot)
    `web.main._staged_pfsense_skips()` returns three distinct things: `[]`
    when it VERIFIED nothing was excluded, a non-empty list when it read
    real skip notes, and `None` when a skip record exists but could not be
    read -- truncated, wrong type, unparseable. Before this distinction
    existed, an unreadable record and a verified-empty one both collapsed to
    `[]` here, so a corrupted skip file produced the exact same "nothing was
    skipped" claim as a config that genuinely excluded nothing. Passing
    `None` through lets this function tell a reader the true thing: not
    "nothing was skipped", but "whether anything was skipped could not be
    determined" -- and `complete` is `False` in that case for the same
    reason it is `False` when something genuinely was skipped.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Marks an `evidence.source` that names DEVICES rather than a file location.
#:
#: WHY A SOURCE, AND WHY THIS EXACT PREFIX
#:     A finding has one `device`. A gap about nine devices therefore has to
#:     say "unknown" there, and a reader of the gap -- `analysis/scan_diff.py`
#:     above all -- must then assume it may cover ANY device. F-1 defines
#:     `source` as where the evidence came from, "filename:line where
#:     possible", and its own examples include a bare device name. Listing
#:     the devices a gap is about is within that meaning. A list-typed field
#:     would be better and would need an F-1 amendment signed by all four.
#:
#:     The prefix contains a SPACE on purpose. access_control already writes
#:     sources as f"{node}: {filter}" -- "rtr-us5: acl_in". A prefix shaped
#:     like "word: " could be produced by a device named "word". No hostname
#:     can contain a space, so "affected devices: " cannot collide with one.
DEVICE_LIST_PREFIX = "affected devices: "


def device_list_source(devices: Iterable[str]) -> str:
    """An `evidence.source` naming exactly these devices, sorted."""
    return DEVICE_LIST_PREFIX + ", ".join(sorted(devices))


def devices_in_source(source: Any) -> Optional[List[str]]:
    """The devices a `device_list_source()` names, or None if it names none.

    None means "this source is not a device list" -- a file path, or
    "rtr-us5: acl_in", or "rtr-branch, rtr-hq" written some other way. It
    never means "no devices", which is not a gap anyone emits.
    """
    text = str(source or "")
    if not text.startswith(DEVICE_LIST_PREFIX):
        return None
    names = [n.strip() for n in text[len(DEVICE_LIST_PREFIX):].split(",")]
    names = [n for n in names if n]
    return names or None


def devices_still_clean(results: Iterable[Dict[str, Any]],
                        covered: Iterable[str]) -> List[str]:
    """The devices in `covered` that no finding in `results` is about, sorted.

    Each check uses this to emit its all-clear BESIDE other findings (#364),
    naming exactly the devices it can vouch for. Before, one finding anywhere
    suppressed the all-clear for every device, so a device whose problems
    were all fixed had no result at all, and a scan diff read the fix as the
    check going blind on it.

    A found or error finding names its device, or lists them in its source,
    and those are not clean. A finding of UNKNOWN scope -- device "unknown"
    and no device list -- may be about any device, so nothing is vouched
    for: the answer is empty, exactly as before this existed.
    """
    clean = set(covered)
    for finding in results:
        if finding.get("status") not in ("found", "error"):
            continue
        device = str(finding.get("device") or "unknown")
        listed = devices_in_source((finding.get("evidence") or {}).get("source"))
        if device != "unknown":
            # A fault between two routers names one in `device` and both in
            # its source: neither may be vouched for as clean.
            clean.discard(device)
            clean -= set(listed or [])
            continue
        if listed is None:
            return []
        clean -= set(listed)
    return sorted(clean)


def _label(finding: Dict[str, Any]) -> Tuple[str, str]:
    return (
        str(finding.get("check") or "unknown"),
        str(finding.get("device") or "unknown"),
    )


def summarise(
    findings: Iterable[Dict[str, Any]],
    conversion_gaps: Optional[Sequence[str]] = (),
) -> Dict[str, Any]:
    """Return the coverage/certainty view implied by a findings list.

    `conversion_gaps` is optional and additive -- omitting it reproduces this
    function's exact prior behaviour, so every existing caller keeps working
    unchanged. Pass it when the findings came from a converted config and the
    converter excluded anything, so the statement below can stop claiming
    nothing was skipped when something genuinely was -- just not something a
    check could have reported on.

    Pass `None` rather than `()` when the CALLER genuinely does not know
    whether anything was excluded -- see this module's own docstring for why
    that is a third, distinct state rather than the same thing as "verified
    empty".

    The result is intentionally plain dicts, matching the rest of the analysis
    layer's F-1 data. It is derived, not cached; if the findings change, the
    coverage statement changes with them.
    """
    checked: set[Tuple[str, str]] = set()
    gaps: List[Dict[str, str]] = []

    for finding in findings:
        check, device = _label(finding)
        status = finding.get("status")

        if status in {"found", "none"}:
            checked.add((check, device))
            # An all-clear lists every device it vouches for (#364), so each
            # of them was checked -- not only the one in its `device` field.
            if status == "none":
                source = (finding.get("evidence") or {}).get("source")
                for listed in devices_in_source(source) or []:
                    checked.add((check, listed))
            continue

        if status != "error":
            continue

        evidence = finding.get("evidence") or {}
        source = str(evidence.get("source") or "")
        # WHAT THIS GAP COVERS (#315). A named device covers itself. A gap on
        # device "unknown" covers the devices its source lists, if it lists
        # any -- PC-049 does -- and otherwise None: scope unknown, so a
        # reader must assume it may hide anything.
        if device != "unknown":
            covers: Optional[List[str]] = [device]
        else:
            covers = devices_in_source(source)
        gaps.append({
            "check": check,
            "device": device,
            "summary": str(finding.get("summary") or "The check could not run"),
            "detail": str(evidence.get("detail") or ""),
            "source": source,
            "covers": covers,
        })

    checked_rows = [
        {"check": check, "device": device}
        for check, device in sorted(checked)
    ]
    conversion_gaps_unreadable = conversion_gaps is None
    conversion_gap_rows = (
        [] if conversion_gaps is None else [str(note) for note in conversion_gaps]
    )

    if not checked and not gaps:
        # THE THIRD STATE, AND IT IS NOT COMPLETENESS.
        #     An empty findings list is not "everything ran and nothing was
        #     skipped" -- it is "nobody looked". Saying the former under a
        #     green heading is F-4 arriving one layer up from the findings:
        #     "we checked and found nothing" and "we could not check" are
        #     different claims, and an absence of findings is neither.
        complete = False
        statement = (
            "No check reported a result, so this report makes no claim about "
            "coverage. Nothing here says the configuration was examined."
        )
    elif gaps:
        one = len(gaps) == 1
        statement = (
            f"{len(gaps)} reported check/device blind spot"
            f"{'' if one else 's'} {'remains' if one else 'remain'}. "
            f"Findings may be incomplete."
        )
        complete = False
    elif conversion_gaps_unreadable:
        # THE CASE #302's REVIEW (ROUND TWO, @ARSH871-bot) FOUND. Every
        # check ran and none of them reported a blind spot, but the record
        # of what a converter may have excluded before any check ran could
        # not be read -- truncated, wrong type, unparseable. Complete is
        # False here for the same reason it is False when the record names
        # a real exclusion below: this report cannot say analysis was
        # exhaustive when it does not know whether part of the source file
        # was dropped before any check ever saw it.
        statement = (
            "Every reported check ran, but the record of what a converter "
            "may have excluded before any check ran could not be read. "
            "Whether anything was excluded is unknown, so this report "
            "cannot claim the analysis is complete."
        )
        complete = False
    elif conversion_gap_rows:
        # THE CASE #302's REVIEW FOUND. Every check ran and none of them
        # reported a blind spot -- but that is a claim about the checks,
        # not about the file. Complete is False here on purpose: this
        # report cannot say analysis was exhaustive when part of the
        # source file was excluded before any check ever saw it.
        one = len(conversion_gap_rows) == 1
        statement = (
            f"Every reported check ran, but {len(conversion_gap_rows)} part"
            f"{'' if one else 's'} of the uploaded configuration could not "
            f"be converted and {'was' if one else 'were'} not included in "
            f"this analysis."
        )
        complete = False
    else:
        statement = "Every reported check ran. Nothing was skipped."
        complete = True

    return {
        "complete": complete,
        "statement": statement,
        "checked": checked_rows,
        "gaps": gaps,
        "conversion_gaps": conversion_gap_rows,
        "conversion_gaps_unreadable": conversion_gaps_unreadable,
    }
