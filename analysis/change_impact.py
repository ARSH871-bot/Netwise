"""
Netwise -- change-impact analysis (Shubham's second feature, US-18 / #30).

WHAT THIS ANSWERS
    "If I make this change, what does it actually do?" -- asked BEFORE the
    change reaches a real device. The client asked for exactly this, and it is
    the question the rest of Netwise cannot answer: every check reads ONE
    config and says whether it is bad. This reads TWO and says what moved.

WHY THIS IS NOT A CHECK
    docs/design/pipeline-feature-shapes.md, ADOPTED with four signatures. The
    CHECKS registry hands a check one Batfish session with one snapshot
    loaded. A differential question needs two, so `run(bf)` cannot express it.

        def analyse_change(before_dir, after_dir, host=None, policy=None) -> list[dict]

    It is called directly and is registered in nothing. DO NOT add it to
    CHECKS -- the pipeline carries a comment saying so, and this docstring is
    the other half of that pair.

THE TWO QUESTIONS, AND WHY BOTH
    compareFilters            which ACL LINES changed
    differentialReachability  which TRAFFIC changed fate

    They answer different things and the pair is what makes the result
    trustworthy:

      - a changed line that alters no traffic is noise -- an edit that reads
        as dangerous and does nothing
      - changed traffic with no changed line means something upstream moved,
        which is the case a filter-level diff alone would miss entirely

    Measured on our own fixtures before anything was written here (#30):
    secure -> insecure returns 1 row from each, and reversing the snapshots
    reports the tightening rather than the loosening. Both directions matter,
    because only one of them is a warning -- see DIRECTION below.

THE TRAP THIS MODULE IS BUILT AROUND
    `differentialReachability` sees nothing at all unless the start location
    is one traffic ENTERS. Measured, secure -> insecure, varying only that:

        startLocation="rtr-us5"                          rows=0
        startLocation="rtr-us5[GigabitEthernet0/0]"      rows=0   <-- names the
                                                                     right
                                                                     interface,
                                                                     still blind
        startLocation="@enter(rtr-us5[GigabitEthernet0/0])"  rows=1
        (no pathConstraints at all)                          rows=1

    An inbound ACL is only crossed by traffic ARRIVING at an interface. A node
    location means traffic ORIGINATING at the device, which never traverses
    one -- so a query constrained that way returns "nothing changed" for a
    change that replaces `deny ip any any` with `permit ip any any`.

    I reported that primitive as broken on #30 and was wrong: the primitive is
    fine, my start location was not. The empty answer was correct for the
    question I asked. That is why this module passes NO path constraint at
    all rather than a tidy-looking one -- unconstrained covers every entry
    point, and the tidy version is the one that silently excludes the ACL.

    ai/query.py had the same mistake from the same cause, and it is fixed
    (#108, #141): its reachability question now starts at @enter(device). Two
    modules, one week, one shape -- which is why the test below asserts on the
    ARGUMENT rather than on the answer. Every other test here fakes the
    session, so none of them can see what was actually sent to Batfish, and
    reintroducing the constraint left all fifteen green while silently
    dropping a real finding.

DIRECTION -- the thing that makes a diff useful rather than merely accurate
    A change that OPENS something and a change that CLOSES something are not
    the same news:

        permit where there was deny   -> new exposure. Silent: nothing breaks,
                                         nobody complains, and it is still
                                         there at the breach.
        deny where there was permit   -> something stops working. Loud: the
                                         helpdesk hears within minutes.

    Severity follows docs/policy-rules.md's model, which grades on how long a
    problem survives unnoticed rather than on impact alone: opening is `high`,
    closing is `medium`. Both are reported. A tightening is not automatically
    good -- it is how you break DNS for a whole site -- so it is never
    silently filed as an improvement.

FINDING IDS
    change_impact owns the `CH-` prefix outright since amendment A-2 (#102).

        CH-000   nothing changed          -- the clean sentinel
        CH-001+  one change, numbered in the order found
        CH-050   could not compare        -- the check-level error sentinel

    CH-050 mirrors policy_compliance's PC-050 deliberately: SENTINEL_NUMBER +
    ERROR_NUMBER_OFFSET, so there is one pattern across both of my features
    rather than two conventions. See #101.

WHAT THIS DOES NOT DO YET, STATED RATHER THAN IMPLIED
    It diffs. Since #323 it also runs every policy_compliance rule before and
    after, so it tells you which of those rules the change breaks, fixes,
    leaves breached, or alters -- but it still does not run access_control or
    routing over `after_dir`, and the result says so rather than implying
    otherwise (#402). Running the
    producer checks over `after_dir` as well is open question 2 on the shapes
    document and is not mine to settle alone; I have argued for it on #61 and
    #86. Until then, "no change detected" means exactly that and must not be
    read as "the proposed config is fine".

RUN IT
    python -m analysis.change_impact <before-folder> <after-folder> [policy.json]

WHAT IT REPORTS, IN ORDER (#403, #402)
    devices added or removed        found   -- the largest change, which neither
                                               Batfish comparison describes
    filter lines that moved         found   compareFilters
    traffic that changed fate       found   differentialReachability
    policy rules broken / fixed /
      altered / still breached      found   policy_compliance's own query, per side
    a stage that could not run      error   CH-050 filter, CH-052 devices,
                                            CH-053 reachability, CH-054 policy,
                                            CH-051 rules not compared
    more than 48 changes            found   CH-049, the rest summarised
    nothing moved                   none    CH-000, naming the rules it did not move

    Each stage runs whatever the others did, so a failure never hides what
    another stage proved, and never hides that a stage did not run.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pybatfish.client.session import Session

from analysis import findings
from analysis import policy as policy_module
from analysis.pipeline import connect, find_parse_problems, load_snapshot

CHECK_NAME = "change_impact"

# Mirrors policy_compliance. See FINDING IDS above and #101.
ERROR_NUMBER_OFFSET = 50
SKIPPED_NUMBER = ERROR_NUMBER_OFFSET

# Batfish needs the two snapshots under distinct names within one network.
NETWORK_NAME = "netwise-change"
BEFORE_SNAPSHOT = "before"
AFTER_SNAPSHOT = "after"

# Severity by direction, per docs/policy-rules.md's model: graded on how long
# the problem survives unnoticed, not on impact alone.
_OPENING_SEVERITY = "high"  # silent -- nothing breaks, so nobody looks
_CLOSING_SEVERITY = "medium"  # loud -- someone notices within the hour


def _error(summary: str, detail: str, source: str) -> List[Dict[str, Any]]:
    """The one shape for "we could not compare". Never a quiet empty list."""
    return [
        findings.error_finding(
            check=CHECK_NAME,
            summary=summary,
            detail=detail,
            source=source,
            number=SKIPPED_NUMBER,
        )
    ]


def _direction(line_action: str) -> str:
    """PERMIT in the after snapshot means the change OPENED something."""
    return "opened" if str(line_action).upper() == "PERMIT" else "closed"


# Which trace dispositions count as the flow having got through.
#
# DELIBERATELY WIDER THAN analysis/checks/routing.py'S SET, which excludes
# EXITS_NETWORK. That exclusion is right for routing: it is asserting that a
# route WORKS, and a destination device missing from the snapshot also reports
# EXITS_NETWORK, so counting it would read an absent device as a working route.
#
# Here the question is different. differentialReachability has ALREADY decided
# which flows count as successful -- it returns flows successful in exactly one
# of the two snapshots, and its own success set includes EXITS_NETWORK. This set
# is only used to work out WHICH SIDE succeeded, so it has to agree with the
# question that selected the flow. Using routing's narrower set here would match
# neither side and lose the direction entirely.
_SUCCESS_DISPOSITIONS = frozenset({"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"})


def _any_success(traces: Any) -> bool:
    """True if any trace in the list ended in a disposition that got through.

    Reads `Trace.disposition` structurally rather than matching on the rendered
    text -- the rendering is for humans and is not a contract.
    """
    try:
        return any(str(t.disposition).upper() in _SUCCESS_DISPOSITIONS for t in traces)
    except TypeError:
        return False


def _flow_direction(snapshot_traces: Any, reference_traces: Any) -> str:
    """Which way a flow's fate moved: "opened", "closed", or "changed".

    WHY THIS IS COMPUTED RATHER THAN ASSUMED
        The first version of this module assumed every differentialReachability
        row was traffic newly getting through, and set severity accordingly.
        That is wrong: the question is SYMMETRIC. Measured on our fixtures,
        reversing the two snapshots returns a row either way --

            secure -> insecure   snapshot PERMITTED / reference DENIED_IN
            insecure -> secure   snapshot DENIED_IN / reference EXITS_NETWORK

        -- so the assumption rated a tightening as a new exposure, at `high`.
        Caught by running the reverse direction, which is the only reason it
        did not ship.

    "changed" is returned when both sides look successful or neither does. That
    should not happen given how the question selects flows, but the honest
    answer to an unexpected shape is to say the direction is unknown rather
    than to pick one.
    """
    after_ok = _any_success(snapshot_traces)
    before_ok = _any_success(reference_traces)
    if after_ok and not before_ok:
        return "opened"
    if before_ok and not after_ok:
        return "closed"
    return "changed"


def _filter_change_findings(
    bf: Session, number: int
) -> tuple[List[Dict[str, Any]], int]:
    """compareFilters: which ACL lines now treat the same traffic differently.

    Returns (findings, next_number). Raises are left to the caller -- a query
    we could not run is a blind spot, and this module never turns one into an
    empty result.
    """
    frame = (
        bf.q.compareFilters()
        .answer(snapshot=AFTER_SNAPSHOT, reference_snapshot=BEFORE_SNAPSHOT)
        .frame()
    )

    results: List[Dict[str, Any]] = []
    for i in range(len(frame)):
        row = frame.iloc[i]
        direction = _direction(row["Line_Action"])
        node = str(row["Node"])
        filter_name = str(row["Filter_Name"])

        if direction == "opened":
            summary = f"A rule change opens traffic that {filter_name} used to block"
            severity = _OPENING_SEVERITY
        else:
            summary = f"A rule change blocks traffic that {filter_name} used to allow"
            severity = _CLOSING_SEVERITY

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=severity,
                device=node,
                summary=summary,
                # Both lines, verbatim from Batfish. The reader needs the pair
                # to see the change; one line alone is not a diff.
                detail=(
                    f"After:  {row['Line_Content']} (line {row['Line_Index']}, "
                    f"{row['Line_Action']}). "
                    f"Before: {row['Reference_Line_Content']} "
                    f"(line {row['Reference_Line_Index']}). "
                    "Both match at least one common flow and treat it differently."
                ),
                source=f"{node}:{filter_name}",
                status="found",
                number=number,
            )
        )
        number += 1

    return results, number


def _reachability_change_findings(
    bf: Session, number: int
) -> tuple[List[Dict[str, Any]], int]:
    """differentialReachability: which traffic now ends up somewhere else.

    NO pathConstraints, deliberately -- see THE TRAP in the module docstring.
    Constraining the start location to a node, or even to the right interface,
    silently excludes traffic entering it, which is the only traffic an
    inbound ACL ever sees.
    """
    frame = (
        bf.q.differentialReachability()
        .answer(snapshot=AFTER_SNAPSHOT, reference_snapshot=BEFORE_SNAPSHOT)
        .frame()
    )

    results: List[Dict[str, Any]] = []
    for i in range(len(frame)):
        row = frame.iloc[i]
        direction = _flow_direction(row["Snapshot_Traces"], row["Reference_Traces"])
        if direction == "opened":
            summary = "Traffic reaches a destination it could not reach before"
            severity = _OPENING_SEVERITY
        elif direction == "closed":
            summary = "Traffic no longer reaches a destination it used to reach"
            severity = _CLOSING_SEVERITY
        else:
            # Neither side looks clearly successful. Say so rather than pick a
            # direction -- an unexplained reachability change still deserves
            # attention, so it keeps the higher severity.
            summary = "Traffic changed where it ends up, in a way we could not classify"
            severity = _OPENING_SEVERITY

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=severity,
                device=_device_of(row["Flow"]),
                summary=summary,
                detail=(
                    f"Flow {row['Flow']}. "
                    f"After:  {_first_trace(row['Snapshot_Traces'])}. "
                    f"Before: {_first_trace(row['Reference_Traces'])}."
                ),
                source="differentialReachability",
                status="found",
                number=number,
            )
        )
        number += 1

    return results, number


def _device_of(flow: Any) -> str:
    """The starting device named in a Batfish Flow, or "unknown".

    Flow renders as "start=rtr-us5 interface=... [...]". Parsed rather than
    guessed at, and falling back to "unknown" rather than to something
    plausible -- F-1 would rather say we do not know.
    """
    text = str(flow)
    marker = "start="
    if marker not in text:
        return "unknown"
    return text.split(marker, 1)[1].split()[0] or "unknown"


def _first_trace(traces: Any) -> str:
    """One trace, trimmed. Batfish returns a list; the first shows the change."""
    text = str(traces).strip()
    return text[:160] if text else "(no trace)"


# --- Every policy rule, before and after (#323, US-31) -----------------------
#
# WHY THIS EXISTS
#     Change impact and policy compliance both existed and never met. The two
#     questions above say what traffic MOVED. They do not say which of the
#     user's own rules the move breaks or repairs -- and an engineer editing a
#     firewall cares about every rule they have, not the one flow they were
#     thinking about.
#
# WHAT IT DOES
#     Each policy_compliance rule is asked the same Batfish question the check
#     asks (`policy_compliance._search`, so the two can never disagree about
#     what a breach is), once against each snapshot. Four outcomes per rule:
#
#         before    after
#         clean     clean     unchanged
#         breached  breached  unchanged   -- still broken, not caused by this
#         breached  clean     RESOLVED    -- this change fixes a breach
#         clean     breached  CREATED     -- this change causes a breach
#
#     A change that resolves one breach and creates another reports BOTH,
#     because a net count of zero is exactly how a swap hides.
#
# DIRECTION, IN THIS MODULE'S EXISTING TERMS
#     "opening" means more traffic permitted; "tightening" means less. A
#     prohibition is breached when forbidden traffic is PERMITTED, so creating
#     that breach is opening and resolving it is tightening. A requirement is
#     breached when required traffic is DENIED, so it is the other way round.
#     Opening is rated high and tightening medium, for the reason given at
#     _OPENING_SEVERITY: nothing breaks when a hole opens, so nobody looks.

_RULE_DIRECTION = {
    # (kind, created?) -> direction
    ("prohibition", True): "opening",
    ("prohibition", False): "tightening",
    ("requirement", True): "tightening",
    ("requirement", False): "opening",
}


def _rule_breached(bf: Any, snapshot_name: str, rule: Dict[str, Any]) -> bool:
    """Is this rule breached in this snapshot? Raises if it cannot be asked.

    Uses the check's own query and its own kind-to-action mapping, so a
    rule means here exactly what it means in a scan.
    """
    from analysis.checks import policy_compliance as pc

    bf.set_snapshot(snapshot_name)
    action = pc.ACTION_BY_KIND[rule["kind"]]
    for headers in rule["queries"]:
        if pc._search(bf, rule["node"], rule["filter"], action, headers):
            return True
    return False


def _rule_label(rule: Dict[str, Any]) -> str:
    number = rule.get("number")
    head = f"policy rule {number}" if number is not None else "a policy rule"
    return f"{head} ({rule['description']})" if rule.get("description") else head


def _breach_changed(bf: Any, rule: Dict[str, Any]) -> bool:
    """For a rule breached before AND after: did the change alter WHICH
    traffic breaches it? (#402 item 4)

    "Breached on both sides" is not "unchanged". Closing LAN->8.8.8.8 while
    opening LAN->1.1.1.1 leaves a "no other destinations" rule breached
    throughout, and the old wording called that "neither causes nor fixes".
    Differential searchFilters answers it directly: rows are flows whose
    verdict differs between the two snapshots.
    """
    from pybatfish.datamodel.flow import HeaderConstraints

    from analysis.checks import policy_compliance as pc

    action = pc.ACTION_BY_KIND[rule["kind"]]
    for headers in rule["queries"]:
        frame = (
            bf.q.searchFilters(
                nodes=rule["node"], filters=rule["filter"], action=action,
                headers=HeaderConstraints(**headers),
            )
            .answer(snapshot=AFTER_SNAPSHOT, reference_snapshot=BEFORE_SNAPSHOT)
            .frame()
        )
        if len(frame):
            return True
    return False


def _devices(bf: Any) -> "Tuple[set | None, set | None]":
    """The devices in each snapshot, or None for a side we could not read."""
    from analysis import snapshot

    out = []
    for name in (BEFORE_SNAPSHOT, AFTER_SNAPSHOT):
        bf.set_snapshot(name)
        out.append(snapshot.device_names(bf))
    return out[0], out[1]


def _device_change_findings(before: set, after: set, number: int) -> Tuple[List[Dict[str, Any]], int]:
    """A device on one side only is a change, and the largest kind (#403).

    Neither compareFilters nor differentialReachability reports it: a filter
    that no longer exists has nothing to compare against, so deleting a
    whole router used to come back as "No change detected" with a green tick.
    """
    results = []
    for name in sorted(before - after):
        results.append(findings.make_finding(
            check=CHECK_NAME, severity=_CLOSING_SEVERITY, device=name,
            summary=f"Device {name} is removed by this change",
            detail=(f"{name} is in the before configuration and not in the after one. "
                    "Every flow it carried changes, and the filter and reachability "
                    "comparisons below do not describe a device that exists on one "
                    "side only, so this card is the only record of it."),
            source=f"{BEFORE_SNAPSHOT} -> {AFTER_SNAPSHOT}", status="found", number=number))
        number += 1
    for name in sorted(after - before):
        results.append(findings.make_finding(
            check=CHECK_NAME, severity=_OPENING_SEVERITY, device=name,
            summary=f"Device {name} is added by this change",
            detail=(f"{name} is in the after configuration and not in the before one. "
                    "Nothing about its traffic is compared below, because there is "
                    "nothing to compare it against -- run a scan of the after "
                    "configuration to check it."),
            source=f"{BEFORE_SNAPSHOT} -> {AFTER_SNAPSHOT}", status="found", number=number))
        number += 1
    return results, number


def _policy_coverage() -> Tuple[List[Dict[str, Any]], str, bool, str]:
    """(policy_compliance rules, label, user_supplied, sentence about the rest).

    US-31 says "every policy rule". This stage compares policy_compliance
    rules only, and the sentence says so out loud (#402 item 3) -- a user
    whose policy is one access_control rule must not read "unchanged" as
    "your rule still holds".
    """
    from analysis.checks import policy_compliance as pc

    rules, label, user_supplied = pc.rules_in_use()
    note = ""
    active = policy_module.active_policy()
    if active is not None:
        skipped = [f"{len(active.entries_for(s))} {s}"
                   for s in ("access_control", "routing") if active.entries_for(s)]
        if skipped:
            note = ("NOT compared: " + " and ".join(skipped) + " rule(s) in your policy. "
                    "Change impact compares policy_compliance rules only; scan the "
                    "after configuration to check the others.")
        if not rules:
            note = ("NOT compared: your policy has no policy_compliance rules, so no "
                    "rule of yours was checked against this change. " + note).strip()
    return rules, label, user_supplied, note


def _policy_change_findings(bf: Any, number: int, before: "set | None" = None,
                            after: "set | None" = None) -> Dict[str, Any]:
    """Run every applicable policy_compliance rule against both snapshots.

    Returns a dict, not a finding list, because three of its outputs are
    sentences that analyse_change() folds into the ONE card it owns:

        findings      created, resolved, altered or still-breached rules
        unchanged     same verdict on the rule's filter, before and after
        absent        rules about a device in NEITHER configuration
        one_side      rules about a device in only ONE configuration
        not_compared  rules we could not ask -- never "unchanged" (F-4)
        coverage      what this stage did not compare at all
    """
    rules, policy_label, _, coverage = _policy_coverage()
    out: Dict[str, Any] = {"findings": [], "unchanged": [], "absent": [], "one_side": [],
                           "not_compared": [], "coverage": coverage,
                           "label": policy_label, "number": number}
    for rule in rules:
        node = rule["node"]
        if before is not None and after is not None:
            if node not in before and node not in after:
                # Worded like PC-050 (#402 item 1). This change cannot affect a
                # rule about a device in neither configuration: a proven
                # "not applicable", not a blind spot, so not an error -- an
                # error here made every proposal on a network without rtr-us5
                # "could not be fully verified".
                out["absent"].append(f"{rule.get('number', '?')} ({node})")
                continue
            if (node in before) != (node in after):
                side = "before" if node in before else "after"
                out["one_side"].append(f"{_rule_label(rule)}: {node} is in the {side} configuration only")
                continue
        try:
            was = _rule_breached(bf, BEFORE_SNAPSHOT, rule)
            now = _rule_breached(bf, AFTER_SNAPSHOT, rule)
            altered = _breach_changed(bf, rule) if (was and now) else False
        except Exception as error:
            out["not_compared"].append(f"{_rule_label(rule)}: {findings.describe_error(error)}")
            continue

        if not was and not now:
            out["unchanged"].append(str(rule.get("number", "?")))
            continue

        where = f"{rule['kind']} on {node} filter {rule['filter']}"
        if was and now:
            if altered:
                summary = f"This change alters how {_rule_label(rule)} is breached"
                detail = (f"{where}: breached before and after, but by different "
                          "traffic -- the change moves which flows break the rule. "
                          "Direction: changed.")
                severity = rule.get("violation_severity", "high")
            else:
                summary = f"{_rule_label(rule)} is breached before and after this change"
                detail = (f"{where}: breached the same way on both sides. This change "
                          "does not cause it and does not fix it; the violation stays.")
                severity = "low"
        else:
            created = now and not was
            direction = _RULE_DIRECTION[(rule["kind"], created)]
            summary = (f"This change BREAKS {_rule_label(rule)}" if created
                       else f"This change FIXES {_rule_label(rule)}")
            detail = (f"{where}: {'held before, breached after' if created else 'breached before, holds after'}. "
                      f"Direction: {direction}. "
                      + (f"Violation if applied: {rule.get('violation_summary')}." if created
                         else "The breach this rule reports is gone in the proposed config."))
            severity = rule.get("violation_severity", "high") if created else "low"
        out["findings"].append(findings.make_finding(
            check=CHECK_NAME, severity=severity, device=node, summary=summary, detail=detail,
            source=f"{policy_label}; rule {rule.get('number', '?')}", status="found",
            number=number))
        number += 1
    out["number"] = number
    return out


#: Ordinary findings stop here. 49 and above are this module's own cards, so
#: a long diff can never collide with them (#402 item 6) -- the band
#: policy_compliance already uses (PC-049, PC-050).
_OVERFLOW_NUMBER = 49
_RULES_NOT_COMPARED_NUMBER = SKIPPED_NUMBER + 1      # CH-051
_DEVICES_UNKNOWN_NUMBER = SKIPPED_NUMBER + 2         # CH-052
_REACHABILITY_FAILED_NUMBER = SKIPPED_NUMBER + 3     # CH-053
_POLICY_FAILED_NUMBER = SKIPPED_NUMBER + 4           # CH-054


def _cap(regular: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep the first 48 ordinary findings; fold the rest into CH-049."""
    if len(regular) < _OVERFLOW_NUMBER:
        return regular
    kept, rest = regular[: _OVERFLOW_NUMBER - 1], regular[_OVERFLOW_NUMBER - 1:]
    order = {"high": 0, "medium": 1, "low": 2}
    worst = min((f["severity"] for f in rest), key=order.get)
    kept.append(findings.make_finding(
        check=CHECK_NAME, severity=worst, device="unknown",
        summary=f"{len(rest)} further change(s) not listed individually",
        detail=("This change produced more findings than are listed one by one. "
                "The first of the rest: " + "; ".join(f["summary"] for f in rest[:5])
                + (" ..." if len(rest) > 5 else "")),
        source=f"{BEFORE_SNAPSHOT} -> {AFTER_SNAPSHOT}", status="found",
        number=_OVERFLOW_NUMBER))
    return kept


def analyse_change(
    before_dir: str | Path,
    after_dir: str | Path,
    host: "str | None" = None,
    policy: Any = None,
) -> List[Dict[str, Any]]:
    """Compare two config folders and return F-1 findings describing the change.

    Does NOT raise for operational failures. An unreachable Batfish, a folder
    that will not load, a config that will not parse and a query that fails all
    come back as status="error" findings, because the user needs to be told
    rather than handed a stack trace -- the same promise analyse() makes.

    The three outcomes are kept distinct, which is the whole of F-4 here:

        found  the change did something, and here is what
        none   both configs loaded, every question ran, nothing moved
        error  we could not compare -- NOT the same as "nothing changed"

    That middle one is the dangerous claim. "This change is safe" is exactly
    what a user wants to hear before applying it to a firewall, so it may only
    be said when both snapshots parsed and every question actually ran.
    """
    before_dir, after_dir = Path(before_dir), Path(after_dir)
    where = f"{before_dir} -> {after_dir}"

    try:
        bf = connect(host)
    except Exception as error:
        return _error(
            summary="Change impact could not run: Batfish is not reachable",
            detail=(
                f"Batfish is not answering at {host}. Start it with: "
                "docker start batfish. "
                f"Underlying error: {findings.describe_error(error)}"
            ),
            source=where,
        )

    # Load both. Named snapshots in one network so the differential questions
    # can reference them, and shared with analyse() via load_snapshot() so the
    # two entry points cannot drift on what a snapshot folder must look like.
    bf.set_network(NETWORK_NAME)
    for label, folder, name in (
        ("before", before_dir, BEFORE_SNAPSHOT),
        ("after", after_dir, AFTER_SNAPSHOT),
    ):
        try:
            load_snapshot(bf, folder, NETWORK_NAME, name)
        except Exception as error:
            return _error(
                summary=f"Change impact could not run: the {label} config could not be loaded",
                detail=findings.describe_error(error),
                source=str(folder),
            )

    # Both must parse. A half-read config on either side makes every comparison
    # below a statement about something we did not fully read.
    for label, folder, name in (
        ("before", before_dir, BEFORE_SNAPSHOT),
        ("after", after_dir, AFTER_SNAPSHOT),
    ):
        bf.set_snapshot(name)
        try:
            problems = find_parse_problems(bf)
        except Exception as error:
            return _error(
                summary=f"Change impact could not run: parse status could not be read for the {label} config",
                detail=findings.describe_error(error),
                source=str(folder),
            )
        if problems:
            return _error(
                summary=f"Change impact could not run: the {label} config did not fully parse",
                detail=(
                    "Batfish could not fully read: "
                    + "; ".join(problems)
                    + ". A line it did not parse is a change we cannot see."
                ),
                source=str(folder),
            )

    regular: List[Dict[str, Any]] = []
    reserved: List[Dict[str, Any]] = []
    number = 1

    def blind(n: int, summary: str, detail: str) -> None:
        reserved.append(findings.error_finding(
            check=CHECK_NAME, summary=summary, detail=detail, source=where, number=n))

    # Which devices are on each side (#403). Unknown is an error, never "none".
    before_devs = after_devs = None
    try:
        before_devs, after_devs = _devices(bf)
    except Exception as error:
        blind(_DEVICES_UNKNOWN_NUMBER, "Could not list the devices in each configuration",
              findings.describe_error(error))
    if before_devs is None or after_devs is None:
        if not any(f["id"].endswith(f"{_DEVICES_UNKNOWN_NUMBER:03d}") for f in reserved):
            blind(_DEVICES_UNKNOWN_NUMBER, "Could not list the devices in each configuration",
                  "Batfish did not say which devices each configuration defines, so a "
                  "device added or removed by this change would not be reported.")
    else:
        device_changes, number = _device_change_findings(before_devs, after_devs, number)
        regular.extend(device_changes)

    # Each stage runs whatever the others did (#402 item 6). What one proved
    # stands when another fails, and the failure is said (#22).
    try:
        filter_changes, number = _filter_change_findings(bf, number)
        regular.extend(filter_changes)
    except Exception as error:
        blind(SKIPPED_NUMBER, "The filter comparison could not run", findings.describe_error(error))

    try:
        flow_changes, number = _reachability_change_findings(bf, number)
        regular.extend(flow_changes)
    except Exception as error:
        blind(_REACHABILITY_FAILED_NUMBER, "The reachability comparison could not run",
              findings.describe_error(error))

    # Every policy rule, before and after (#323). Installed the same way
    # analyse() installs it and cleared in a `finally`, so a policy never
    # outlives the call that supplied it.
    policy_module.set_active_policy(policy)
    stage: Dict[str, Any] = {}
    try:
        stage = _policy_change_findings(bf, number, before_devs, after_devs)
        regular.extend(stage["findings"])
    except Exception as error:
        blind(_POLICY_FAILED_NUMBER, "The policy comparison could not run",
              findings.describe_error(error))
    finally:
        policy_module.clear_active_policy()

    not_compared = stage.get("not_compared", []) + stage.get("one_side", [])
    if not_compared:
        blind(_RULES_NOT_COMPARED_NUMBER,
              f"{len(not_compared)} policy rule(s) could not be compared across the change",
              "; ".join(not_compared))

    # The sentences about rules nothing above reported on.
    notes = []
    if stage.get("unchanged"):
        notes.append("Policy rule(s) with the same verdict on their filter before and "
                     "after (this says the filter's decision did not move, not that "
                     "nothing about their traffic did): " + ", ".join(stage["unchanged"]) + ".")
    if stage.get("absent"):
        notes.append("Policy rule(s) about devices in neither configuration, which this "
                     "change cannot affect: " + ", ".join(stage["absent"]) + ".")
    if stage.get("coverage"):
        notes.append(stage["coverage"])
    note_text = (" " + " ".join(notes)) if notes else ""

    results = _cap(regular) + reserved

    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="No change detected between the two configurations",
                detail=(
                    "No device was added or removed, no filter line treats the same "
                    "traffic differently, and no flow reaches a destination it could "
                    "not reach before. This says the change moved nothing; it does "
                    "not say the proposed config is free of problems -- run the "
                    "audit for that." + note_text
                ),
                source=where,
                number=0,
            )
        ]

    if notes:
        # Alongside real changes, so it can never be mistaken for the
        # all-clear above -- and it takes CH-000 only because that all-clear
        # is, by construction, not in this list.
        results.append(
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="Policy rules this change did not move",
                detail=note_text.strip(),
                source=where,
                number=0,
            )
        )
    return results


# --- How big is this change? (#420) -------------------------------------------
#
# One number beside the findings, so a reviewer gets the size of a change
# before reading every card. Three rules, each from #420's criteria:
#
#   COMPUTED, AND SHOWN. The score is a weighted count of the findings above,
#   and the breakdown is returned with it, so it can always be explained. It
#   reads only `status` and `severity` -- structured fields -- never a
#   summary's wording, which this project has been burnt by twice (#145,
#   #205).
#
#   OPENING COUNTS MORE THAN CLOSING. Not a second model: the severities
#   above already encode it (_OPENING_SEVERITY high, _CLOSING_SEVERITY
#   medium; a broken policy rule carries the rule's own severity), so
#   weighting by severity carries it through.
#
#   INCOMPLETE NEVER SCORES SMALL. A change that could not be fully compared
#   has an unknown size, and a low number would read as reassurance. Any
#   `error` finding makes the band "incomplete", whatever the number.
#
# Returned beside the findings, never inside them: it is not an F-1 field
# (see the open question on #405 about adding keys to findings).

SCORE_WEIGHTS = {"high": 3, "medium": 2, "low": 1}

#: (lowest score, band). A score of 0 is "none" only when nothing was blind.
SCORE_BANDS = ((10, "large"), (4, "moderate"), (1, "small"), (0, "none"))


def score(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The size of a change, from analyse_change()'s findings."""
    found = [f for f in results if f.get("status") == "found"]
    blind = [f for f in results if f.get("status") == "error"]
    breakdown = {sev: sum(1 for f in found if f.get("severity") == sev) for sev in SCORE_WEIGHTS}
    total = sum(SCORE_WEIGHTS[sev] * n for sev, n in breakdown.items())
    band = next(name for floor, name in SCORE_BANDS if total >= floor)
    if blind:
        band = "incomplete"
    parts = [f"{n} {sev} x{SCORE_WEIGHTS[sev]}" for sev, n in breakdown.items() if n]
    explanation = (" + ".join(parts) + f" = {total}") if parts else "no changes found = 0"
    if blind:
        explanation += (f"; {len(blind)} part(s) could not be compared, so the real size is "
                        "unknown and may be larger")
    return {"score": total, "band": band, "complete": not blind,
            "breakdown": dict(breakdown, could_not_compare=len(blind)),
            "explanation": explanation}


def main() -> None:
    if len(sys.argv) not in (3, 4):
        sys.exit(
            "usage: python -m analysis.change_impact <before-folder> <after-folder> [policy.json]\n"
            "example: python -m analysis.change_impact "
            "tests/fixtures/rtr-us5-secure tests/fixtures/rtr-us5-insecure"
        )
    policy = None
    if len(sys.argv) == 4:
        policy = policy_module.load_policy_file(sys.argv[3])
        # Every channel, like `python -m analysis.pipeline --policy` (#402 item 6).
        for note in list(policy.renamed) + list(policy.assigned):
            print(f"note: {note}")
    results = analyse_change(sys.argv[1], sys.argv[2], policy=policy)
    print(json.dumps(results, indent=2))
    size = score(results)
    print()
    print(f"  size   {size['band']} ({size['explanation']})")
    print()
    for status in ("found", "none", "error"):
        print(f"  {status:<6} {sum(1 for f in results if f['status'] == status)}")


if __name__ == "__main__":
    main()
