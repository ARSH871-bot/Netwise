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

        def analyse_change(before_dir, after_dir) -> list[dict]

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
    It diffs. It does not AUDIT the proposed state -- it will not tell you
    that the "after" config violates POL-2, only that it changed. Running the
    producer checks over `after_dir` as well is open question 2 on the shapes
    document and is not mine to settle alone; I have argued for it on #61 and
    #86. Until then, "no change detected" means exactly that and must not be
    read as "the proposed config is fine".

RUN IT
    python -m analysis.change_impact <before-folder> <after-folder>
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from pybatfish.client.session import Session

from analysis import findings
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


def analyse_change(
    before_dir: str | Path,
    after_dir: str | Path,
    host: "str | None" = None,
) -> List[Dict[str, Any]]:
    """Compare two config folders and return F-1 findings describing the change.

    Does NOT raise for operational failures. An unreachable Batfish, a folder
    that will not load, a config that will not parse and a query that fails all
    come back as status="error" findings, because the user needs to be told
    rather than handed a stack trace -- the same promise analyse() makes.

    The three outcomes are kept distinct, which is the whole of F-4 here:

        found  the change did something, and here is what
        none   both configs loaded, both questions ran, nothing moved
        error  we could not compare -- NOT the same as "nothing changed"

    That middle one is the dangerous claim. "This change is safe" is exactly
    what a user wants to hear before applying it to a firewall, so it may only
    be said when both snapshots parsed and both questions actually ran.
    """
    before_dir, after_dir = Path(before_dir), Path(after_dir)

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
            source=f"{before_dir} -> {after_dir}",
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

    results: List[Dict[str, Any]] = []
    number = 1

    try:
        filter_changes, number = _filter_change_findings(bf, number)
    except Exception as error:
        return _error(
            summary="Change impact could not run: the filter comparison failed",
            detail=findings.describe_error(error),
            source=f"{before_dir} -> {after_dir}",
        )
    results.extend(filter_changes)

    try:
        flow_changes, number = _reachability_change_findings(bf, number)
    except Exception as error:
        # The filter comparison may already have found real changes. Report
        # BOTH -- what was proved AND what could not be reached. Discarding a
        # proven finding because a second query failed is issue #22, and it
        # fails in the reassuring direction.
        results.extend(
            _error(
                summary="The reachability comparison could not run",
                detail=findings.describe_error(error),
                source=f"{before_dir} -> {after_dir}",
            )
        )
        return results
    results.extend(flow_changes)

    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="No change detected between the two configurations",
                detail=(
                    "No filter line treats the same traffic differently, and no "
                    "flow reaches a destination it could not reach before. This "
                    "says the change moved nothing; it does not say the proposed "
                    "config is free of problems -- run the audit for that."
                ),
                source=f"{before_dir} -> {after_dir}",
                number=0,
            )
        ]

    return results


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(
            "usage: python -m analysis.change_impact <before-folder> <after-folder>\n"
            "example: python -m analysis.change_impact "
            "tests/fixtures/rtr-us5-secure tests/fixtures/rtr-us5-insecure"
        )
    results = analyse_change(sys.argv[1], sys.argv[2])
    print(json.dumps(results, indent=2))
    print()
    for status in ("found", "none", "error"):
        print(f"  {status:<6} {sum(1 for f in results if f['status'] == status)}")


if __name__ == "__main__":
    main()
