"""
Netwise -- access-control check (Arsh's feature).

>>> THIS FILE IS THE TEMPLATE. Ankeet, Shubham, Samika: copy its shape. <<<

    A check is one Python file with one function:

        def run(bf: Session) -> list[dict]

    It receives a live Batfish session with the snapshot already loaded, and
    returns a list of findings built with analysis.findings. That is the whole
    contract. The pipeline handles connecting, loading, and catching your
    mistakes -- you only write the analysis.

WHAT THIS CHECK DOES -- four analyses, one check

    1. POLICY STATEMENTS (testFilters)
       "This exact packet must be allowed / blocked." Spot-checks one flow at a
       time and names the ACL line that decided.

    2. GUARANTEES (searchFilters)   <-- our strongest capability
       "NO packet in this whole space may be permitted." Searches an entire
       space of flows at once, so it PROVES a property instead of sampling it.

    3. DEAD RULES (filterLineReachability)
       Finds ACL lines that can never match because an earlier line shadows
       them. The config looks like it does something; it does nothing.

    4. UNDEFINED REFERENCES (undefinedReferences)
       Finds config pointing at an ACL or object group that was never defined.

    All four are access control, so they are ONE check -- `access_control` --
    producing `AC-` findings. They are not four registry entries: F-1 fixes the
    `check` vocabulary to five values, and adding to it needs all four of us.

HOW IT DECIDES WHAT TO REPORT
    Every analysis reports independently:
      - a real problem            -> status="found"
      - Batfish could not answer  -> status="error", we are blind here
      - nothing wrong anywhere    -> ONE status="none" for the whole check

    Each analysis is wrapped separately, so if filterLineReachability fails we
    still run undefinedReferences. A blind spot in one analysis must not
    silently shrink the others.

    And we only ever say "all clear" if every analysis actually completed. If a
    query failed, the honest answer is "we could not check" -- see F-4 in
    docs/finding-format.md.
"""

from itertools import count
from typing import Any, Dict, Iterator, List

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings, snapshot

# The name this check is registered under, and the value that goes in every
# finding's "check" field.
CHECK_NAME = "access_control"

# --- 1. Policy statements: single flows that must be allowed or blocked -----
#
# PLACEHOLDER: these describe the rtr-us5 test fixture. The real client policy
# will replace them -- that is why the policy lives here as plain data rather
# than being buried in the code. Editing this list should not require
# understanding anything below it.
POLICY: List[Dict[str, Any]] = [
    {
        "description": "DNS lookups to the approved DNS server must be allowed",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {
            "srcIps": "10.10.10.0/24",
            "dstIps": "218.8.104.58",
            "applications": ["dns"],
        },
        "expected": "PERMIT",
        "violation_summary": "DNS to the approved server is blocked, so name lookups will fail",
        "violation_severity": "medium",
    },
    {
        "description": "Plain HTTP to the internal server must be blocked",
        "node": "rtr-us5",
        "filter": "acl_in",
        "headers": {
            "srcIps": "10.10.10.0/24",
            "dstIps": "10.20.0.5",
            "applications": ["http"],
        },
        "expected": "DENY",
        "violation_summary": "Unencrypted web traffic reaches the internal server",
        "violation_severity": "high",
    },
]

# --- 2. Guarantees: whole SPACES of traffic that must never be permitted ----
#
# The difference from POLICY above is the difference between testing and
# proving. A policy statement checks one packet. A guarantee checks every
# packet that fits the description -- every source address in the subnet,
# every source port, all at once. If Batfish returns nothing, no such packet
# exists. That is a proof, not a sample.
GUARANTEES: List[Dict[str, Any]] = [
    {
        "description": "No unencrypted web traffic may be permitted out of the internal subnet",
        "node": "rtr-us5",
        "filter": "acl_in",
        # Deliberately broad: ANY source in the subnet, ANY destination.
        "headers": {"srcIps": "10.10.10.0/24", "applications": ["http"]},
        "violation_summary": "Unencrypted web traffic is allowed out of the internal subnet",
        "violation_severity": "high",
    },
]


def run(bf: Session) -> List[Dict[str, Any]]:
    """Run all four analyses and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    # One shared counter across all four analyses, so every finding gets a
    # unique id (AC-001, AC-002, ...). docs/finding-format.md calls `id` a
    # unique identifier, so anything downstream may rely on it -- duplicates
    # would let a consumer silently drop one of a colliding pair.
    #
    # KNOWN WEAKNESS: these numbers are assigned in discovery order, so a
    # finding's id shifts if an earlier one stops occurring. policy_compliance
    # pins ids to rules instead, which is better and is what would let the
    # dashboard show what changed since the previous run. Worth adopting here.
    numbering = count(1)

    # Which of our statements can this snapshot actually answer?
    #
    # POLICY and GUARANTEES name specific devices. On a snapshot that does not
    # contain them, every statement would report "could not check" -- correct
    # under F-4, but measured at 8 of 9 findings on one fixture and 10 of 10 on
    # a converted PF Sense config. Correct and unusable are not the same thing.
    #
    # So the inapplicable ones are reported ONCE, together, instead of one card
    # each. They are still reported: skipping quietly is the silent omission
    # F-4 exists to prevent, and a device may be absent because someone forgot
    # to upload it.
    present = snapshot.device_names(bf)
    total = len(POLICY) + len(GUARANTEES)
    results: List[Dict[str, Any]] = []

    if present is None:
        # We could not find out what is in this snapshot. Note what this does
        # NOT say: it does not claim the devices are absent, because we have
        # not observed that. Saying so would send a reader looking for a
        # missing device when the real fault was a broken Batfish query -- the
        # same mistake routing.py fixed in 6d7c769, where a hardcoded summary
        # blamed a missing route for what was actually a deny rule.
        policy, guarantees = [], []
        results.append(
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary=(
                    f"{total} access policy statement(s) could not be checked "
                    "against this config"
                ),
                detail=(
                    "The devices present in this snapshot could not be "
                    "determined, so we cannot tell whether these statements "
                    "apply to it. Nothing is claimed about them either way. "
                    "The analyses that need no policy -- dead rules and "
                    "undefined references -- still ran."
                ),
                source="analysis/checks/access_control.py",
                number=next(numbering),
            )
        )
    else:
        policy = [s for s in POLICY if s["node"] in present]
        guarantees = [g for g in GUARANTEES if g["node"] in present]
        absent = sorted(
            {s["node"] for s in POLICY if s["node"] not in present}
            | {g["node"] for g in GUARANTEES if g["node"] not in present}
        )
        if absent:
            skipped = (len(POLICY) - len(policy)) + (len(GUARANTEES) - len(guarantees))
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    # Safe here in a way it is not above: we know what is
                    # present, so naming the missing device is an observation.
                    device=absent[0] if len(absent) == 1 else "unknown",
                    summary=(
                        f"{skipped} access policy statement(s) could not be checked "
                        "against this config"
                    ),
                    detail=(
                        "They are written about "
                        + ", ".join(absent)
                        + ", which "
                        + ("is" if len(absent) == 1 else "are")
                        + " not in this snapshot. Nothing is claimed about them "
                        "either way. The analyses that need no policy -- dead rules "
                        "and undefined references -- still ran."
                    ),
                    source="analysis/checks/access_control.py",
                    number=next(numbering),
                )
            )

    results.extend(_check_policy_statements(bf, numbering, policy))
    results.extend(_check_guarantees(bf, numbering, guarantees))
    results.extend(_check_dead_rules(bf, numbering))
    results.extend(_check_undefined_references(bf, numbering))

    # Only claim "all clear" if every analysis ran AND found nothing. If any
    # produced an error finding, `results` is non-empty and we never get here --
    # which is the point.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=POLICY[0]["node"] if POLICY else "unknown",
                summary="No issues found by access control",
                detail=(
                    f"{len(POLICY)} policy statement(s) hold, {len(GUARANTEES)} "
                    "guarantee(s) proven, no dead rules, no undefined references"
                ),
                source=", ".join(sorted({s["node"] for s in POLICY})),
            )
        ]

    return results


# ---------------------------------------------------------------------------
# 1. Policy statements -- testFilters
# ---------------------------------------------------------------------------


def _check_policy_statements(
    bf: Session, numbering: Iterator[int], statements: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Check each single-flow policy statement with testFilters.

    `statements` is the subset whose devices are in this snapshot -- run()
    filters them, so anything reaching here is genuinely checkable.
    """
    results: List[Dict[str, Any]] = []

    for statement in statements:
        node = statement["node"]
        filter_name = statement["filter"]

        # testFilters answers: for ONE specific packet, does this filter permit
        # or deny it, and WHICH LINE decided? That line is the evidence -- it
        # is what lets us say "blocked by this rule" instead of just "blocked",
        # and it is what the AI layer expands into plain English.
        try:
            frame = (
                bf.q.testFilters(
                    nodes=node,
                    filters=filter_name,
                    # Where the packet enters the device. A filter's behaviour
                    # can depend on the incoming interface, so this matters.
                    startLocation=node,
                    headers=HeaderConstraints(**statement["headers"]),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {statement['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        if frame.empty:
            # The query ran but matched nothing -- usually the node or filter
            # does not exist in this snapshot. Blind, not clean.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {statement['description'].lower()}",
                    detail=(
                        f"Batfish returned no result for filter {filter_name!r} "
                        f"on device {node!r}. Does it exist in this config?"
                    ),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        row = frame.iloc[0]
        actual = row["Action"]

        if actual == statement["expected"]:
            continue  # config agrees with policy -- nothing to report

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=statement["violation_severity"],
                device=node,
                summary=statement["violation_summary"],
                # The evidence is Batfish's own words -- the exact ACL line that
                # decided. We never paraphrase it here; the AI layer does that,
                # grounded in this string.
                detail=(
                    f"Expected {statement['expected']} but got {actual}, "
                    f"decided by: {row['Line_Content']}"
                ),
                # testFilters names the matching LINE but not its line NUMBER,
                # so the best source we can give is device:filter.
                source=f"{node}:{filter_name}",
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 2. Guarantees -- searchFilters  (the strongest capability)
# ---------------------------------------------------------------------------


def _check_guarantees(
    bf: Session, numbering: Iterator[int], guarantees: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Prove that no packet in a whole space is permitted, using searchFilters.

    WHY THIS IS DIFFERENT FROM testFilters
        testFilters asks about one packet. searchFilters asks about every packet
        matching a description -- every address in the subnet, every source
        port -- and returns one that violates the rule, if any exists.

        So an EMPTY result is the interesting one: it means Batfish searched
        the whole space and found no permitted flow. That is a proof the
        guarantee holds, not a sample that happened to pass.

        A returned row is a counter-example: a specific flow that IS permitted
        when it should not be, plus the ACL line responsible.
    """
    results: List[Dict[str, Any]] = []

    for guarantee in guarantees:
        node = guarantee["node"]
        filter_name = guarantee["filter"]

        try:
            frame = (
                bf.q.searchFilters(
                    nodes=node,
                    filters=filter_name,
                    # action="permit" means "search for flows this filter
                    # PERMITS". We expect none, because the guarantee says this
                    # traffic must never be allowed.
                    action="permit",
                    headers=HeaderConstraints(**guarantee["headers"]),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not prove: {guarantee['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{filter_name}",
                    number=next(numbering),
                )
            )
            continue

        if frame.empty:
            # Nothing in the whole space is permitted -- the guarantee holds.
            # No finding: this analysis found no problem.
            continue

        # Batfish found at least one violating flow. Report the first as the
        # counter-example -- one concrete packet is far more useful to a human
        # than "the policy is violated somewhere".
        row = frame.iloc[0]
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=guarantee["violation_severity"],
                device=node,
                summary=guarantee["violation_summary"],
                detail=(
                    f"Example permitted flow: {row['Flow']}, "
                    f"allowed by: {row['Line_Content']}"
                ),
                source=f"{node}:{filter_name}",
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 3. Dead rules -- filterLineReachability
# ---------------------------------------------------------------------------


def _check_dead_rules(bf: Session, numbering: Iterator[int]) -> List[Dict[str, Any]]:
    """Find ACL lines that can never match because an earlier line shadows them.

    WHY THIS MATTERS
        A dead rule is dangerous precisely because it looks fine. Someone reads
        the config, sees "permit HTTPS to the finance server", and believes it
        works. It never fires, because a broader line above it already decided.

        Batfish returns ONE ROW PER UNREACHABLE LINE, naming the blocking
        line(s). An empty result means every line in every ACL can fire.
    """
    try:
        frame = bf.q.filterLineReachability().answer().frame()
    except Exception as error:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                summary="Could not check for dead ACL rules",
                detail=findings.describe_error(error),
                source="filterLineReachability",
                number=next(numbering),
            )
        ]

    results: List[Dict[str, Any]] = []
    for _, row in frame.iterrows():
        # `Sources` looks like ["rtr-us5: acl_in"] -- the device and filter the
        # dead line belongs to. Split it back apart for the finding fields.
        source_text = row["Sources"][0] if len(row["Sources"]) else "unknown: unknown"
        device, _, filter_name = source_text.partition(": ")

        # A dead DENY is worse than a dead PERMIT. A permit that never fires
        # blocks traffic someone wanted (an availability problem). A deny that
        # never fires lets through traffic someone meant to block -- a security
        # hole. Batfish tells us which it is, so we grade accordingly rather
        # than guessing.
        dead_action = row["Unreachable_Line_Action"]
        severity = "high" if dead_action == "DENY" else "medium"

        blocking = ", ".join(row["Blocking_Lines"]) or "an earlier line"
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=severity,
                device=device,
                summary=f"ACL rule never takes effect in {filter_name}",
                detail=(
                    f"Unreachable line: {row['Unreachable_Line']} "
                    f"(action {dead_action}). Blocked by: {blocking}. "
                    f"Reason: {row['Reason']}"
                ),
                source=source_text,
                status="found",
                number=next(numbering),
            )
        )

    return results


# ---------------------------------------------------------------------------
# 4. Undefined references -- undefinedReferences
# ---------------------------------------------------------------------------


def _check_undefined_references(
    bf: Session, numbering: Iterator[int]
) -> List[Dict[str, Any]]:
    """Find config that points at a structure which was never defined.

    WHY THIS MATTERS
        `ip access-group acl_guest_in in` on an interface, with no
        `ip access-list acl_guest_in` anywhere, is a silent failure. The author
        believed they had applied a filter. Depending on the platform the
        traffic may be entirely unfiltered.

        An empty result means every referenced structure exists.
    """
    try:
        frame = bf.q.undefinedReferences().answer().frame()
    except Exception as error:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                summary="Could not check for undefined references",
                detail=findings.describe_error(error),
                source="undefinedReferences",
                number=next(numbering),
            )
        ]

    # undefinedReferences reports the FILE, not the device. Rather than guessing
    # a hostname from the filename, ask Batfish which nodes came from which
    # file -- so `device` stays grounded in real output like everything else.
    file_to_node = _map_files_to_nodes(bf)

    results: List[Dict[str, Any]] = []
    for _, row in frame.iterrows():
        file_name = row["File_Name"]
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                # High: an undefined ACL reference means traffic the author
                # believed was filtered may not be filtered at all.
                severity="high",
                device=file_to_node.get(file_name, "unknown"),
                summary=f"Config refers to {row['Struct_Type']} '{row['Ref_Name']}' which is not defined",
                detail=(
                    f"Referenced as: {row['Context']}. "
                    f"The structure {row['Ref_Name']!r} is never defined in this snapshot."
                ),
                # `Lines` is already in filename:[line] form -- exactly the
                # "filename:line" F-1 asks for.
                source=str(row["Lines"]),
                status="found",
                number=next(numbering),
            )
        )

    return results


def _map_files_to_nodes(bf: Session) -> Dict[str, str]:
    """Map each config file to the device defined in it, using fileParseStatus.

    Returns an empty map on failure -- callers fall back to "unknown", which is
    what F-1 says to use when we cannot tell which device a finding belongs to.
    """
    try:
        frame = bf.q.fileParseStatus().answer().frame()
    except Exception:
        return {}

    mapping: Dict[str, str] = {}
    for _, row in frame.iterrows():
        nodes = row["Nodes"]
        if len(nodes):
            mapping[row["File_Name"]] = nodes[0]
    return mapping
