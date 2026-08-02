"""
Netwise -- access-control check (Arsh's feature).

>>> THIS FILE IS THE TEMPLATE. Ankeet, Shubham, Samika: copy its shape. <<<

    A check is one Python file with one function:

        def run(bf: Session) -> list[dict]

    It receives a live Batfish session with the snapshot already loaded, and
    returns a list of findings built with analysis.findings. That is the whole
    contract. The pipeline handles connecting, loading, and catching your
    mistakes -- you only write the analysis.

WHAT THIS CHECK DOES
    It asserts an access policy: a list of "this traffic must be allowed" and
    "this traffic must be blocked" statements, each checked against the real
    config with Batfish's testFilters question.

    This grew out of US-5, which ran the same two queries and printed them.
    Printing is fine for a proof; the product needs findings, so the same logic
    now RETURNS F-1 findings instead.

HOW IT DECIDES WHAT TO REPORT
    For each policy statement:
      - Batfish agrees with the policy   -> nothing to report
      - Batfish disagrees                -> status="found", a real violation
      - Batfish could not answer         -> status="error", we are blind here
    If every statement was checked and all held -> a single status="none".

    That last distinction matters. If the router does not exist, or the ACL was
    renamed, we must NOT report "all clear" -- we never actually checked. See
    F-4 in docs/finding-format.md.
"""

from typing import Any, Dict, List

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings

# The name this check is registered under, and the value that goes in every
# finding's "check" field.
CHECK_NAME = "access_control"

# --- The access policy being asserted --------------------------------------
#
# PLACEHOLDER: these statements describe the rtr-us5 test fixture. The real
# client policy will replace them -- that is a later user story, and it is why
# the policy lives here as plain data rather than being buried in the code.
# Editing this list should not require understanding anything below it.
#
# Each statement says: "a packet like THIS must be <expected> by <filter>".
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
        # What to tell the user if this statement is violated, and how bad it is.
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


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every policy statement and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    results: List[Dict[str, Any]] = []

    # Sequence numbers for the IDs (AC-001, AC-002 ...). Violations and errors
    # are numbered separately so no two findings share an id.
    violation_number = 0
    error_number = 0

    for statement in POLICY:
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
            # Could not ask the question at all -- a bad node name, a renamed
            # ACL, an invalid header. We are blind for this statement, so it is
            # an error, NOT a clean result.
            error_number += 1
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {statement['description'].lower()}",
                    detail=f"Batfish could not answer this query: {error}",
                    source=f"{node}:{filter_name}",
                    number=error_number,
                )
            )
            continue

        if frame.empty:
            # The query ran but matched nothing -- usually the node or filter
            # does not exist in this snapshot. Again: blind, not clean.
            error_number += 1
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
                    number=error_number,
                )
            )
            continue

        row = frame.iloc[0]
        actual = row["Action"]
        matched_line = row["Line_Content"]

        if actual == statement["expected"]:
            # The config agrees with the policy. Nothing to report.
            continue

        # The config disagrees with the policy: a real finding.
        violation_number += 1
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
                    f"decided by: {matched_line}"
                ),
                # testFilters names the matching LINE but not its line NUMBER,
                # so the best source we can give is device:filter.
                source=f"{node}:{filter_name}",
                status="found",
                number=violation_number,
            )
        )

    # Only claim "all clear" if we actually checked everything successfully.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=POLICY[0]["node"] if POLICY else "unknown",
                summary="No issues found by access control",
                detail=f"All {len(POLICY)} access policy statement(s) hold",
                source=", ".join(sorted({s["node"] for s in POLICY})),
            )
        ]

    return results
