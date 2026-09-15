"""
Netwise -- routing check (Ankeet's feature).

WHAT THIS CHECK DOES
    It asserts a reachability policy: a list of "traffic from A must (or must
    not) be able to reach B" statements, each proved or disproved against the
    real config with Batfish's traceroute question. This answers the client's
    core question for this feature: "can host A reach host B?", answered
    purely from the config, with the hop-by-hop path as evidence.

WHY traceroute AND NOT THE routes QUESTION
    Both are listed in CLAUDE.md as tools for this feature. `routes` shows
    the routing table Batfish computed; `traceroute` actually walks the path
    hop by hop and reports the outcome. For "does A reach B", traceroute is
    the direct answer -- it proves the property rather than requiring someone
    to read a routing table and infer whether it would work. `routes` is left
    unused here, the same way policy_compliance.py chose one Batfish question
    over another and documented why rather than using both by default.

WHAT COUNTS AS "REACHABLE" -- and why EXITS_NETWORK is deliberately excluded
    pybatfish's own tooling (pybatfish.datamodel.flow._get_color_for_disposition)
    treats three dispositions as success for colouring a trace diagram green:
    ACCEPTED, DELIVERED_TO_SUBNET, and EXITS_NETWORK. This module uses only
    the first two.

    DELIVERED_TO_SUBNET is included on purpose. Measured directly against a
    real two-router fixture (see tests/fixtures/routing-secure): traceroute
    between two LANs connected over a WAN link reports DELIVERED_TO_SUBNET,
    not ACCEPTED -- ACCEPTED requires the destination IP to be a device's own
    interface address, which a plain host address on a LAN never is. Treating
    DELIVERED_TO_SUBNET as failure would make every ordinary LAN-to-LAN route
    look broken.

    EXITS_NETWORK is excluded on purpose, and this was found by independent
    review, not anticipated up front. It means "forwarded toward a next hop
    Batfish has no model of at all" -- which sounds like a reasonable thing to
    call success for a flow headed to the real internet, but every ROUTES
    statement below names a SPECIFIC destination NODE that is meant to exist
    in this snapshot. Measured: deleting rtr-branch.cfg from routing-secure
    entirely and re-running the HQ -> branch statement reports EXITS_NETWORK,
    not an error. If EXITS_NETWORK counted as success, a whole device missing
    from the upload -- a real, plausible mistake -- would be reported as a
    clean, working route, which is exactly the false "none" F-4 exists to
    prevent. Excluding it means that case instead surfaces as a genuine
    finding (or, if the OTHER statement in ROUTES also references the missing
    node directly, as the status="error" the empty-frame branch below already
    produces).

DOES THIS CHECK HAVE THE SAME TRAP policy_compliance.py DOCUMENTS?
    policy_compliance.py's docstring warns that reachability/traceroute-style
    questions can give a false "policy holds" reading: rtr-us5 has no route to
    10.20.0.5, so `reachability` reports zero successful flows for a ROUTING
    reason, not a policy one, and a check reading "empty means clean" would
    put a green tick on a config that permits everything. Raised as a
    question worth checking here too, since this module is traceroute-based.

    Checked directly: no, not the same way, because this check's whole
    purpose is routing correctness itself, so NO_ROUTE is never read as
    success here -- it is excluded from SUCCESS_DISPOSITIONS deliberately
    (see above), and a REACHABLE statement that hits it is reported as
    status="found", not "none". There is no false "all clear" in that
    direction.

    Checking it did surface a smaller, related issue, fixed in the same
    session it was raised: each ROUTES statement's violation_summary
    originally asserted a specific cause ("a route appears to be missing")
    regardless of what actually went wrong. Verified live with a constructed
    scenario (a route present but blocked by an outbound ACL) that traceroute
    reports DENIED_OUT, a genuinely different disposition from NO_ROUTE --
    both are correctly classified as failures by SUCCESS_DISPOSITIONS, so the
    status is never wrong, but the old summary text would have blamed a
    missing route even when the real cause was a deny rule. Fixed by making
    violation_summary state the observed effect ("cannot reach") rather than
    an assumed cause; evidence.detail already carries the real disposition
    Batfish reported, which is where a specific cause belongs.

THE rtr-us5 FIXTURES DO NOT WORK FOR THIS CHECK
    Both existing rtr-us5 fixtures (tests/fixtures/rtr-us5-secure,
    rtr-us5-insecure) have exactly one interface and no route beyond the
    router itself. Measured: traceroute to 10.20.0.5 from either fixture
    reports NO_ROUTE regardless of what the ACL says, because there is
    nothing past the router to route to. A routing check that ran only
    against those fixtures could never demonstrate a genuine successful
    result, so this check uses a dedicated fixture pair instead:
    tests/fixtures/routing-secure (both directions reachable) and
    tests/fixtures/routing-missing-route (one direction broken by a missing
    static route). See those fixtures' own comments for the topology.

HOW IT DECIDES WHAT TO REPORT
    Each statement declares "expected": "REACHABLE" or "UNREACHABLE". Both
    are implemented -- an earlier version of this module documented
    UNREACHABLE as the way to express a deliberately isolated segment but
    never actually handled it, which meant using it silently produced a
    false status="none" instead of evaluating anything. Fixed: see
    _evaluate() below, and tests/test_routing_classification.py, which
    regression-tests both this and the EXITS_NETWORK case directly.

      - "REACHABLE"   holds only if EVERY trace succeeds. A flow can take
                       more than one path (equal-cost routes), and a real
                       packet could take any of them, so one failing path
                       among several is a genuine partial defect.
      - "UNREACHABLE" holds only if EVERY trace fails. Mirrors searchFilters'
                       "no packet in this whole space" reasoning in
                       policy_compliance.py: even one path getting through
                       when none should is a leak, not noise.
      - Batfish could not answer at all -> status="error", we are blind here.

    If every statement was checked and all held -> a single status="none".
    NO_ROUTE is not automatically a finding and an empty query result is not
    automatically "clean" -- see F-4 in docs/finding-format.md.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import policy as policy_module
from analysis import findings, snapshot

# The name this check is registered under, and the value in every "check" field.
CHECK_NAME = "routing"

# The id for the one card reported when route statements do not apply to this
# snapshot. It needs a number of its own because ROUTES numbers are PINNED to a
# statement (RT-001 is always the HQ -> branch assertion), so borrowing one
# would make an id mean different things depending on what was uploaded.
#
# 50 deliberately matches policy_compliance.py's PC-050, so RT-050 and PC-050
# carry the same meaning in every check that has one: "these rules do not apply
# to this snapshot, or we could not tell". Statements are numbered from 1 and
# there are two of them, so nothing else can land here -- asserted by
# tests/test_device_scoping.py rather than left as an assumption.
SKIPPED_NUMBER = 50

#: RT-051: a supplied policy this check does not read (#196).
#: Clear of the route numbers (1..N) and of SKIPPED_NUMBER above. A DIFFERENT
#: fact from 50: that one says "your snapshot lacks the device our assertions
#: name", this one says "you gave us assertions and we did not read them".
UNREAD_POLICY_NUMBER = 51

# See the "WHAT COUNTS AS REACHABLE" section of the module docstring for why
# this is NOT the same set pybatfish's own tooling treats as success.
SUCCESS_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET"}

# --- The reachability policy being asserted ---------------------------------
#
# PLACEHOLDER: these statements describe the routing-secure / routing-missing-
# route test fixtures. The real client topology will replace them -- kept as
# plain data, same as POLICY in access_control.py and POLICY_RULES in
# policy_compliance.py, so editing the intent list doesn't require reading
# the code below it.
#
# "number" is PINNED to the statement, not assigned by discovery order. IDs
# stay stable across runs this way (RT-001 is always this statement), which
# access_control.py's own comments flag as the better approach it doesn't yet
# use itself -- adopted here from the start rather than copied as a known
# weakness.
#
# node names two devices that only exist in the routing fixtures: rtr-hq
# and rtr-branch. Any snapshot without them -- every single-router config, and
# every snapshot a user uploads through the dashboard -- used to make Batfish
# fail the query, so BOTH statements came back status="error" ("Work terminated
# abnormally"), one amber card each, about a config they had nothing to do with.
#
# FIXED (#29). run() below now asks which devices are actually in the snapshot
# and reports the inapplicable statements ONCE, together, as a single card that
# says so plainly. The open question this module recorded -- does a skipped
# statement count as checked? -- was answered by access_control.py (#45) and
# policy_compliance.py (#50) while this comment sat here: it does not. It is an
# error, never a "none". Nothing is skipped silently.
#
# RENAMED from "start_node" to "node" (#159, decision D1). access_control.py
# and policy_compliance.py already used "node"; this was the one holdout, and
# the mismatch is exactly what would let a user-supplied policy file type
# "node:" under a route statement and get silence instead of an error. Pure
# rename -- nothing about how routes are evaluated changes.
ROUTES: List[Dict[str, Any]] = [
    {
        "number": 1,  # RT-001
        "description": "The HQ LAN must be able to reach the branch LAN",
        "node": "rtr-hq",
        "src_ip": "10.10.10.5",
        "dst_ip": "10.20.20.5",
        "expected": "REACHABLE",
        "violation_summary": "The HQ network cannot reach the branch network",
        "violation_severity": "high",
    },
    {
        "number": 2,  # RT-002
        "description": "The branch LAN must be able to reach the HQ LAN",
        "node": "rtr-branch",
        "src_ip": "10.20.20.5",
        "dst_ip": "10.10.10.5",
        "expected": "REACHABLE",
        "violation_summary": "The branch network cannot reach the HQ network",
        "violation_severity": "high",
    },
]


# --- Whose route assertions are we checking? (#87 / #319) -------------------

BUILTIN_POLICY_LABEL = (
    "Netwise's built-in example policy (analysis/checks/routing.py) "
    "-- no policy file was supplied"
)
USER_POLICY_LABEL = "the policy file you supplied"


def routes_in_use() -> Tuple[List[Dict[str, Any]], str, bool]:
    """The route assertions this run should check, and where they came from.

    THE LAST OF THE THREE (#87)
        `policy_compliance` learned this in #181, `access_control` in #316,
        and this is the third. With it, every section `analysis/policy.py`
        validates is read by the check that owns it, which is what #87 asked
        for.

    THE THREE STATES, WHICH ARE NOT TWO
        no policy supplied      -> ROUTES below, LABELLED as ours
        policy with entries     -> the user's assertions
        policy with NO entries  -> the user's (empty) policy, NOT ours

        Keyed on `active_policy() is None`, never on emptiness -- the same
        rule as the other two checks, and for the same reason. An empty
        routing section means "I assert nothing about reachability", which
        is a different claim from "I gave you no policy". Falling back to
        ours there would check assertions about rtr-hq and rtr-branch that
        the user explicitly declined to make, and label them as theirs.

    WHY `number` IS NOT REQUIRED OF THE USER
        ROUTES pins `number` to the statement so ids stay stable across
        runs -- RT-001 is always the same assertion. A user's file may omit
        it; `_assign_missing_numbers()` supplies one and records it in
        `Policy.assigned`, so the value is reported rather than silent.
        That is why `number` is absent from `_SECTION_REQUIRED["routing"]`
        while the five keys this check actually dereferences are present.
    """
    active = policy_module.active_policy()
    if active is None:
        return ROUTES, BUILTIN_POLICY_LABEL, False
    return active.entries_for(CHECK_NAME), USER_POLICY_LABEL, True


def _evaluate(expected: str, traces: Sequence[Any]) -> Optional[str]:
    """Classify one route statement's traces against what was expected.

    Returns None if the statement holds, or a one-line description of the
    violation if it does not.

    A PURE function on purpose: it takes plain disposition-and-hops objects,
    not a live Batfish session, so it can be unit tested directly without
    Docker or Batfish. See tests/test_routing_classification.py, which
    exercises both branches and specifically regression-tests the
    EXITS_NETWORK case described in the module docstring.
    """
    successes = [t for t in traces if t.disposition in SUCCESS_DISPOSITIONS]
    failures = [t for t in traces if t.disposition not in SUCCESS_DISPOSITIONS]
    multi = len(traces) > 1

    if expected == "REACHABLE":
        if not failures:
            return None
        bad = failures[0]
        hops = " -> ".join(hop.node for hop in bad.hops) or "?"
        detail = f"traceroute ended in {bad.disposition}. Path: {hops}"
        if multi:
            detail += f" ({len(failures)} of {len(traces)} paths failed)"
        return detail

    if expected == "UNREACHABLE":
        if not successes:
            return None
        bad = successes[0]
        hops = " -> ".join(hop.node for hop in bad.hops) or "?"
        detail = f"traceroute unexpectedly succeeded: {bad.disposition}. Path: {hops}"
        if multi:
            detail += f" ({len(successes)} of {len(traces)} paths succeeded)"
        return detail

    # A statement with anything else in "expected" is a bug in ROUTES, not a
    # runtime condition -- raising here means run() surfaces it through the
    # pipeline's own crash-isolation as a status="error" finding (see
    # run_check() in analysis/pipeline.py) rather than silently doing nothing,
    # which is exactly the failure this function exists to replace.
    raise ValueError(f"route 'expected' must be REACHABLE or UNREACHABLE, got {expected!r}")


def run(bf: Session) -> List[Dict[str, Any]]:
    """Check every route statement and return F-1 findings.

    The pipeline has already connected to Batfish and loaded the snapshot, so
    this function only has to ask questions and shape the answers.
    """
    results: List[Dict[str, Any]] = []

    # WHOSE assertions? (#319) Resolved once, here, so every branch below
    # agrees. `routes` replaces the module-level ROUTES everywhere in this
    # function; ROUTES is now only the fallback routes_in_use() may return.
    routes, policy_label, user_supplied = routes_in_use()

    # THE "WE DID NOT READ YOUR RULES" CARD IS GONE, BECAUSE WE NOW DO.
    #
    # #196 added an RT-050 saying "N supplied route assertion(s) were not
    # read", and this module's comment said it "goes away when this check
    # learns to read a policy properly". It has, so it does. Leaving it
    # would be a check reporting a limitation it no longer has -- the same
    # class of stale claim as the documents this project keeps correcting,
    # arriving through a finding instead of a paragraph.
    #
    # An empty routing section is still reported, loudly, just below: that
    # is a different statement and it is still true.
    if user_supplied and not routes:
        results.append(
            findings.no_issues_finding(
                check=CHECK_NAME,
                device="n/a",
                summary="No route assertions to check",
                detail=(
                    "Your policy file has no routing entries, so nothing was "
                    "asserted about which networks must reach which. This is "
                    "not a problem with the config -- it is what an empty "
                    "section means."
                ),
                source=policy_label,
                number=UNREAD_POLICY_NUMBER,
            )
        )
        return results

    # --- Scope the statements to the devices actually in this snapshot -------
    #
    # Every statement in ROUTES names a specific node. On a snapshot that
    # does not contain it, Batfish fails the query and each statement returns
    # its own "could not check" card -- correct under F-4, but on an ordinary
    # single-router upload that was every card the routing check produced.
    #
    # They are still reported, once, together. Skipping quietly is the silent
    # omission F-4 exists to prevent: a device may be absent because someone
    # forgot to upload it, and that is worth saying out loud.
    #
    # This adopts the shape established in access_control.py (#45) and
    # policy_compliance.py (#50). The question those two answered -- does a
    # skipped statement count as checked? -- is settled the same way here: no.
    # It is an error, never a "none".
    present = snapshot.device_names(bf)

    if present is None:
        # We could not find out what is in this snapshot. Note what this does
        # NOT say: it does not claim the devices are absent, because we have not
        # observed that. Claiming it would send a reader hunting for a router
        # that was never missing -- the same mistake this module's own
        # violation_summary made before 6d7c769, blaming an absent route for
        # what was actually a deny rule.
        return [
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary=(
                    f"{len(routes)} route assertion(s) could not be checked "
                    "against this config"
                ),
                detail=(
                    "The devices present in this snapshot could not be "
                    "determined, so we cannot tell whether these assertions "
                    "apply to it. Nothing is claimed about them either way."
                ),
                source="analysis/checks/routing.py",
                number=SKIPPED_NUMBER,
            )
        ]

    applicable = [r for r in routes if r["node"] in present]
    absent = sorted({r["node"] for r in routes if r["node"] not in present})
    if absent:
        results.append(
            findings.error_finding(
                check=CHECK_NAME,
                # Safe here in a way it is not above: we know what is present,
                # so naming what is missing is an observation, not a guess.
                device=absent[0] if len(absent) == 1 else "unknown",
                summary=(
                    f"{len(routes) - len(applicable)} route assertion(s) could "
                    "not be checked against this config"
                ),
                detail=(
                    "They are written about "
                    + ", ".join(absent)
                    + ", which "
                    + ("is" if len(absent) == 1 else "are")
                    + " not in this snapshot. Nothing is claimed about them "
                    "either way."
                ),
                source="analysis/checks/routing.py",
                number=SKIPPED_NUMBER,
            )
        )

    for route in applicable:
        node = route["node"]

        # traceroute answers: starting from THIS node, with THESE headers,
        # where does the packet end up, hop by hop? Unlike testFilters it
        # does not need a filter name -- it walks the whole path, ACLs
        # included, and reports how the flow was finally disposed of.
        try:
            frame = (
                bf.q.traceroute(
                    startLocation=node,
                    headers=HeaderConstraints(
                        srcIps=route["src_ip"], dstIps=route["dst_ip"]
                    ),
                )
                .answer()
                .frame()
            )
        except Exception as error:
            # Could not ask the question at all -- a bad node name, a
            # malformed header. We are blind for this statement, so it is an
            # error, NOT a clean result.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {route['description'].lower()}",
                    detail=findings.describe_error(error),
                    source=f"{node}:{route['dst_ip']}",
                    number=route["number"],
                )
            )
            continue

        if frame.empty:
            # The query ran but matched nothing -- usually the node does not
            # exist in this snapshot. Blind, not clean.
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=node,
                    summary=f"Could not check: {route['description'].lower()}",
                    detail=(
                        f"Batfish returned no result starting from node "
                        f"{node!r}. Does it exist in this config?"
                    ),
                    source=f"{node}:{route['dst_ip']}",
                    number=route["number"],
                )
            )
            continue

        row = frame.iloc[0]
        violation = _evaluate(route["expected"], row["Traces"])

        if violation is None:
            # The statement holds. Nothing to report.
            continue

        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=route["violation_severity"],
                device=node,
                summary=route["violation_summary"],
                # The evidence is Batfish's own words -- the disposition it
                # actually reached and the path it took to get there. We
                # never paraphrase it here; the AI layer does that, grounded
                # in this string.
                detail=(
                    f"Expected {route['expected']} for a flow from "
                    f"{route['src_ip']} to {route['dst_ip']}, but {violation}"
                ),
                source=f"{node}:{route['dst_ip']}",
                status="found",
                number=route["number"],
            )
        )

    # Only claim "all clear" if we actually checked everything successfully.
    #
    # `applicable`, not ROUTES: this must count what actually ran. Any skipped
    # statement has already put an error card in `results`, so this branch
    # cannot currently be reached with applicable empty -- but a sentence
    # claiming "all 2 assertions hold" when none of them ran would be wrong the
    # day that stops being true, and it is the kind of wrong nobody re-reads.
    if not results:
        return [
            findings.no_issues_finding(
                check=CHECK_NAME,
                device=applicable[0]["node"] if applicable else "unknown",
                summary="No issues found by routing",
                detail=f"All {len(applicable)} route assertion(s) hold",
                source=", ".join(sorted({r["node"] for r in applicable}))
                or "unknown",
            )
        ]

    return results
