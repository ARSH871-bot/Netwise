"""Which parts of my network does no policy rule talk about? (#421)

WHY THIS EXISTS
    PC-049 (#228/#229, #366) already reports devices no rule covers. That is
    too coarse: a router can be "covered" by one rule about one subnet while
    three of its four interfaces carry traffic no rule mentions. This goes
    one level down, to each interface and the subnet on it.

WHAT "COVERED" MEANS HERE
    A subnet is covered when some policy_compliance rule's source or
    destination overlaps it -- the rule says something about traffic from or
    to that subnet. A query with no address constraint talks about all
    traffic, so it covers every subnet.

    Only rules about a device that IS in the snapshot count. A rule about a
    missing device never runs (PC-050), so it covers nothing, however its
    addresses read.

THREE ANSWERS, AS EVERYWHERE ELSE IN THIS POLICY CODE
    covered     some rule provably overlaps the subnet
    uncovered   no rule does
    unknown     no rule provably does, and at least one uses address syntax
                analysis/policy_conflicts does not parse -- so it might

    And a device whose interfaces Batfish cannot list is UNKNOWN, never
    covered. An uncovered subnet is coverage information, not a violation:
    nothing here says the network is wrong, only where the policy is silent.

    Drawing the map is the dashboard's job; this returns the data.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Sequence, Set

from analysis.policy_conflicts import _Undecidable, _networks


def interfaces(bf: Any) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """{device: [{interface, subnet, active}]} from Batfish, or None if unreadable.

    Subnets are the NETWORK of each interface address (10.10.10.1/24 ->
    10.10.10.0/24), because that is what a rule's addresses are compared with.
    """
    frame = bf.q.interfaceProperties(properties="All_Prefixes,Active").answer().frame()
    out: Dict[str, List[Dict[str, Any]]] = {}
    for _, row in frame.iterrows():
        iface = row["Interface"]
        for prefix in row["All_Prefixes"] or []:
            out.setdefault(str(iface.hostname), []).append({
                "interface": str(iface.interface),
                "subnet": ipaddress.ip_interface(str(prefix)).network,
                "active": bool(row["Active"]),
            })
    return out


def _touches(rule: Dict[str, Any], subnet: Any) -> Optional[bool]:
    """Does this rule's source or destination overlap `subnet`? True/False/None."""
    unsure = False
    for query in rule.get("queries", []) or []:
        if not isinstance(query, dict):
            unsure = True
            continue
        if "srcIps" not in query or "dstIps" not in query:
            return True                   # an unconstrained side talks about everything
        for field in ("srcIps", "dstIps"):
            try:
                if any(net.overlaps(subnet) for net in _networks(field, query[field])):
                    return True
            except _Undecidable:
                unsure = True
    return None if unsure else False


def coverage_map(rules: Sequence[Dict[str, Any]],
                 by_device: Optional[Dict[str, List[Dict[str, Any]]]],
                 devices: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """One row per interface subnet, saying whether any rule talks about it.

    `devices` is every device in the snapshot. A device in it whose interfaces
    could not be read gets one row with `covered` None -- unknown, not covered.
    """
    present = set(devices or []) | set(by_device or {})
    live_rules = [r for r in rules if r.get("node") in present]
    rows: List[Dict[str, Any]] = []
    for device in sorted(present):
        listed = (by_device or {}).get(device)
        if not listed:
            rows.append({"device": device, "interface": None, "subnet": None, "active": None,
                         "covered": None, "rules": [], "unsure": [],
                         "reason": "Batfish listed no addressed interfaces for this device"})
            continue
        for entry in listed:
            sure, unsure = [], []
            for rule in live_rules:
                verdict = _touches(rule, entry["subnet"])
                if verdict is True:
                    sure.append(rule.get("number"))
                elif verdict is None:
                    unsure.append(rule.get("number"))
            rows.append({"device": device, "interface": entry["interface"],
                         "subnet": str(entry["subnet"]), "active": entry["active"],
                         "covered": True if sure else (None if unsure else False),
                         "rules": sure, "unsure": unsure, "reason": ""})
    return rows


def summary(rows: Sequence[Dict[str, Any]]) -> str:
    known = [r for r in rows if r["subnet"]]
    covered = sum(1 for r in known if r["covered"] is True)
    unknown = sum(1 for r in rows if r["covered"] is None)
    text = f"{covered} of {len(known)} interface subnet(s) are covered by a policy rule"
    if unknown:
        text += f"; {unknown} could not be decided"
    return text


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m analysis.policy_coverage <config-dir> [policy.json]`"""
    import sys
    from pathlib import Path

    from analysis import snapshot
    from analysis.checks import policy_compliance as pc
    from analysis.pipeline import connect, load_snapshot
    from analysis.policy import PolicyError, load_policy_file

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2):
        print("usage: python -m analysis.policy_coverage <config-dir> [policy.json]")
        return 2
    rules = pc.POLICY_RULES
    if len(args) == 2:
        try:
            rules = load_policy_file(args[1]).entries_for("policy_compliance")
        except PolicyError as error:
            print(f"{args[1]}: not loaded -- {error}")
            return 2
    bf = connect(None)
    load_snapshot(bf, Path(args[0]), "netwise-coverage", "snapshot")
    try:
        by_device = interfaces(bf)
    except Exception as error:   # noqa: BLE001 -- said, not swallowed
        print(f"could not list interfaces, so coverage is unknown: {error}")
        by_device = None
    rows = coverage_map(rules, by_device, snapshot.device_names(bf))
    label = {True: "covered", False: "UNCOVERED", None: "unknown"}
    for r in rows:
        who = (f"rule(s) {', '.join(map(str, r['rules']))}" if r["rules"]
               else (f"maybe rule(s) {', '.join(map(str, r['unsure']))}" if r["unsure"] else r["reason"]))
        print(f"  {r['device']:<12} {str(r['interface'] or '-'):<22} {str(r['subnet'] or '-'):<18} "
              f"{label[r['covered']]:<10} {who}")
    print(summary(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
