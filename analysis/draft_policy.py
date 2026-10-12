"""Draft a policy from the user's own config (#326, US-34).

WHY THIS EXISTS
    A user who supplies no policy gets our built-in example rules, which name
    our fixture's devices and so mostly report "could not check" on anyone
    else's network (#87). The blank page is the main reason nobody writes
    one. This gives them a starting point made from their own config.

WHAT IT PRODUCES
    One `policy_compliance` rule per line of every filter applied to an
    interface. A permit line becomes a rule about the traffic that line
    allows today; a deny line, the traffic it blocks. Each rule:

      - copies the line's traffic (addresses, protocols, ports) exactly, and
        refuses the line rather than approximating anything it cannot copy;
      - cites the file and line it came from, as Batfish reports them;
      - leaves both judgements -- must this stay allowed or blocked, and how
        serious would a violation be -- as `<FILL IN ...>` values.

WHY EVERY RULE IS CHECKED BEFORE IT IS WRITTEN DOWN
    A line's text is not what the filter does to that line's traffic. On
    rtr-us5-messy the second line says `permit udp ... eq domain`, and the
    first line has already denied all of it. A rule copied from the text
    would say DNS is allowed; the filter blocks it.

    So each drafted rule is put to Batfish with the SAME question
    `policy_compliance` will ask of it later (ACTION_BY_KIND), against the
    config it came from. Empty means the rule holds for every packet it
    describes. Anything else means an earlier line decides part of that
    traffic, and the line is listed as not drafted, with Batfish's own
    example packet and the line that decided it. That is the "refuses where
    the config is ambiguous" criterion, measured rather than inferred.

WHY THE JUDGEMENTS ARE LEFT BLANK
    Everything in a draft is true of the config today. Accepted unedited it
    is a policy saying "the config should do what it does", which passes on
    every config ever written, the insecure one included -- a green tick
    that means nothing. `analysis.policy` refuses the file until every
    `<FILL IN ...>` is replaced and the top-level `draft` block is deleted.

WHAT IT DOES NOT DRAFT
    `access_control` and `routing` rules. Both state intent about a single
    flow or a path, and no config line records that. The draft says so.

Run it from the repository root:

    python -m analysis.draft_policy tests/fixtures/rtr-us5-secure --out draft.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings, pipeline
from analysis.checks import policy_compliance
from analysis.policy import DRAFT_KEY, PLACEHOLDER_PREFIX

#: What a line's action says about its traffic today, as a policy_compliance
#: kind: a permit line's traffic is allowed ("requirement"), a deny line's is
#: blocked ("prohibition"). Used only to CHECK the rule; the user chooses.
_KIND_TODAY = {"PERMIT": "requirement", "DENY": "prohibition"}

#: The header fields a drafted rule copies. A line matching on anything else
#: (TCP flags, ICMP types, packet length...) is refused, because a rule without
#: that condition would describe more traffic than the line does.
_IP_FIELDS = ("srcIps", "dstIps")
_PORT_FIELDS = ("srcPorts", "dstPorts")
_COPIED_FIELDS = frozenset(_IP_FIELDS + _PORT_FIELDS + ("ipProtocols", "negate"))

#: Batfish's IP-space classes that are one address or prefix, and the key that
#: holds it. Anything else -- an object-group reference, a set, a difference --
#: would have to be expanded by us, which is guessing.
_IP_SPACE_VALUE = {"IpWildcardIpSpace": "ipWildcard", "PrefixIpSpace": "prefix", "IpIpSpace": "ip"}


def _short(class_name: Any) -> str:
    """`org.batfish.datamodel.acl.MatchHeaderSpace` -> `MatchHeaderSpace`."""
    return str(class_name).rsplit(".", 1)[-1]


def _ip_space(space: Any) -> Tuple[Optional[str], Optional[str]]:
    """One of a line's address fields as a header string, or why it cannot be."""
    kind = _short(space.get("class", "")) if isinstance(space, dict) else type(space).__name__
    if kind == "UniverseIpSpace":
        return "0.0.0.0/0", None
    key = _IP_SPACE_VALUE.get(kind)
    if key is None:
        return None, (f"it matches addresses through a {kind}, which a rule cannot "
                      f"write down without guessing what it contains")
    value = str(space.get(key, ""))
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None, (f"its address {value!r} is not one address or prefix "
                      f"(a non-contiguous wildcard mask cannot be written as one)")
    return value, None


def _ports(ranges: List[Any]) -> Tuple[Optional[str], Optional[str]]:
    """Batfish's ["53-53", "1024-2048"] as the header string "53,1024-2048"."""
    parts = []
    for item in ranges:
        match = re.fullmatch(r"(\d+)-(\d+)", str(item))
        if not match:
            return None, f"its port range {item!r} is not in a form this draft can copy"
        low, high = match.groups()
        parts.append(low if low == high else f"{low}-{high}")
    return ",".join(parts), None


def _headers_for(line: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The traffic one ACL line matches, as searchFilters headers.

    Returns (headers, None), or (None, the reason it cannot be copied
    exactly). Never a narrower or wider approximation: a rule describing
    different traffic from its line would be cited to a line it misstates.
    """
    line_class = _short(line.get("class", ""))
    if line_class != "ExprAclLine":
        return None, f"it is an {line_class}, not a line that matches traffic itself"

    match = line.get("matchCondition") or {}
    match_class = _short(match.get("class", ""))
    if match_class == "TrueExpr":
        return {}, None  # matches every packet, e.g. a Juniper term with no `from`
    if match_class != "MatchHeaderSpace":
        return None, (f"its match ({match_class}) is not a plain match on addresses, "
                      f"protocols and ports, so writing it as a rule would mean guessing")

    space = match.get("headerSpace") or {}
    if space.get("negate"):
        return None, ("it matches every packet EXCEPT the ones it names (negate), "
                      "which a rule cannot write down exactly")
    extra = sorted(k for k, v in space.items() if k not in _COPIED_FIELDS and v not in (None, [], {}))
    if extra:
        return None, (f"it also matches on {', '.join(extra)}, which a drafted rule "
                      f"cannot copy, so the rule would describe more traffic than the line")

    headers: Dict[str, Any] = {}
    for field in _IP_FIELDS:
        if field in space:
            value, reason = _ip_space(space[field])
            if reason:
                return None, reason
            headers[field] = value
    if space.get("ipProtocols"):
        headers["ipProtocols"] = [str(p).lower() for p in space["ipProtocols"]]
    for field in _PORT_FIELDS:
        if space.get(field):
            value, reason = _ports(space[field])
            if reason:
                return None, reason
            headers[field] = value
    return headers, None


def _unreadable(bf: Session) -> Tuple[Set[str], List[str]]:
    """Devices to draft nothing from, and a note per file Batfish did not fully read.

    A line Batfish did not parse is missing from its model. A rule checked
    against that model could hold there and not on the device, so nothing is
    drafted from a partly read file -- the same caution #373 applies to
    unused filters.
    """
    frame = bf.q.fileParseStatus().answer().frame()
    if frame.empty:
        return set(), ["Batfish found no configuration files to read, so nothing could be drafted."]
    nodes: Set[str] = set()
    notes: List[str] = []
    for _, row in frame.iterrows():
        if row["Status"] == "PASSED":
            continue
        nodes.update(str(n) for n in (row.get("Nodes") or []))
        notes.append(
            f"{row['File_Name']} ({row['Status']}): Batfish could not read every line "
            f"of this file, so a rule drafted from it could describe a filter the "
            f"device does not have. Nothing was drafted from it."
        )
    return nodes, notes


def _applied(bf: Session) -> Set[Tuple[str, str]]:
    """Every (device, filter) applied to an interface, in either direction."""
    frame = bf.q.interfaceProperties(
        properties="Incoming_Filter_Name,Outgoing_Filter_Name"
    ).answer().frame()
    applied: Set[Tuple[str, str]] = set()
    for _, row in frame.iterrows():
        node = getattr(row["Interface"], "hostname", None)
        for column in ("Incoming_Filter_Name", "Outgoing_Filter_Name"):
            name = row[column]
            if node and isinstance(name, str) and name:
                applied.add((str(node), name))
    return applied


def _citations(bf: Session) -> Dict[Tuple[str, str, str], str]:
    """(file, structure type, structure name) -> "file:[line numbers]".

    Joined to a line through the `vendorStructureId` Batfish attaches to it,
    so the citation is Batfish's own record of where the line is -- never a
    search of the file's text by us.
    """
    frame = bf.q.definedStructures().answer().frame()
    cites: Dict[Tuple[str, str, str], str] = {}
    for _, row in frame.iterrows():
        source = row["Source_Lines"]
        filename = getattr(source, "filename", None)
        if filename:
            cites[(filename, str(row["Structure_Type"]), str(row["Structure_Name"]))] = str(source)
    return cites


def _cite(line: Dict[str, Any], cites: Dict[Tuple[str, str, str], str]) -> Optional[str]:
    vendor_id = line.get("vendorStructureId") or {}
    return cites.get((vendor_id.get("filename"), vendor_id.get("structureType"),
                      vendor_id.get("structureName")))


def _counter_example(bf: Session, node: str, name: str, kind: str,
                     headers: Dict[str, Any]) -> Optional[str]:
    """None if the rule holds for every packet it describes, else Batfish's example.

    The same searchFilters question policy_compliance will ask of the rule
    once the user adopts it, so "the draft holds today" and "the check
    passes today" cannot disagree.
    """
    frame = bf.q.searchFilters(
        nodes=node,
        filters=name,
        action=policy_compliance.ACTION_BY_KIND[kind],
        headers=HeaderConstraints(**headers),
    ).answer().frame()
    if frame.empty:
        return None
    row = frame.iloc[0]
    decided = {"PERMIT": "PERMITTED", "DENY": "DENIED"}.get(str(row["Action"]), str(row["Action"]))
    return f"Batfish found {row['Flow']} {decided} by '{row['Line_Content']}'"


def _rule(node: str, name: str, label: str, action: str, headers: Dict[str, Any]) -> Dict[str, Any]:
    if action == "PERMIT":
        today = (f"today {name} PERMITS all of this traffic. Write requirement if it "
                 f"must stay allowed, or prohibition if it must be blocked")
    else:
        today = (f"today {name} BLOCKS all of this traffic. Write prohibition if it "
                 f"must stay blocked, or requirement if it must be allowed")
    return {
        "description": label,
        "node": node,
        "filter": name,
        "kind": f"{PLACEHOLDER_PREFIX}: {today}>",
        "queries": [headers],
        "violation_severity": (f"{PLACEHOLDER_PREFIX}: high, medium or low -- how serious "
                               f"it would be if this rule stopped holding>"),
        "violation_summary": f"{name} on {node} does not treat this traffic as your policy requires",
    }


def draft_policy(bf: Session) -> Dict[str, Any]:
    """Draft a policy from the snapshot loaded in `bf`. Returns plain JSON data.

    The result will NOT load as a policy until a person has decided every
    rule -- see the module docstring and `analysis.policy`.
    """
    skip_nodes, not_drafted = _unreadable(bf)
    applied = _applied(bf)
    cites = _citations(bf)
    frame = bf.q.namedStructures(structureTypes="IP_ACCESS_LIST").answer().frame()
    filters = sorted(
        ((str(r["Node"]), str(r["Structure_Name"]), r["Structure_Definition"])
         for _, r in frame.iterrows()),
        key=lambda item: item[:2],
    )

    # The most rules one draft may hold: the limit the loader enforces on any
    # policy (#376), owned by policy_compliance because it comes from that
    # check's finding-id bands. Read here, not copied into this module.
    limit = policy_compliance.HIGHEST_POLICY_NUMBER
    rules: List[Dict[str, Any]] = []
    past_limit = 0
    for node, name, definition in filters:
        # "~" names are structures Batfish built itself, not the user's.
        if name.startswith("~") or node in skip_nodes:
            continue
        if (node, name) not in applied:
            not_drafted.append(
                f"{node} {name}: defined but not applied to any interface, so no rule "
                f"was drafted from it (it may still be used elsewhere, for example by "
                f"NAT or a route-map)."
            )
            continue

        for position, line in enumerate((definition or {}).get("lines", []), start=1):
            if len(rules) >= limit:
                past_limit += 1
                continue
            label = f"{node} {name} line {position}: {line.get('name', '')}"
            cite = _cite(line, cites)
            if cite is None:
                not_drafted.append(
                    f"{label} -- Batfish has no config line to cite for it (it may have "
                    f"generated the line itself), and every drafted rule must cite one."
                )
                continue
            label = f"{label} ({cite})"

            headers, reason = _headers_for(line)
            kind = _KIND_TODAY.get(str(line.get("action")))
            if reason is None and kind is None:
                reason = f"its action {line.get('action')!r} is neither PERMIT nor DENY"
            if reason:
                not_drafted.append(f"{label} -- not drafted: {reason}.")
                continue

            try:
                counter = _counter_example(bf, node, name, kind, headers)
            except Exception as error:
                not_drafted.append(
                    f"{label} -- Batfish could not check this line, so it was not "
                    f"drafted: {findings.describe_error(error)}"
                )
                continue
            if counter:
                not_drafted.append(
                    f"{label} -- not drafted: an earlier line decides part of the traffic "
                    f"it describes. {counter}. A rule copied from this line would claim "
                    f"more than the filter does."
                )
                continue
            rules.append(_rule(node, name, label, str(line["action"]), headers))

    if not rules and not not_drafted:
        # Nothing drafted and nothing refused means there was nothing to draft
        # FROM. Said outright, so an empty draft cannot read as "we looked at
        # your filters and found no rules" (#266's fourth state).
        not_drafted.append(
            "No filter is applied to any interface in this config, so there was "
            "nothing to draft rules from."
        )
    if past_limit:
        not_drafted.append(
            f"{past_limit} more line(s) were not examined: one policy numbers at most "
            f"{limit} policy_compliance rules, so its finding ids stay distinct."
        )

    return {
        DRAFT_KEY: {
            "status": (
                "UNREVIEWED DRAFT generated by Netwise from your configuration. "
                "Netwise will refuse this file until every <FILL IN ...> value holds "
                "your decision and this whole 'draft' block has been deleted."
            ),
            "summary": (f"{len(rules)} rule(s) drafted; {len(not_drafted)} item(s) not drafted, "
                        f"each listed with its reason under not_drafted."),
            "how_it_was_made": (
                "One rule per line of each filter applied to an interface, citing the "
                "file and line it came from. Every rule describes what the filter does "
                "TODAY, and Batfish confirmed each one holds for the configuration it "
                "was drafted from."
            ),
            "what_you_decide": (
                "For each rule: requirement (this traffic must be allowed) or "
                "prohibition (it must be blocked), and how serious a violation would "
                "be. Delete any rule you do not care about. A draft accepted as it "
                "stands only says the config does what it already does. Rules about "
                "one flow (access_control) or a path (routing) cannot be drafted from "
                "config lines; docs/user-guide.md shows how to add them."
            ),
            "not_drafted": not_drafted,
        },
        "policy_compliance": rules,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.draft_policy",
        description="Draft a policy from a config folder. The draft will not load "
                    "until you have made every decision in it.",
    )
    parser.add_argument("config_dir", help="snapshot root: device files live in <config_dir>/configs/")
    parser.add_argument("--out", help="write the draft to this file instead of printing it")
    parser.add_argument("--host", default=None, help="Batfish host (default: as analysis.pipeline)")
    args = parser.parse_args(argv)

    try:
        bf = pipeline.connect(args.host)
        pipeline.load_snapshot(bf, Path(args.config_dir), "netwise-draft", "draft")
        draft = draft_policy(bf)
    except Exception as error:
        print(f"Could not draft a policy: {findings.describe_error(error)}", file=sys.stderr)
        return 1

    text = json.dumps(draft, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(draft[DRAFT_KEY]["summary"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
