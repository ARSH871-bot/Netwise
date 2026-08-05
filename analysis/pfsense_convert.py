"""
Netwise -- convert a PF Sense config.xml export into Cisco IOS config text
that Batfish can read natively (US-6).

WHY THIS EXISTS
    The client's real firewall is PF Sense, which exports a declarative XML
    tree (config.xml): interfaces, filter rules, NAT, aliases, DHCP, VPN.
    Batfish has no parser for that format at all -- it understands Cisco IOS,
    Juniper, Arista and a handful of others, never PF Sense. Every check this
    project has built (access_control, policy_compliance, routing) already
    assumes a Cisco-style node with named ACLs bound to interfaces.

    So the shape of the fix is: parse the one input format Batfish cannot
    read, emit the one output format everything else in this project already
    understands, and change nothing else. A converted config re-enters the
    pipeline through the exact same analyse() every other config uses.

SCOPE -- TIMEBOXED ON PURPOSE, PER CLAUDE.md SECTION 7
    IN SCOPE: interfaces (name, IP, subnet) and filter rules (source,
    destination, protocol, port, pass/block). That is what issue #6's
    acceptance criterion actually requires: "a converted config loads and
    analyses without error."

    OUT OF SCOPE, stated here rather than silently dropped: NAT, aliases with
    ranges or CIDR groups, DHCP, VPN, traffic shaping, IPv6, combined
    "tcp/udp" rules, and rules split across more than one interface. None of
    that is attempted. Where the input needs one of these to convert
    correctly, this module raises PfSenseConversionError rather than
    producing something that looks plausible and is wrong -- the same
    "refuse rather than guess" discipline analysis/checks/routing.py's
    _compute_dead_rule_outcome() and ai/Modelfile both already commit to.

A SIMPLIFYING ASSUMPTION, STATED EXPLICITLY
    PF Sense's real rule evaluation is "last matching rule wins" unless a
    rule is marked "quick" (which most PF Sense-GUI-authored rules are, but
    the XML does not guarantee it). This module instead treats rules as
    first-match-wins, top to bottom -- exactly how a Cisco ACL already
    behaves, and how every existing check in this project already reasons
    about rule order. tests/fixtures/pfsense-source/config.xml is written so
    every rule matches a disjoint slice of traffic except the final
    catch-all, which makes it correct under EITHER evaluation model. A real
    PF Sense export relying on last-match-wins semantics between overlapping
    rules would convert to something that parses cleanly but decides
    differently than the original -- a known limitation, not a hidden one.

WHY INTERFACE NAMES ARE REWRITTEN, NOT COPIED
    PF Sense identifies interfaces with FreeBSD device names (em0, em1, igb0).
    Cisco IOS config syntax requires an interface name matching a known Cisco
    interface type (GigabitEthernet0/0, and similar), because Batfish's Cisco
    grammar parses against that vocabulary specifically -- em0 is not valid
    Cisco IOS syntax and would fail to parse, which would violate the one
    acceptance criterion this story has. So each PF Sense interface role is
    assigned a synthetic GigabitEthernet0/N name, in the order it appears in
    the XML; the original PF Sense identifier and description are kept as a
    comment for traceability, not thrown away.
"""

from __future__ import annotations

import ipaddress
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Union

# The only ACL name every other fixture in this project already uses for the
# LAN-inbound filter. Reusing it, rather than inventing a new name, is what
# lets tests/fixtures/pfsense-source/config.xml's converted output be
# compared directly against tests/fixtures/rtr-us5-secure's hand-written one.
ACL_NAME = "acl_in"

_PFSENSE_TO_CISCO_ACTION = {"pass": "permit", "block": "deny", "reject": "deny"}
_PFSENSE_TO_CISCO_PROTOCOL = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "any": "ip"}


class PfSenseConversionError(Exception):
    """Raised when the input needs something this converter deliberately does
    not attempt -- see the module docstring's SCOPE section. Always raised
    with a message naming the specific unsupported construct, never silently
    swallowed or approximated."""


def _text(el: Optional[ET.Element], tag: str, default: Optional[str] = None) -> Optional[str]:
    """Return the text of `el`'s first `tag` child, or `default` if absent.

    PF Sense's XML uses an empty element (e.g. `<any/>`) to mean "this option
    is set" rather than storing a value in text -- callers that need to
    detect presence rather than read text use `el.find(tag) is not None`
    directly instead of this helper.
    """
    if el is None:
        return default
    child = el.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _parse_interfaces(root: ET.Element) -> Dict[str, Dict[str, str]]:
    """Return {role: {"if": ..., "ipaddr": ..., "subnet": ..., "descr": ...}}
    for every interface PF Sense defines, in document order.

    `role` is PF Sense's own key ("wan", "lan", "opt1", ...) -- it is also
    the value a filter rule's <interface> and a network reference's
    <network> use to point back at one of these, so it is kept as the dict
    key rather than translated at this stage.
    """
    interfaces_el = root.find("interfaces")
    if interfaces_el is None:
        raise PfSenseConversionError("no <interfaces> section in this export")

    interfaces: Dict[str, Dict[str, str]] = {}
    for iface_el in interfaces_el:
        role = iface_el.tag
        ipaddr = _text(iface_el, "ipaddr")
        subnet = _text(iface_el, "subnet")
        if not ipaddr or not subnet:
            # DHCP-assigned or unconfigured interfaces have no static ipaddr.
            # Nothing to model for such an interface -- skip it rather than
            # emit a Cisco stanza with no address, which would itself fail
            # to parse meaningfully.
            continue
        interfaces[role] = {
            "if": _text(iface_el, "if", default=role),
            "ipaddr": ipaddr,
            "subnet": subnet,
            "descr": _text(iface_el, "descr", default=role.upper()),
        }
    return interfaces


def _assign_cisco_interface_names(interfaces: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Map each PF Sense role to a synthetic Cisco interface name, in the
    order interfaces were defined. See the module docstring for why this
    rewrite is necessary rather than optional."""
    return {role: f"GigabitEthernet0/{i}" for i, role in enumerate(interfaces)}


def _resolve_endpoint(el: ET.Element, interfaces: Dict[str, Dict[str, str]]) -> str:
    """Convert a PF Sense <source> or <destination> element into a Cisco ACL
    address clause: "any", "host 1.2.3.4", or "NETWORK WILDCARD-MASK".

    Handles exactly the three forms tests/fixtures/pfsense-source/config.xml
    uses: <any/>, <network>ROLE</network> (that interface's own subnet), and
    <address>IP</address> (a single host). PF Sense also supports network
    aliases like "lanip" (the interface's own address, not its subnet) and
    named address-group aliases -- neither is handled; both raise rather
    than silently picking the nearest matching behaviour.

    WHY <address> IS VALIDATED AS AN IP, NOT TRUSTED AS ONE
        Found in review, not anticipated up front: PF Sense's <address> can
        itself hold a named alias (e.g. "TRUSTED_HOSTS") rather than a literal
        IP -- the same "named alias" case this docstring already calls out
        for <network>, just reachable through a different element. Without
        the check below, that alias name was passed straight through into
        "host TRUSTED_HOSTS", which is not valid Cisco syntax.

        Measured what Batfish actually does with that line: it does NOT
        reject the file outright. fileParseStatus reports
        PARTIALLY_UNRECOGNIZED, and Batfish silently drops the one bad line
        while modelling everything else. Today, analysis.pipeline's
        find_parse_problems() treats any non-PASSED status as fatal, so this
        still surfaces as status="error" rather than a wrong answer -- but
        that strictness is an open decision under active proposal to relax
        for real-world configs (CLAUDE.md section 11). Relying on ANOTHER
        module's current policy, one already flagged as likely to change, as
        the only thing standing between this and a silently wrong model of a
        client firewall is not good enough. Validated here instead, at the
        layer that actually knows what went wrong.
    """
    if el.find("any") is not None:
        return "any"

    network = _text(el, "network")
    if network is not None:
        if network not in interfaces:
            raise PfSenseConversionError(
                f"rule references network {network!r}, which is not a "
                "configured interface with a static address (or is an "
                "alias form like 'lanip' that this converter does not "
                "resolve)"
            )
        iface = interfaces[network]
        net = ipaddress.IPv4Network(f"{iface['ipaddr']}/{iface['subnet']}", strict=False)
        return f"{net.network_address} {net.hostmask}"

    address = _text(el, "address")
    if address is not None:
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            raise PfSenseConversionError(
                f"<address> is {address!r}, not an IP address -- likely a "
                "named alias, which this converter does not resolve"
            ) from None
        return f"host {address}"

    raise PfSenseConversionError(
        "a <source> or <destination> element matched none of any/network/"
        "address -- likely a named alias group, which is out of scope"
    )


def _rule_to_acl_line(rule_el: ET.Element, interfaces: Dict[str, Dict[str, str]]) -> str:
    """Convert one PF Sense <rule> element into one Cisco extended-ACL line."""
    pf_type = _text(rule_el, "type")
    action = _PFSENSE_TO_CISCO_ACTION.get(pf_type or "")
    if action is None:
        raise PfSenseConversionError(f"unsupported rule <type>: {pf_type!r}")

    pf_protocol = _text(rule_el, "protocol", default="any")
    cisco_protocol = _PFSENSE_TO_CISCO_PROTOCOL.get(pf_protocol or "")
    if cisco_protocol is None:
        raise PfSenseConversionError(
            f"unsupported <protocol>: {pf_protocol!r} -- combined forms "
            "like 'tcp/udp' need two Cisco ACL lines and are not handled"
        )

    source_el = rule_el.find("source")
    destination_el = rule_el.find("destination")
    if source_el is None or destination_el is None:
        raise PfSenseConversionError("rule is missing <source> or <destination>")

    src = _resolve_endpoint(source_el, interfaces)
    dst = _resolve_endpoint(destination_el, interfaces)

    port_clause = ""
    if cisco_protocol in ("tcp", "udp"):
        port = _text(destination_el, "port")
        if port is not None:
            # Same class of gap the review found in <address>: PF Sense's
            # <port> can hold a named alias (e.g. "HTTPS_ALT") instead of a
            # number. Checked for the identical reason, not just because the
            # other one was found -- an unvalidated port would produce
            # "eq HTTPS_ALT", equally invalid Cisco syntax, equally liable to
            # be silently dropped by Batfish's partial-recognition parsing.
            if not port.isdigit() or not (0 < int(port) <= 65535):
                raise PfSenseConversionError(
                    f"<port> is {port!r}, not a single numeric port -- "
                    "named aliases and ranges are out of scope"
                )
            port_clause = f" eq {port}"

    return f"{action} {cisco_protocol} {src} {dst}{port_clause}"


def convert(xml_path: Union[str, Path]) -> str:
    """Parse a PF Sense config.xml export and return equivalent Cisco IOS
    config text. Raises PfSenseConversionError for anything out of scope --
    see the module docstring. Never returns a partial or best-guess result.
    """
    root = ET.parse(xml_path).getroot()

    hostname = _text(root.find("system"), "hostname", default="pfsense")
    interfaces = _parse_interfaces(root)
    if not interfaces:
        raise PfSenseConversionError("no interface has both an address and a subnet")
    cisco_names = _assign_cisco_interface_names(interfaces)

    filter_el = root.find("filter")
    rule_els = filter_el.findall("rule") if filter_el is not None else []

    # All rules must be on ONE interface role. Batfish/Cisco applies one ACL
    # per interface direction; supporting rules split across several
    # interfaces would mean building several ACLs and is out of scope for
    # this pass. Raise rather than silently merging rules from different
    # interfaces into one ACL, which would change what the config means.
    rule_roles = {_text(r, "interface") for r in rule_els}
    rule_roles.discard(None)
    if len(rule_roles) > 1:
        raise PfSenseConversionError(
            f"filter rules span multiple interfaces {sorted(rule_roles)}; "
            "only a single-interface rule set is supported"
        )
    acl_role = next(iter(rule_roles), None)
    if acl_role is not None and acl_role not in interfaces:
        raise PfSenseConversionError(
            f"filter rules apply to interface {acl_role!r}, which has no "
            "static address configured"
        )

    acl_lines = [_rule_to_acl_line(r, interfaces) for r in rule_els]

    lines: List[str] = [f"hostname {hostname}", "!"]
    for role, info in interfaces.items():
        cisco_name = cisco_names[role]
        net = ipaddress.IPv4Network(f"{info['ipaddr']}/{info['subnet']}", strict=False)
        lines.append(f"interface {cisco_name}")
        lines.append(f" description {info['descr']} (PF Sense: {info['if']})")
        lines.append(f" ip address {info['ipaddr']} {net.netmask}")
        if role == acl_role:
            lines.append(f" ip access-group {ACL_NAME} in")
        lines.append("!")

    if acl_lines:
        lines.append(f"ip access-list extended {ACL_NAME}")
        lines.extend(f" {line}" for line in acl_lines)
        lines.append("!")

    return "\n".join(lines) + "\n"


def write_snapshot(xml_path: Union[str, Path], snapshot_dir: Union[str, Path]) -> Path:
    """Convert `xml_path` and write it as a Batfish-ready snapshot at
    `snapshot_dir` (device files land in `snapshot_dir/configs/`, matching
    what analysis.pipeline.load_snapshot expects). Returns the file written.
    """
    text = convert(xml_path)
    hostname = ET.parse(xml_path).getroot().find("system")
    hostname_text = _text(hostname, "hostname", default="pfsense")

    configs_dir = Path(snapshot_dir) / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)
    out_path = configs_dir / f"{hostname_text}.cfg"
    out_path.write_text(text)
    return out_path


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(
            "usage: python -m analysis.pfsense_convert <config.xml> <snapshot-dir>\n"
            "example: python -m analysis.pfsense_convert "
            "tests/fixtures/pfsense-source/config.xml /tmp/pfsense-converted"
        )
    written = write_snapshot(sys.argv[1], sys.argv[2])
    print(f"Wrote {written}")
    print()
    print(written.read_text())
