"""Describe the SHAPE of a PF Sense config.xml without revealing its contents.

WHY THIS EXISTS
    CLAUDE.md constraint 1: no config data goes to any cloud AI service. That
    rule does not stop us reasoning about a client's export -- it stops us
    moving it. This prints structure only: which elements are present, how
    many, and which of them analysis/pfsense_convert.py can handle.

    It NEVER prints a value. No hostnames, no addresses, no descriptions, no
    interface names. Only tag names, counts, and yes/no answers. The output is
    safe to paste into a chat, an email, or a report.

RUN
    python tools/pfsense_shape.py path/to/config.xml

WHAT TO DO WITH THE OUTPUT
    Paste it. It is enough to say whether the converter will work on this
    file, what it would refuse on, and what would need building -- without
    anyone outside the machine seeing a single line of the network.
"""
from __future__ import annotations

import collections
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Constructs analysis/pfsense_convert.py understands today. Anything outside
# this list is not a bug -- it is a documented refusal (CLAUDE.md section 7).
SUPPORTED_RULE_FIELDS = {
    "type", "interface", "ipprotocol", "protocol", "source",
    "destination", "descr", "tracker", "quick",
}
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
SUPPORTED_TYPES = {"pass", "block", "reject"}


def _tag_census(root: ET.Element) -> collections.Counter:
    return collections.Counter(el.tag for el in root.iter())


def main(path: str) -> None:
    root = ET.parse(path).getroot()
    census = _tag_census(root)

    print("PF Sense config.xml -- STRUCTURE ONLY, no values")
    print("=" * 56)

    rules = root.findall("./filter/rule")
    quick = [r for r in rules if r.find("quick") is not None]
    print(f"\nfilter rules              : {len(rules)}")
    print(f"  marked <quick/>         : {len(quick)}")
    print(f"  NOT marked quick        : {len(rules) - len(quick)}")

    # THE question. See CLAUDE.md section 7 and issue #47.
    if not rules:
        verdict = "no rules found -- the converter refuses an empty rule set"
    elif len(quick) == len(rules):
        verdict = "ALL rules are quick -> first-match-wins is equivalent. Safe to convert."
    elif not quick:
        verdict = "NO rules are quick -> last-match-wins applies. Converter will refuse overlapping pairs."
    else:
        verdict = "MIXED -> safe only where the EARLIER rule of an overlapping pair is quick."
    print(f"  => {verdict}")

    print(f"\ninterfaces                : {len(root.findall('./interfaces/*'))}")
    print("\nrule field usage (tag names only):")
    field_use = collections.Counter(
        child.tag for rule in rules for child in rule
    )
    for tag, n in sorted(field_use.items(), key=lambda kv: -kv[1]):
        mark = " " if tag in SUPPORTED_RULE_FIELDS else " <-- NOT SUPPORTED"
        print(f"  {tag:<24}{n:>4}{mark}")

    print("\nvalues we must recognise (vocabulary only, never addresses):")
    for field, allowed in (("type", SUPPORTED_TYPES), ("protocol", SUPPORTED_PROTOCOLS)):
        seen = collections.Counter(
            (r.findtext(field) or "").strip() for r in rules if r.find(field) is not None
        )
        for value, n in sorted(seen.items()):
            mark = " " if value in allowed else " <-- NOT SUPPORTED"
            print(f"  {field}={value!r:<18}{n:>4}{mark}")

    print("\nsections present at the top level:")
    out_of_scope = {"nat", "dhcpd", "openvpn", "ipsec", "aliases", "shaper"}
    for tag in sorted({el.tag for el in root}):
        mark = " <-- out of scope, converter ignores or refuses" if tag in out_of_scope else ""
        print(f"  {tag}{mark}")

    print(f"\ntotal elements in file    : {sum(census.values())}")
    print("\nNothing above contains an address, hostname, or description.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tools/pfsense_shape.py path/to/config.xml")
    if not Path(sys.argv[1]).is_file():
        sys.exit(f"not a file: {sys.argv[1]}")
    main(sys.argv[1])
