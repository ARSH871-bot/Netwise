"""Does the user's own policy contradict itself? (#322, US-30)

WHY THIS EXISTS
    A `prohibition` says traffic must be DENIED. A `requirement` says traffic
    must be PERMITTED. If two such rules describe overlapping traffic on the
    same device and the same filter, **no configuration can satisfy both** --
    whatever the network does, one of them reports a violation.

    Before this, that policy loaded cleanly and the scan ran. The user got a
    finding, it was real, and fixing it created the other one. The rules were
    at fault and nothing said so.

    This is #240's problem D, and the only one in that list needing no network:
    it is a property of the policy file alone. No Batfish, no config, no
    Docker.

WHAT COUNTS AS A CONTRADICTION
    One `prohibition` and one `requirement`, same `node`, same `filter`, whose
    header spaces intersect. Two prohibitions that overlap are consistent --
    both deny, and denying twice is denying. Two requirements likewise.

    A rule's `queries` are a union: `policy_compliance` fails the rule if ANY
    query fails, so the rule covers every query it lists. So a contradiction
    is any query of the prohibition meeting any query of the requirement.

THE DESIGN DECISION THAT MATTERS: PROVEN, NOT PRESUMED
    Batfish header specifiers are a language, not a list. `dstIps` can read
    `0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)`; `ipProtocols` can read `!tcp`.
    This module does not implement that language and must not pretend to.

    So every field parses to one of three answers -- a set, "matches
    everything" (the field was absent), or **undecidable**. A pair of queries
    is only a contradiction when every field is decidable and every field
    intersects. If any field is undecidable the pair is reported as
    undecidable and is NOT called a contradiction.

    Undecidable is not the same as safe, and this module never lets it be
    silently treated as such -- `load_policy` carries those pairs out on
    `Policy.undecidable`, which the pipeline reports the same way it reports
    renamed keys. Deciding we cannot tell, and saying nothing, is F-4 arriving
    through the policy file: "we checked and found nothing" standing in for
    "we could not check".

SCOPE
    `policy_compliance` only, because `kind` is a `policy_compliance` key --
    it is the only section whose rules can disagree about the same traffic in
    this way. `routing` expresses expectations per route rather than per
    header space, and `access_control` statements are not paired as
    permit/deny over a shared space. If either gains that shape, the entry
    point is `contradictions()`, which takes entries and knows nothing about
    which section produced them.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

#: The header fields this module can reason about. A query key outside this
#: set makes the query undecidable rather than ignored: a field we do not
#: understand may be the one that keeps two rules apart, and treating it as
#: absent would widen the space and invent an overlap.
KNOWN_FIELDS = ("srcIps", "dstIps", "srcPorts", "dstPorts", "ipProtocols")

#: Characters that put a specifier outside the plain-list subset parsed here.
#: `\` is set difference, `!` negation, `(`/`)` grouping, `@` and `/` with
#: letters are named specifiers like `@enter(...)` or `ref.Interface(...)`.
_COMPLEX = re.compile(r"[\\!()@]|\bref\.", re.IGNORECASE)

ANY = "ANY"  #: the field was absent, so it constrains nothing


class _Undecidable(Exception):
    """Raised internally when a specifier is outside the parsed subset."""

    def __init__(self, field: str, value: Any, why: str) -> None:
        super().__init__(f"{field}={value!r} ({why})")
        self.field = field
        self.value = value
        self.why = why


def _networks(field: str, spec: Any) -> List[ipaddress.IPv4Network]:
    """A comma-separated list of addresses or CIDRs, as networks."""
    if not isinstance(spec, str):
        raise _Undecidable(field, spec, "not a string")
    if _COMPLEX.search(spec):
        raise _Undecidable(field, spec, "uses Batfish specifier syntax this check does not parse")
    out: List[ipaddress.IPv4Network] = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise _Undecidable(field, spec, f"{part!r} is not an address or CIDR")
    if not out:
        raise _Undecidable(field, spec, "empty")
    return out


def _ports(field: str, spec: Any) -> List[Tuple[int, int]]:
    """`"443"`, `"0-442,444-65535"` -> inclusive integer ranges."""
    if isinstance(spec, int):
        return [(spec, spec)]
    if not isinstance(spec, str):
        raise _Undecidable(field, spec, "not a string or integer")
    if _COMPLEX.search(spec):
        raise _Undecidable(field, spec, "uses Batfish specifier syntax this check does not parse")
    out: List[Tuple[int, int]] = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        bounds = part.split("-")
        try:
            if len(bounds) == 1:
                lo = hi = int(bounds[0])
            elif len(bounds) == 2:
                lo, hi = int(bounds[0]), int(bounds[1])
            else:
                raise ValueError
        except ValueError:
            raise _Undecidable(field, spec, f"{part!r} is not a port or port range")
        if not (0 <= lo <= hi <= 65535):
            raise _Undecidable(field, spec, f"{part!r} is not a port range from 0 to 65535")
        out.append((lo, hi))
    if not out:
        raise _Undecidable(field, spec, "empty")
    return out


def _protocols(field: str, spec: Any) -> Set[str]:
    if isinstance(spec, str):
        spec = [spec]
    if not isinstance(spec, (list, tuple)):
        raise _Undecidable(field, spec, "not a list")
    out = set()
    for item in spec:
        text = str(item).strip().lower()
        if not text or _COMPLEX.search(text):
            raise _Undecidable(field, spec, f"{item!r} is negated or not a plain protocol name")
        out.add(text)
    if not out:
        raise _Undecidable(field, spec, "empty")
    return out


def _parse(query: Any) -> Dict[str, Any]:
    """One query to {field: parsed value or ANY}. Raises _Undecidable."""
    if not isinstance(query, dict):
        raise _Undecidable("query", query, "not an object")
    unknown = sorted(set(query) - set(KNOWN_FIELDS))
    if unknown:
        raise _Undecidable("query", query, f"has field(s) this check does not model: {', '.join(unknown)}")
    parsed: Dict[str, Any] = {}
    for field in KNOWN_FIELDS:
        if field not in query:
            parsed[field] = ANY
        elif field in ("srcIps", "dstIps"):
            parsed[field] = _networks(field, query[field])
        elif field in ("srcPorts", "dstPorts"):
            parsed[field] = _ports(field, query[field])
        else:
            parsed[field] = _protocols(field, query[field])
    return parsed


def _nets_meet(a: Sequence[ipaddress.IPv4Network],
               b: Sequence[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    """Shared addresses. Two CIDR blocks are disjoint or one holds the other,
    so the intersection of a pair is simply the more specific of the two."""
    shared = []
    for x in a:
        for y in b:
            if x.overlaps(y):
                shared.append(x if x.prefixlen >= y.prefixlen else y)
    return shared


def _ranges_meet(a: Sequence[Tuple[int, int]],
                 b: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    shared = []
    for lo1, hi1 in a:
        for lo2, hi2 in b:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            if lo <= hi:
                shared.append((lo, hi))
    return shared


def _field_meet(field: str, x: Any, y: Any) -> Tuple[bool, Optional[str]]:
    """Do two parsed constraints share anything? -> (yes, description)."""
    if x is ANY and y is ANY:
        return True, None                     # both unconstrained: no detail worth printing
    if x is ANY:
        return True, _describe(field, y)
    if y is ANY:
        return True, _describe(field, x)
    if field in ("srcIps", "dstIps"):
        shared = _nets_meet(x, y)
    elif field in ("srcPorts", "dstPorts"):
        shared = _ranges_meet(x, y)
    else:
        shared = sorted(x & y)
    return (bool(shared), _describe(field, shared) if shared else None)


_LABEL = {"srcIps": "src", "dstIps": "dst", "srcPorts": "src ports",
          "dstPorts": "dst ports", "ipProtocols": "protocol"}


def _describe(field: str, value: Any) -> str:
    if field in ("srcPorts", "dstPorts"):
        text = ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in value)
    else:
        text = ",".join(str(v) for v in value)
    return f"{_LABEL[field]} {text}"


def overlap(query_a: Any, query_b: Any) -> Tuple[Optional[bool], str]:
    """Do two queries describe any traffic in common?

    Returns `(True, "src ..., dst ...")` when they provably do, `(False, "")`
    when they provably do not, and `(None, reason)` when a specifier is
    outside the subset this module parses. Never guesses.
    """
    try:
        a, b = _parse(query_a), _parse(query_b)
    except _Undecidable as exc:
        return None, str(exc)
    parts = []
    for field in KNOWN_FIELDS:
        meets, detail = _field_meet(field, a[field], b[field])
        if not meets:
            return False, ""
        if detail:
            parts.append(detail)
    return True, ", ".join(parts) if parts else "all traffic"


def _scope(entry: Any) -> Tuple[str, str]:
    return (str(entry.get("node", "")), str(entry.get("filter", "")))


def _ref(entry: Any) -> str:
    number = entry.get("number")
    label = f"rule {number}" if number is not None else "an unnumbered rule"
    description = entry.get("description")
    return f"{label} ({description!r})" if description else label


def contradictions(entries: Sequence[Any]) -> Tuple[List[str], List[str]]:
    """Find prohibition/requirement pairs that cannot both hold.

    Returns `(contradictions, undecidable)`, both lists of human-readable
    sentences naming each pair. A caller that refuses the policy should use
    the first; it must not treat the second as nothing -- see the module
    docstring.
    """
    prohibitions = [e for e in entries if isinstance(e, dict) and e.get("kind") == "prohibition"]
    requirements = [e for e in entries if isinstance(e, dict) and e.get("kind") == "requirement"]

    conflicts: List[str] = []
    undecided: List[str] = []
    for forbid in prohibitions:
        for require in requirements:
            if _scope(forbid) != _scope(require):
                continue                      # different device or filter: cannot collide
            node, filter_name = _scope(forbid)
            where = f"on {node} filter {filter_name}" if node and filter_name else ""
            unknown_here: List[str] = []
            found = False
            for qa in forbid.get("queries", []) or []:
                for qb in require.get("queries", []) or []:
                    verdict, detail = overlap(qa, qb)
                    if verdict is True:
                        conflicts.append(
                            f"{_ref(forbid)} forbids what {_ref(require)} requires {where}"
                            f": both describe {detail}".replace("  ", " ")
                        )
                        found = True
                        break
                    if verdict is None:
                        unknown_here.append(detail)
                if found:
                    break
            if not found and unknown_here:
                undecided.append(
                    f"{_ref(forbid)} and {_ref(require)} {where} could not be compared"
                    f": {unknown_here[0]}".replace("  ", " ")
                )
    return conflicts, undecided
