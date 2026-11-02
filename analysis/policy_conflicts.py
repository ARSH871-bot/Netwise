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
#: `\` is set difference, `!` negation, `(`/`)` grouping, and `@` or `ref.`
#: start a named specifier like `@enter(...)` or `ref.Interface(...)`.
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
    if isinstance(spec, bool):
        raise _Undecidable(field, spec, "a boolean is not a port")
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


#: Protocol tokens this module understands, by name and by IANA number.
#: A CLOSED list (#387 review, @ARSH871-bot): anything else is undecidable.
#: Taking every unrecognised token as a protocol name was a guess, and it
#: guessed wrong in the reassuring direction -- `"6"` never met `"tcp"`, so a
#: real contradiction loaded as consistent. Batfish reads `"6"` as TCP.
_PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp",
              "6": "tcp", "17": "udp", "1": "icmp"}


def _protocols(field: str, spec: Any) -> Set[str]:
    if isinstance(spec, str):
        spec = [spec]
    if not isinstance(spec, (list, tuple)):
        raise _Undecidable(field, spec, "not a list")
    out = set()
    for item in spec:
        # pybatfish splits "tcp,udp" into two protocols, so this does too.
        for token in str(item).split(","):
            text = token.strip().lower()
            if text not in _PROTOCOLS:
                raise _Undecidable(
                    field, spec,
                    f"{token.strip()!r} is not a protocol this check recognises "
                    f"({', '.join(sorted(k for k in _PROTOCOLS if not k.isdigit()))}, "
                    "or their numbers)",
                )
            out.add(_PROTOCOLS[text])
    if not out:
        raise _Undecidable(field, spec, "empty")
    return out


class _Unknown:
    """One field we could not parse. Kept per field, not per query (#387)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


def _parse_field(field: str, value: Any) -> Any:
    try:
        if field in ("srcIps", "dstIps"):
            return _networks(field, value)
        if field in ("srcPorts", "dstPorts"):
            return _ports(field, value)
        return _protocols(field, value)
    except _Undecidable as exc:
        return _Unknown(str(exc))


def _parse(query: Any) -> Tuple[Dict[str, Any], List[str]]:
    """One query to ({field: value, ANY, or _Unknown}, [reasons]).

    Unmodelled keys are returned as reasons rather than raised: they make a
    pair undecidable, but they cannot make it OVERLAP, and a field we did
    parse may still prove the two queries disjoint.
    """
    if not isinstance(query, dict):
        raise _Undecidable("query", query, "not an object")
    reasons = [
        f"query has field(s) this check does not model: {', '.join(sorted(set(query) - set(KNOWN_FIELDS)))}"
    ] if set(query) - set(KNOWN_FIELDS) else []
    parsed = {f: (ANY if f not in query else _parse_field(f, query[f])) for f in KNOWN_FIELDS}
    reasons += [v.reason for v in parsed.values() if isinstance(v, _Unknown)]
    return parsed, reasons


def _nets_meet(a: Sequence[ipaddress.IPv4Network],
               b: Sequence[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    """Shared addresses. Two CIDR blocks are disjoint or one holds the other,
    so the intersection of a pair is simply the more specific of the two."""
    shared = []
    for x in a:
        for y in b:
            if x.overlaps(y):
                pick = x if x.prefixlen >= y.prefixlen else y
                if pick not in shared:
                    shared.append(pick)
    return shared


def _ranges_meet(a: Sequence[Tuple[int, int]],
                 b: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    shared = []
    for lo1, hi1 in a:
        for lo2, hi2 in b:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            if lo <= hi and (lo, hi) not in shared:
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
    when they provably do not, and `(None, reason)` when it cannot be decided.
    Never guesses.

    FIELD BY FIELD (#387 review). A query is a conjunction, so ONE field that
    is provably disjoint makes the pair disjoint -- whatever the other fields
    say, including ones we could not parse. That can never invent an overlap,
    because a conjunct only ever shrinks a space. Only when nothing proves
    them disjoint does an unparsed field make the answer undecidable.
    """
    try:
        a, reasons_a = _parse(query_a)
        b, reasons_b = _parse(query_b)
    except _Undecidable as exc:
        return None, str(exc)
    parts = []
    for field in KNOWN_FIELDS:
        x, y = a[field], b[field]
        if isinstance(x, _Unknown) or isinstance(y, _Unknown):
            continue
        meets, detail = _field_meet(field, x, y)
        if not meets:
            return False, ""
        if detail:
            parts.append(detail)
    reasons = reasons_a + reasons_b
    if reasons:
        return None, reasons[0]
    return True, ", ".join(parts) if parts else "all traffic"


#: Characters that make a `filter` a Batfish SPECIFIER rather than a name --
#: `/acl_in/` is a regex, `@in(Gi0/0)` an interface's filter, `a,b` a list.
#: Such a filter can name the same ACL as another rule's plain name.
#: Not `_COMPLEX`: in an address list `/` is a CIDR and `,` separates entries,
#: both parsed above, while in a filter name they mean regex and list.
_FILTER_SPECIFIER = re.compile(r"[/@(,]")


def _same_scope(a: Any, b: Any) -> Optional[bool]:
    """Are two rules about the same device AND the same filter?

    True or False when it is clear, None when it is not. Batfish resolves
    `ACL_IN`, `acl_in ` and `/acl_in/` all to `acl_in` (#387 review), so a raw
    string comparison called those "different filter: cannot collide" and
    skipped a real contradiction. Node is compared exactly: a mis-cased node
    never runs at all, so it cannot produce a contradictory result.
    """
    if str(a.get("node", "")) != str(b.get("node", "")):
        return False
    fa, fb = str(a.get("filter", "")), str(b.get("filter", ""))
    if fa == fb:
        return True
    if _FILTER_SPECIFIER.search(fa) or _FILTER_SPECIFIER.search(fb):
        return None
    if fa.strip().casefold() == fb.strip().casefold():
        return None
    return False


def _ref(entry: Any) -> str:
    number = entry.get("number")
    label = f"rule {number}" if number is not None else "an unnumbered rule"
    description = entry.get("description")
    return f"{label} ({description!r})" if description else label


def _compare(prohibitions: Sequence[Any], requirements: Sequence[Any],
             name_p: Any = _ref, name_r: Any = _ref) -> Tuple[List[str], List[str]]:
    """Every prohibition against every requirement. The one comparison loop.

    Shared by contradictions() (one policy) and between() (two policies), so
    the two can never disagree about what a contradiction is. `name_p` and
    `name_r` say how to name a rule from each side -- the only difference
    between the two callers.
    """
    conflicts: List[str] = []
    undecided: List[str] = []
    for forbid in prohibitions:
        for require in requirements:
            scope = _same_scope(forbid, require)
            if scope is False:
                continue                      # different device or filter: cannot collide
            node, filter_name = forbid.get("node", ""), forbid.get("filter", "")
            where = f"on {node} filter {filter_name}" if node and filter_name else ""
            if scope is None:
                undecided.append(
                    f"{name_p(forbid)} and {name_r(require)} name filters "
                    f"{forbid.get('filter')!r} and {require.get('filter')!r} on {node}, "
                    "which Batfish may resolve to the same ACL; could not be compared"
                )
                continue
            unknown_here: List[str] = []
            found = False
            for qa in forbid.get("queries", []) or []:
                for qb in require.get("queries", []) or []:
                    verdict, detail = overlap(qa, qb)
                    if verdict is True:
                        conflicts.append(
                            f"{name_p(forbid)} forbids what {name_r(require)} requires {where}"
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
                    f"{name_p(forbid)} and {name_r(require)} {where} could not be compared"
                    f": {unknown_here[0]}".replace("  ", " ")
                )
    return conflicts, undecided


def _kind(entries: Sequence[Any], kind: str) -> List[Any]:
    return [e for e in entries if isinstance(e, dict) and e.get("kind") == kind]


def contradictions(entries: Sequence[Any]) -> Tuple[List[str], List[str]]:
    """Find prohibition/requirement pairs that cannot both hold.

    Returns `(contradictions, undecidable)`, both lists of human-readable
    sentences naming each pair. A caller that refuses the policy should use
    the first; it must not treat the second as nothing -- see the module
    docstring.
    """
    return _compare(_kind(entries, "prohibition"), _kind(entries, "requirement"))


def between(entries_a: Sequence[Any], entries_b: Sequence[Any],
            name_a: str = "policy A", name_b: str = "policy B") -> Tuple[List[str], List[str]]:
    """Find rules in one policy that forbid what the OTHER policy requires.

    WHY THIS EXISTS (Studio 6, multi-policy conflict check)
        Two teams can each write a policy for the same firewall -- security's
        and the application owners' -- and each can be consistent on its own.
        Applied together, a prohibition in one and a requirement in the other
        can describe the same traffic, and then no configuration satisfies
        both. load_policy() cannot see that, because it only ever reads one
        file at a time.

    Both directions are checked: A's prohibitions against B's requirements,
    and B's prohibitions against A's. Same three answers as within one policy
    -- a pair that cannot be decided is returned in the second list, never
    dropped. Rules are named with their policy, so the user knows which file
    to change.
    """
    ref_a = lambda e: f"{name_a} {_ref(e)}"   # noqa: E731
    ref_b = lambda e: f"{name_b} {_ref(e)}"   # noqa: E731
    c1, u1 = _compare(_kind(entries_a, "prohibition"), _kind(entries_b, "requirement"), ref_a, ref_b)
    c2, u2 = _compare(_kind(entries_b, "prohibition"), _kind(entries_a, "requirement"), ref_b, ref_a)
    return c1 + c2, u1 + u2


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m analysis.policy_conflicts first.json second.json`

    Loads each file the normal way -- so a file that contradicts ITSELF is
    refused with the loader's own message, naming that file -- then compares
    the two. Exit status 1 when they contradict each other, 0 otherwise.
    """
    import sys
    from pathlib import Path

    from analysis.policy import PolicyError, load_policy_file

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: python -m analysis.policy_conflicts <first-policy.json> <second-policy.json>")
        return 2
    loaded = []
    for path in args:
        try:
            loaded.append(load_policy_file(path))
        except PolicyError as error:
            print(f"{path}: not loaded -- {error}")
            return 2
    a, b = (Path(x).name for x in args)
    conflicts, undecided = between(
        loaded[0].entries_for("policy_compliance"), loaded[1].entries_for("policy_compliance"), a, b)
    for line in conflicts:
        print(f"CONFLICT: {line}")
    for line in undecided:
        print(f"warning: {line}")
    if not conflicts:
        print(f"No rule in {a} forbids what {b} requires, or the other way round"
              + (f" ({len(undecided)} pair(s) could not be compared, above)." if undecided else "."))
    return 1 if conflicts else 0


if __name__ == "__main__":
    raise SystemExit(main())
