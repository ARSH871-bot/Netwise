"""Netwise -- is this the same problem as last time? (US-33, #325)

WHY THIS EXISTS
    "What changed since the last scan" (#315) and storing scan history (#223)
    both need to know whether a finding today is the same problem as one
    last week. A finding's `id` cannot answer that, and neither can the
    obvious structured fields. Both measured on real Batfish output, 15
    September 2026, six fixtures, 25 findings:

    1. `id` IS NOT IDENTITY. It is assigned per run, and access_control
       numbers positionally. The same id names different problems:

           AC-001  rtr-us5-insecure   Unencrypted web traffic reaches the
                                      internal server
           AC-001  rtr-us5-messy      DNS to the approved server is blocked
           AC-001  routing-secure     3 access policy statement(s) could not
                                      be checked

    2. (check, device, evidence.source) IS NOT IDENTITY EITHER.
       ("access_control", "rtr-us5", "rtr-us5:acl_in") is shared by three
       different problems, and the policy_compliance equivalent by five.

    3. EVEN THE SUMMARY IS NOT ENOUGH. rtr-us5-messy reports two dead rules
       with identical check, device, source AND summary -- "ACL rule never
       takes effect in acl_in" -- told apart only by `evidence.detail`:

           Unreachable line: permit udp ... host 218.8.104.58 eq domain
           Unreachable line: permit tcp ... host 10.20.0.5 eq 443

       A key without `detail` merges them, so fixing one dead rule would be
       reported as nothing having changed.

WHAT THE FINGERPRINT IS BUILT FROM, AND WHY EACH FIELD IS IN OR OUT
    IN   check, device, evidence.source, summary, evidence.detail
    OUT  id        -- positional, and collides (point 1)
    OUT  severity  -- `risk` and business context re-rate it; the same
                      problem re-rated is still the same problem
    OUT  status    -- the diff COMPARES status, so identity must not depend
                      on it

    `detail` was the field to worry about: searchFilters evidence carries an
    example flow Batfish chose, `[10.10.10.0:49152->8.8.8.8:80 TCP (SYN)]`.
    If Batfish picked a different example each run, every scan would give
    the same problem a new identity. Measured: four complete runs over all
    six fixtures produced byte-identical findings, every field. So it is in.

    Whitespace is normalised, because `evidence.source` is already written
    two ways by the same check -- "rtr-us5:acl_in" and "rtr-us5: acl_in".

SIMILARITY IS A HINT, NEVER A MERGE
    The acceptance criterion asks for a similarity measure on the free text,
    to catch a finding whose wording changed between Netwise versions. It is
    here -- but it does not decide identity, because the measurement says it
    cannot:

        highest similarity, DIFFERENT problems, same structural key   0.732
          "Unencrypted web traffic is allowed out of the internal subnet"
          "Unencrypted web traffic reaches the internal server"
        lowest similarity, SAME problem reworded (from git history)   0.748

    A gap of 0.016, calibrated on two real rewordings. Any threshold in it
    is fitted to two data points, and the pair just below it are two
    different problems -- a guarantee violation and a policy statement. A
    matcher that merged them would report one as "unchanged" on the day it
    was fixed and the other appeared.

    So `compare()` never moves a finding out of `new` or `resolved` on a
    guess. Similar pairs are reported alongside, in `possibly_same`, for a
    person to judge. Over-flagging costs a reader a glance; merging costs a
    user a false "unchanged" -- F-4's shape, arriving through history.

KNOWN LIMIT, STATED RATHER THAN DISCOVERED
    `evidence.source` and `evidence.detail` carry config-derived text -- a
    line number such as `configs/rtr-us5.cfg:[37]`, or an ACL line. Editing
    an UNRELATED part of a config can shift those, and the same problem then
    appears as one `resolved` and one `new`. That is the conservative
    failure: two real problems are never merged into one. `possibly_same`
    is where such a pair surfaces.

Pure functions. No Batfish, no web import, no persistence -- storing
fingerprints is #223, and presenting the diff is #315.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Mapping, Sequence

#: A pair whose summaries are at least this similar is reported in
#: `possibly_same`. DELIBERATELY LOW. It only ever adds a hint, so a false
#: positive costs a glance while a false negative hides a likely rewording.
#: It is below 0.732 on purpose: that pair ARE different problems, and
#: flagging them for a person is exactly right -- merging them would not be.
POSSIBLY_SAME_THRESHOLD = 0.6

_WHITESPACE = re.compile(r"\s+")


def _text(value: Any) -> str:
    """Case- and whitespace-insensitive, and nothing else.

    Deliberately NOT stripping digits or punctuation: an IP, a port or an
    ACL line is exactly what separates two real problems (see point 3 in the
    module docstring).
    """
    return _WHITESPACE.sub(" ", str(value or "")).strip().lower()


def _source(value: Any) -> str:
    """`evidence.source` with ALL whitespace removed.

    The same check writes "rtr-us5:acl_in" and "rtr-us5: acl_in". A source
    is an identifier, never prose, so no space in it carries meaning.
    """
    return _WHITESPACE.sub("", str(value or "")).lower()


def fingerprint(finding: Mapping[str, Any]) -> str:
    """A stable identity for the PROBLEM a finding describes.

    Same problem, any run, any severity re-rating, any status -> same value.
    Different problem -> different value, including two dead rules that
    share every field but `evidence.detail`.
    """
    evidence = finding.get("evidence") or {}
    canonical = [
        _text(finding.get("check")),
        _text(finding.get("device")),
        _source(evidence.get("source")),
        _text(finding.get("summary")),
        _text(evidence.get("detail")),
    ]
    payload = json.dumps(canonical, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def similarity(a: Mapping[str, Any], b: Mapping[str, Any]) -> float:
    """How alike two findings' summaries read, 0.0 to 1.0. A hint only."""
    return difflib.SequenceMatcher(
        None, _text(a.get("summary")), _text(b.get("summary"))).ratio()


def compare(previous: Sequence[Mapping[str, Any]],
            current: Sequence[Mapping[str, Any]]) -> Dict[str, List[Any]]:
    """Partition two scans into unchanged, new and resolved -- plus hints.

    Returns a dict with four keys:

        unchanged      findings from `current` whose problem was also in
                       `previous`
        new            findings in `current` only
        resolved       findings in `previous` only
        possibly_same  (resolved, new, similarity) tuples: same check and
                       device, summaries alike. Each finding in a pair is
                       STILL in `resolved` or `new` -- nothing is moved on a
                       guess.

    Counts are honoured, not collapsed. If `previous` holds a fingerprint
    twice and `current` once, one is unchanged and one is resolved. None of
    the six fixtures produces a duplicate today; this is so a future one
    cannot quietly swallow a problem.

    WHAT THIS DOES NOT DO
        It does not decide what a status change means. A check that went
        from finding problems to being unable to run is "newly blind", and
        #315 requires that to be its own category rather than "resolved".
        That is the diff's job, one layer up; this function only says which
        problems are the same.
    """
    prev_by_fp: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for finding in previous:
        prev_by_fp[fingerprint(finding)].append(finding)

    unmatched_prev = Counter({fp: len(items) for fp, items in prev_by_fp.items()})
    unchanged: List[Mapping[str, Any]] = []
    new: List[Mapping[str, Any]] = []

    for finding in current:
        fp = fingerprint(finding)
        if unmatched_prev[fp] > 0:
            unmatched_prev[fp] -= 1
            unchanged.append(finding)
        else:
            new.append(finding)

    resolved: List[Mapping[str, Any]] = []
    for fp, items in prev_by_fp.items():
        # The LAST n of each fingerprint are the unmatched ones; which copy
        # is reported does not matter, because they are identical problems.
        remaining = unmatched_prev[fp]
        if remaining:
            resolved.extend(items[-remaining:])

    possibly_same = []
    for old in resolved:
        for fresh in new:
            if (_text(old.get("check")) == _text(fresh.get("check"))
                    and _text(old.get("device")) == _text(fresh.get("device"))):
                score = similarity(old, fresh)
                if score >= POSSIBLY_SAME_THRESHOLD:
                    possibly_same.append((old, fresh, round(score, 3)))

    return {
        "unchanged": unchanged,
        "new": new,
        "resolved": resolved,
        "possibly_same": possibly_same,
    }
