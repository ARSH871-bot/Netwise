"""Extract the software version a Cisco IOS config declares (#239, AC-1).

WHY THIS READS RAW TEXT RATHER THAN ASKING BATFISH
    Every other analysis in this project reads Batfish's vendor-neutral model,
    which is the right default: Batfish has already done the parsing, and
    re-parsing config text ourselves is how two components start disagreeing
    about what a config says.

    The software version is the one thing the model does not carry. Measured
    against a live Batfish rather than assumed -- `nodeProperties` returns 37
    columns for a Cisco IOS snapshot and the closest any of them gets is:

        Configuration_Format = CISCO_IOS

    That is the vendor and the syntax family. It is not a version, and nothing
    else in the model is either. So AC-1 cannot be satisfied from the model,
    and this module exists because of that measurement -- not because reading
    text was preferred.

WHAT IT DELIBERATELY DOES NOT DO
    It does not decide whether a version is *vulnerable*, and it does not know
    what CVEs are. It answers one question -- "what does this file say its
    version is?" -- and returns None when the file does not say. Everything
    downstream treats None as "we could not find out", never as "fine".

THE LIMITATION THAT SHAPES EVERYTHING DOWNSTREAM, STATED HERE BECAUSE IT IS
EASIEST TO MISS
    A running-config's `version` line carries the TRAIN, not the build:

        version 15.2

    The precise release -- 15.2(4)M6, say -- appears in `show version` output,
    which is runtime state and is not in an exported config at all. So the
    most this module can ever return is a train, and a CVE that affects
    15.2(4)M6 but not 15.2(4)M11 cannot be told apart from it here.

    That is a real limit on how precise any CVE match can be, and it belongs
    in the finding rather than in a comment nobody reads. `analysis/checks/
    cve_mapping.py` is required to say so on every finding it produces.
"""

from __future__ import annotations

import re
from typing import Optional

#: A top-level IOS `version` command.
#:
#: ANCHORED AT COLUMN 0, AND THAT IS THE WHOLE SAFETY PROPERTY.
#:     `version` appears in a Cisco config in several places that have
#:     nothing to do with the software release, and a loose search finds all
#:     of them:
#:
#:         ip ssh version 2                <- SSH protocol version
#:         ntp server 10.0.0.1 version 4   <- NTP protocol version
#:         standby 1 version 2             <- HSRP version, indented
#:         snmp-server ... v3              <- (different keyword, but same trap)
#:
#:     Every one of those either has another token first or is indented under
#:     a parent command. The software-version line is the only one that is
#:     the FIRST token of an unindented line, so that is what is matched.
#:     `^` with re.MULTILINE, and no `\s*` before `version`, is doing that
#:     work deliberately -- adding one would silently admit `standby 1
#:     version 2`'s indented cousins.
#:
#: THE VALUE IS CAPTURED AS WRITTEN, NOT NORMALISED.
#:     No stripping of a "12." prefix, no padding to two decimals, no
#:     coercion to a float -- "15.2" is a train identifier, not a number, and
#:     15.10 sorts after 15.9 only if you already know that. Comparison is the
#:     dataset's problem, and it compares strings.
#: `\r` IS IN THE TRAILING CLASS, AND IT WAS NOT AT FIRST.
#:     Without it a CRLF file -- which is what a config exported from a
#:     Windows tool looks like, so precisely what a client sends -- matched
#:     nothing at all and the version came back None. Silently absent on the
#:     most likely real input, with no error to notice. Caught by the test
#:     that predicted it in its own docstring before the pattern was written;
#:     without that test this would still be here.
_VERSION_LINE = re.compile(r"^version[ \t]+(\S+)[ \t\r]*$", re.MULTILINE)

#: THERE IS NO COMMENT-STRIPPING STEP, AND THAT IS A DELIBERATE DELETION.
#:
#: This module first stripped `^!.*$` before matching, on the reasoning that a
#: commented-out version line is not a declaration. Correct reasoning, dead
#: code: a comment line begins with `!`, so it does not begin with `version`,
#: so the column-0 anchor above has already excluded it. Verified rather than
#: argued --
#:
#:     '! version 15.2'                 -> no match
#:     '!version 15.2'                  -> no match
#:     '! Upgraded from version 12.4'   -> no match
#:
#: -- and a mutation deleting the strip SURVIVED the whole suite, because
#: nothing depended on it.
#:
#: Removed rather than kept as defence in depth, for the reason
#: `analysis/checks/risk.py`'s `_escalate()` records about its one-level cap:
#: two guards enforcing the same thing, neither load-bearing on its own, means
#: a later reader can delete either one, watch the tests pass, and leave the
#: property resting entirely on the other without knowing it. One decision
#: point. The tests for commented-out version lines stay -- they assert the
#: BEHAVIOUR, which is unchanged, and they now pin the anchor doing the work.
#:
#: KNOWN LIMITATION, which neither approach covered: a `banner motd` block can
#: contain arbitrary text at column 0, so a banner whose body literally
#: contained a line `version 15.2` would be read as a declaration. Recorded
#: rather than fixed -- handling it means tracking banner delimiters, which is
#: config parsing of the kind this module exists to stay out of. It is also
#: far-fetched in a way the `ip ssh version 2` case is not.


def find_version(config_text: Optional[str]) -> Optional[str]:
    """The version this config declares, or None if it does not declare one.

    None means "this file does not say", and it is the honest answer for an
    empty file, a file with no version line, a file whose version line is
    commented out, and a file that contradicts itself. The caller must not
    read None as a version it can safely ignore -- see the check's AC-1
    handling, which turns it into `status="error"` rather than a skip.

    CONTRADICTORY LINES RETURN None RATHER THAN THE FIRST ONE.
        A single config should declare its version once. Two lines saying
        DIFFERENT things means something is wrong with the file -- most
        plausibly two configs concatenated -- and picking the first is a
        guess about which device we are looking at. This project refuses in
        that situation everywhere else it arises (see
        `analysis/pfsense_convert.py`'s rule-order handling), so it refuses
        here too.

        Two lines saying the SAME thing is not ambiguous and is accepted;
        there is only one answer it could be.

    Never raises. A None or non-string input is "no version found", because a
    caller that handed us something odd should get the cautious answer rather
    than an exception it then has to decide what to do with.
    """
    if not isinstance(config_text, str) or not config_text:
        return None

    found = _VERSION_LINE.findall(config_text)

    if not found:
        return None

    distinct = set(found)
    if len(distinct) > 1:
        # Contradictory declarations. See the docstring: refusing is the
        # point, and it is why this returns a set-size check rather than
        # `found[0]`.
        return None

    return found[0]
