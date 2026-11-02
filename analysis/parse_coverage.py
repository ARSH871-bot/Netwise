"""How much of each partly read file Batfish could read (#317, US-24).

WHY THIS EXISTS
    A file Batfish only partly understood already gets a caveat: the
    pipeline's "Results may be incomplete" finding. Until this, the caveat
    named the file and nothing else, so the user could not tell a file with
    one odd line from one Batfish barely read. This says how much, and what.

    Measured on `tests/fixtures/vendor-asa`, the one partly parsed fixture:

        configs/fw-asa.cfg (PARTIALLY_UNRECOGNIZED): Batfish did not recognise
        5 of its 16 configuration lines, so 11 were read -- nameif x2
        (lines 18, 23); security-level x2 (lines 19, 24); access-group x1
        (line 29)

    The `access-group` line is the one that applies the firewall's ACL, and
    the one behind #373's unused-filter misreport. Naming it is the point.

WHERE THE NUMBERS COME FROM
    The unrecognised lines are Batfish's own `parseWarning` rows whose comment
    is "This syntax is unrecognized"; nothing here parses the config. The
    total is the file's lines read from disk, because Batfish does not report
    one.

WHY THE TOTAL EXCLUDES COMMENTS, AND ONLY SOMETIMES
    fw-asa.cfg has 36 lines and 20 are `!` comments. Counting them would say
    "31 of 36 read" (86%) about a file whose configuration Batfish read 11 of
    16 lines of (69%) -- a figure that looks better than the truth. So comment
    and blank lines are left out of the total, but only for formats whose
    comment marker is known (COMMENT_MARKERS). For any other format the total
    is the non-blank lines and the sentence says comments were not excluded,
    rather than guessing a marker.

WHAT THE CALLER MUST DO WITH A FAILURE
    `describe()` raises if Batfish cannot answer or a file cannot be read.
    The pipeline then falls back to naming the files, as it always has: a
    failure to measure coverage must never cost the user the caveat itself.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

#: The comment marker for each Batfish file format we are sure of. Batfish
#: reports `File_Format` per file; vendor-asa, for instance, comes back as
#: CISCO_IOS. A format missing here is counted without excluding comments.
COMMENT_MARKERS: Dict[str, str] = {
    "CISCO_IOS": "!",
    "CISCO_IOS_XR": "!",
    "CISCO_NX": "!",
    "CISCO_ASA": "!",
    "ARISTA": "!",
}

#: The `parseWarning` comment that means "Batfish did not understand this line".
UNRECOGNIZED = "This syntax is unrecognized"


def describe(bf: Any, config_dir: Path, status: str) -> List[str]:
    """One sentence for each file whose parse status is `status`."""
    files = bf.q.fileParseStatus().answer().frame()
    warnings = bf.q.parseWarning().answer().frame()
    sentences = []
    for _, row in files.iterrows():
        if row["Status"] != status:
            continue
        name = str(row["File_Name"])
        unread = [
            (int(warning["Line"]), str(warning["Text"]))
            for _, warning in warnings.iterrows()
            if str(warning["Filename"]) == name and str(warning["Comment"]) == UNRECOGNIZED
        ]
        sentences.append(_sentence(name, status, str(row.get("File_Format", "")),
                                   unread, Path(config_dir) / name))
    return sentences


def _sentence(name: str, status: str, file_format: str,
              unread: List[Tuple[int, str]], path: Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    marker = COMMENT_MARKERS.get(file_format)
    if marker:
        total = sum(1 for line in lines if line.strip() and not line.strip().startswith(marker))
        counted = f"configuration lines ('{marker}' comment and blank lines not counted)"
    else:
        total = sum(1 for line in lines if line.strip())
        counted = (f"non-blank lines (comments not excluded: no comment marker "
                   f"is known for format {file_format or 'unknown'})")

    if not unread:
        # "0 of 16 not recognised" would read as fully read, and Batfish has
        # said the opposite. Say what is known instead.
        return (f"{name} ({status}): Batfish reports this file as only partly "
                f"read but named no specific line, so how much was missed is "
                f"not known")

    return (f"{name} ({status}): Batfish did not recognise {len(unread)} of its "
            f"{total} {counted}, so {total - len(unread)} were read -- "
            f"{_by_kind(unread)}")


def _by_kind(unread: List[Tuple[int, str]]) -> str:
    """"nameif x2 (lines 18, 23); access-group x1 (line 29)", most common first.

    The kind is the line's first word: what a reader would look for in the
    file. It is a grouping of Batfish's own text, not an interpretation of it.
    """
    kinds = Counter(text.split()[0].lower() for _, text in unread if text.split())
    parts = []
    for kind, count in sorted(kinds.items(), key=lambda item: (-item[1], item[0])):
        numbers = sorted(n for n, text in unread if text.split() and text.split()[0].lower() == kind)
        label = "line" if len(numbers) == 1 else "lines"
        parts.append(f"{kind} x{count} ({label} {', '.join(str(n) for n in numbers)})")
    return "; ".join(parts)
