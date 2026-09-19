"""Load the shipped CVE reference dataset (#239, AC-3 and AC-4).

OFFLINE, STRUCTURALLY, NOT BY POLICY
    Netwise is air-gapped by requirement (CLAUDE.md section 5), so "does not
    fetch" cannot be a rule someone remembers -- it has to be a property of
    the code. This module imports `json` and `pathlib` and nothing else. There
    is no URL anywhere in it, no `requests`, no `urllib`, and no parameter
    that could become one. `tests/test_cve_data.py` asserts that by reading
    this file's own imports, so adding a network call here fails a test rather
    than passing review.

WHY A LOADER AT ALL, RATHER THAN json.load() AT THE CALL SITE
    The same reason `analysis/policy.py` exists. A dataset that half-loads is
    worse than one that does not load: a missing `assessed` list would make
    every train look like "no data", which is a defensible-looking answer that
    happens to be wrong for every device. So the shape is validated once, here,
    and a malformed file raises rather than degrading quietly.

    This file is OURS, not the user's, which changes what the validation is
    for but not whether it should exist. It is not defending against a hostile
    edit; it is defending against a careless one -- a trailing comma removed, a
    train added to `advisories` and forgotten in `assessed` -- where the
    failure would otherwise be a wrong finding rather than an error.

THE ONE INVARIANT WORTH MORE THAN THE REST
    Every train carrying advisories MUST also appear in `assessed`. The two
    lists encode different claims -- "we looked at this train" and "here is
    what we found" -- and a train with findings but no assessment is
    incoherent. More importantly the drift is silent in the dangerous
    direction: a check asking `is_assessed()` first would report "no data" for
    a train we have real CVEs for. Validated at load, not trusted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

#: The shipped dataset. A path, resolved relative to this module, so it works
#: from any working directory and under both `python -m` and `python path/to`.
DEFAULT_DATASET = Path(__file__).parent / "data" / "cisco_ios_cves.json"

#: A published CVE identifier. Checked because an invented or mistyped id is
#: the one error in this file a reader cannot catch by eye -- "CVE-2018-0171"
#: and "CVE-2018-171" look alike and only one is real. This validates the
#: SHAPE, which is all a regex can do; that the id exists is a matter of
#: having transcribed it from a real advisory.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

#: A Cisco IOS train, as a running-config writes it: major.minor.
_TRAIN = re.compile(r"^\d+\.\d+$")

_REQUIRED_TOP_LEVEL = ("dataset_version", "generated", "assessed", "advisories")
_REQUIRED_ADVISORY_KEYS = ("id", "title", "cisco_severity")


class CveDataError(ValueError):
    """The dataset could not be loaded. Deliberately a ValueError, matching
    `PolicyError` and `BusinessContextError`, so a caller already catching
    bad input keeps working."""


class CveData:
    """The dataset, validated. Read-only from the caller's point of view.

    `assessed` and `advisories` are deliberately separate, and the two
    questions a caller asks are separate too:

        is_assessed(train)     have we looked at this train at all?
        advisories_for(train)  what did we find?

    A caller that only asked the second one could not tell "assessed, nothing
    found" from "never looked", which is exactly the conflation AC-2 forbids.
    """

    def __init__(
        self,
        dataset_version: str,
        generated: str,
        assessed: Sequence[str],
        advisories: Mapping[str, Sequence[Mapping[str, Any]]],
        source: str = "",
        scope: str = "",
    ) -> None:
        self.dataset_version = dataset_version
        self.generated = generated
        self.source = source
        self.scope = scope
        self._assessed = frozenset(assessed)
        self._advisories = {k: list(v) for k, v in advisories.items()}

    # -- the two questions ---------------------------------------------------

    def is_assessed(self, train: Optional[str]) -> bool:
        """Have we looked at this train at all?

        False is "we have no data", NOT "it is fine". The check turns this
        into `status="error"`, and that is the whole of AC-2.
        """
        return isinstance(train, str) and train in self._assessed

    def advisories_for(self, train: Optional[str]) -> List[Dict[str, Any]]:
        """What we recorded for this train. Empty list for an assessed train
        with nothing recorded, and ALSO empty for an unassessed one -- so a
        caller must ask `is_assessed()` first. That asymmetry is deliberate
        and is why the two are separate methods rather than one that returns
        `None` vs `[]`; a caller reading a falsy value would treat both the
        same, which is the bug AC-2 describes.
        """
        if not isinstance(train, str):
            return []
        return [dict(a) for a in self._advisories.get(train, [])]

    # -- staleness (AC-3) ----------------------------------------------------

    def provenance(self) -> str:
        """One line naming the dataset and its date, for a finding's evidence.

        AC-3 asks that "the reference dataset is versioned and its date is
        shown, so a stale dataset is visible". Visible means ON THE FINDING --
        a version recorded only in the file is visible to whoever opens the
        file, which is not the person reading the result.
        """
        return (
            f"CVE dataset {self.dataset_version}, compiled {self.generated}"
            f"{f' from {self.source}' if self.source else ''}"
        )

    @property
    def assessed_trains(self) -> List[str]:
        """Sorted, for a message that has to list them."""
        return sorted(self._assessed)


def _fail(message: str) -> None:
    raise CveDataError(f"{DEFAULT_DATASET.name}: {message}")


def _validate_advisory(train: str, index: int, entry: Any) -> None:
    where = f"advisories[{train!r}] entry {index}"

    if not isinstance(entry, Mapping):
        _fail(f"{where}: expected an object, got {type(entry).__name__}")

    for key in _REQUIRED_ADVISORY_KEYS:
        if not entry.get(key):
            _fail(f"{where}: missing required key {key!r}")

    if not _CVE_ID.match(str(entry["id"])):
        _fail(
            f"{where}: {entry['id']!r} is not a CVE identifier. Expected "
            f"CVE-YYYY-NNNN. A mistyped id points a reader at the wrong "
            f"advisory, or at none"
        )


def load_cve_data(path: Optional[Path] = None) -> CveData:
    """Load and validate the dataset. Raises `CveDataError`, never degrades.

    `path` exists so a test can load a fixture dataset. It is a filesystem
    path and there is no code path here that would accept a URL -- see the
    module docstring on why that is structural rather than a convention.
    """
    dataset_path = Path(path) if path is not None else DEFAULT_DATASET

    try:
        raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"not found at {dataset_path}. The dataset ships with the "
              f"repository; it is never downloaded")
    except json.JSONDecodeError as exc:
        _fail(f"is not valid JSON ({exc})")

    if not isinstance(raw, Mapping):
        _fail(f"expected an object at the top level, got {type(raw).__name__}")

    for key in _REQUIRED_TOP_LEVEL:
        if key not in raw:
            _fail(f"missing required key {key!r}")

    assessed = raw["assessed"]
    if not isinstance(assessed, list) or not all(isinstance(t, str) for t in assessed):
        _fail("'assessed' must be a list of train strings")
    for train in assessed:
        if not _TRAIN.match(train):
            _fail(f"'assessed' contains {train!r}, which is not a major.minor "
                  f"train. A config's version line only ever carries one")

    advisories = raw["advisories"]
    if not isinstance(advisories, Mapping):
        _fail("'advisories' must be an object keyed by train")

    for train, entries in advisories.items():
        if not isinstance(entries, list):
            _fail(f"advisories[{train!r}] must be a list")
        # THE INVARIANT. See the module docstring: a train with findings but
        # no assessment is incoherent, and the drift is silent in the
        # dangerous direction -- the check asks is_assessed() first and would
        # report "no data" for a train we hold real CVEs for.
        if train not in assessed:
            _fail(
                f"advisories[{train!r}] has {len(entries)} entr(y/ies) but "
                f"{train!r} is not in 'assessed'. Every train we have findings "
                f"for is by definition a train we looked at; leaving it out "
                f"would make the check report 'no data' for it"
            )
        for index, entry in enumerate(entries, start=1):
            _validate_advisory(train, index, entry)

    return CveData(
        dataset_version=str(raw["dataset_version"]),
        generated=str(raw["generated"]),
        assessed=assessed,
        advisories=advisories,
        source=str(raw.get("source", "")),
        scope=str(raw.get("scope", "")),
    )
