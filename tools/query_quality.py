"""Score the held-out question set for ai/query.py (US-60, #393).

WHAT THIS DOES
    Runs every question in tests/fixtures/query_quality/holdout.json through
    the REAL answer_question(), against a FakeSession built fresh from each
    entry's own configuration, and tallies the four outcomes
    docs/evaluation.md Part 2 already reports by hand: answered-correct,
    refused-correctly, refused-but-should-have-answered, and answered-wrong
    -- the one that matters, because a tool that answers confidently and
    wrongly about a firewall is the exact failure this whole project exists
    to avoid.

WHY THIS RUNS THE REAL CODE EVERY TIME, UNLIKE #385's HELD-OUT SET
    #385 (tools/explanation_quality.py) had to freeze a human rating of
    MODEL-WRITTEN PROSE, because the model's text varies run to run and
    judging whether it reads well needs a person. ai/query.py calls no
    model in either direction (CLAUDE.md 7c) -- it is pure, deterministic
    classification and resolution over a snapshot, real or faked. There is
    nothing here that can go stale the way #385's captured text can, so
    there is no staleness-hash check and no frozen output: this tool
    EXECUTES answer_question() against each entry's real FakeSession, every
    time it runs, which is strictly stronger evidence than replaying a
    snapshot of a past run.

OUTCOME CLASSIFICATION
    answered_correct          grounded, and matches the entry's expectation
    answered_wrong             grounded, but does NOT match -- the dangerous one
    refused_correctly          not grounded, as the entry expects
    refused_but_should_answer  not grounded, but the entry expected an answer

RUN IT BY HAND
    python -m tools.query_quality
    python tools/query_quality.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.query import answer_question

#: Resolved relative to this file, not the caller's working directory --
#: the same reasoning tools/explanation_quality.py's DEFAULT_HOLDOUT_PATH
#: already uses, so this runs correctly from either documented invocation
#: form regardless of which one put the repository root on sys.path.
DEFAULT_HOLDOUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "tests" / "fixtures" / "query_quality" / "holdout.json"
)

#: "Answered and wrong" must never happen -- not a budget, a floor of zero.
#: Grounded in the same clean record docs/evaluation.md Part 2 already
#: measured by hand (0 of 20 on 10 August), and in the project's own stated
#: reason the question feature refuses rather than guesses at every
#: ambiguous step (CLAUDE.md 7c).
QUERY_QUALITY_THRESHOLD = {"max_answered_wrong": 0}


class FakeHop:
    def __init__(self, node: str):
        self.node = node


class FakeTrace:
    def __init__(self, disposition: str, hops=None):
        self.disposition = disposition
        self.hops = hops or [FakeHop("some-node")]


class _FakeAnswer:
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _FakeFrame:
    def __init__(self, rows):
        self._rows = rows

    @property
    def empty(self):
        return len(self._rows) == 0

    def __len__(self):
        return len(self._rows)

    def iterrows(self):
        return enumerate(self._rows)

    class _Iloc:
        def __init__(self, rows):
            self._rows = rows

        def __getitem__(self, index):
            return self._rows[index]

    @property
    def iloc(self):
        return self._Iloc(self._rows)


class _FakeQuestions:
    def __init__(
        self, *, devices=frozenset(), traceroute_frame=None,
        whole_snapshot_frame=None, raises=False,
    ):
        self._devices = devices
        self._traceroute_frame = traceroute_frame
        self._whole_snapshot_frame = whole_snapshot_frame
        self._raises = raises
        self.traceroute_calls: List[Dict[str, Any]] = []

    def fileParseStatus(self, **_kwargs):
        if self._devices is None:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(_FakeFrame([{"Nodes": sorted(self._devices)}]))

    def traceroute(self, **kwargs):
        self.traceroute_calls.append(kwargs)
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._traceroute_frame)

    def filterLineReachability(self, **_kwargs):
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._whole_snapshot_frame)

    def undefinedReferences(self, **_kwargs):
        if self._raises:
            raise RuntimeError("Batfish said no")
        return _FakeAnswer(self._whole_snapshot_frame)


class FakeSession:
    def __init__(self, questions):
        self.q = questions


def _build_fake_session(config: Dict[str, Any]) -> FakeSession:
    """Reconstruct the FakeSession a holdout entry's `fake_session` block
    describes. The JSON shape is deliberately the same information
    tests/test_query_translation.py's own FakeSession classes take, just
    serialisable -- this is the one translation layer between the two."""
    devices = config.get("devices", [])
    devices = set(devices) if devices is not None else None

    traceroute_frame = None
    if "traceroute_frame_rows" in config:
        rows = []
        for row in config["traceroute_frame_rows"]:
            traces = [
                FakeTrace(t["disposition"], hops=[FakeHop(h) for h in t.get("hops", [])] or None)
                for t in row.get("traces", [])
            ]
            rows.append({"Traces": traces})
        traceroute_frame = _FakeFrame(rows)

    whole_snapshot_frame = None
    if "whole_snapshot_frame_rows" in config:
        whole_snapshot_frame = _FakeFrame(config["whole_snapshot_frame_rows"])

    questions = _FakeQuestions(
        devices=devices,
        traceroute_frame=traceroute_frame,
        whole_snapshot_frame=whole_snapshot_frame,
        raises=config.get("raises", False),
    )
    return FakeSession(questions)


def load_holdout(path: Path = DEFAULT_HOLDOUT_PATH) -> List[Dict[str, Any]]:
    """The held-out set's `entries` list, read from `path`."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)["entries"]


def _matches_expectation(entry: Dict[str, Any], result: Dict[str, Any]) -> bool:
    """Whether a grounded `result` matches what `entry` expected of it."""
    answer = result["answer"]
    if "answer_starts_with" in entry and not answer.startswith(entry["answer_starts_with"]):
        return False
    if "answer_contains" in entry and entry["answer_contains"] not in answer:
        return False
    if "understood_expected" in entry and result["question_understood"] != entry["understood_expected"]:
        return False
    return True


def score_holdout(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run every entry's question through the real answer_question(), and
    tally the four outcomes. Raises ValueError on an empty set -- the same
    F-4 reasoning tools/explanation_quality.py's score_holdout() already
    uses: a score with nothing behind it must never print as a number."""
    if not entries:
        raise ValueError("cannot score: the held-out set is empty")

    counts = {
        "answered_correct": 0, "answered_wrong": 0,
        "refused_correctly": 0, "refused_but_should_answer": 0,
    }
    details: List[Dict[str, Any]] = []

    for entry in entries:
        session = _build_fake_session(entry.get("fake_session", {}))
        result = answer_question(entry["question"], session)
        expected = entry["outcome_expected"]
        should_ground = expected == "answered_correct"

        if result["grounded"] and should_ground:
            actual = "answered_correct" if _matches_expectation(entry, result) else "answered_wrong"
        elif result["grounded"] and not should_ground:
            # Answered when the entry says this should have been refused --
            # always the dangerous bucket, regardless of what the answer
            # text happens to say.
            actual = "answered_wrong"
        elif not result["grounded"] and should_ground:
            actual = "refused_but_should_answer"
        else:
            actual = "refused_correctly"

        counts[actual] += 1
        details.append({
            "id": entry["id"], "question": entry["question"],
            "expected": expected, "actual": actual,
            "answer": result["answer"],
        })

    return {
        "n_entries": len(entries),
        "counts": counts,
        "details": details,
    }


def _print_report(score: Dict[str, Any]) -> None:
    counts = score["counts"]
    print(f"Held-out question set: {score['n_entries']} entries")
    for key in ("answered_correct", "refused_correctly", "refused_but_should_answer", "answered_wrong"):
        print(f"  {key}: {counts[key]}")
    mismatches = [d for d in score["details"] if d["expected"] != d["actual"]]
    if mismatches:
        print("\nMismatches (expected != actual):")
        for d in mismatches:
            print(f"  {d['id']}: expected {d['expected']!r}, got {d['actual']!r} -- {d['question']!r}")
            print(f"    answer: {d['answer']!r}")


if __name__ == "__main__":
    entries = load_holdout()
    score = score_holdout(entries)
    _print_report(score)
    if score["counts"]["answered_wrong"] > QUERY_QUALITY_THRESHOLD["max_answered_wrong"]:
        sys.exit(1)
