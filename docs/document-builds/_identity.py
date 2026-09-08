"""Student names and IDs, loaded from a file that is NOT tracked.

WHY THIS EXISTS
    #290 excluded `/docs/Feedback/` from the repository and gave the reason in
    `.gitignore` itself:

        These carry student IDs, a marker's written assessment of an
        individual, and cover sheets belonging to different team members.
        They are correspondence about people, not project artefacts.

        The deciding fact is that this repository was PUBLIC until 31 August
        and the visibility has already changed twice. A file that is only
        safe while a setting stays where it is should not be tracked at all.

    The first version of `docs/document-builds/` walked the same content back
    in through the generator rather than the output: a cover-sheet line
    carrying two members' student IDs, one of which belongs to somebody else.
    Caught in review on #311 before it merged, which is the only moment the
    decision is cheap.

    So the structure of every document is tracked and anybody can rebuild it.
    The identifiers are not, and each person supplies their own.

SETUP
    Copy `docs/identity.example.json` to `docs/identity.json` and fill it in.
    That path is gitignored. Missing IDs render as the name alone, so a
    half-filled file produces a document that is honest about what it does
    not know rather than one that invents it.
"""
import json
import pathlib

_PATH = pathlib.Path(__file__).resolve().parents[1] / "identity.json"
_EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "identity.example.json"


def load():
    """The identity file, or a loud failure explaining how to create it.

    Deliberately raises rather than falling back to placeholders. A cover
    sheet that silently says "Student ID: unknown" is the kind of thing that
    reaches a marker, and this project's whole argument is that a missing
    fact should be visible at the moment it goes missing.
    """
    if not _PATH.exists():
        raise SystemExit(
            f"\n  {_PATH.name} is missing.\n\n"
            f"  It carries student names and IDs and is deliberately NOT in git\n"
            f"  (see the docstring in {pathlib.Path(__file__).name}, and #290).\n\n"
            f"  Create it:   copy {_EXAMPLE.name} -> {_PATH.name}, then fill it in.\n"
            f"  Location:    {_PATH}\n"
        )
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"\n  {_PATH} is not valid JSON: {exc}\n")

    members = data.get("team_members")
    if not isinstance(members, list) or not members:
        raise SystemExit(f"\n  {_PATH} has no 'team_members' list.\n")
    return data


def team_members_line(data=None):
    """All four names with IDs, or all four names with none. Never a mixture.

    ALL OR NOTHING, AND BOTH TEAMMATES WHO RAISED THIS WERE RIGHT
        @shubhamkataria2005 objected on #311 that the cover named two of four
        members with IDs and two without, and that this was an accident
        rather than a decision. @patelankeet2 then hand-removed every ID from
        the cover in his edit of the report, which is the same objection
        arriving as a fix.

        So the rule is: if every member has an ID, show them all. If any is
        missing, show names only and let the ACTION box say which are
        outstanding. A partial list is the one option nobody wanted, and it
        was the only one the previous version could produce.

        Ankeet's outcome is what this returns today. The moment the last ID
        lands in identity.json it becomes ours again, with no code change.
    """
    data = load() if data is None else data
    people = [(str(m.get("name", "")).strip(), str(m.get("student_id", "")).strip())
              for m in data["team_members"]]
    people = [(n, sid) for n, sid in people if n]
    if people and all(sid for _, sid in people):
        return "; ".join(f"{n} ({sid})" for n, sid in people)
    return "; ".join(n for n, _ in people)


def missing_ids(data=None):
    """Names with no student ID yet, so a build can say so out loud."""
    data = load() if data is None else data
    return [str(m.get("name", "")).strip() for m in data["team_members"]
            if not str(m.get("student_id", "")).strip() and m.get("name")]
