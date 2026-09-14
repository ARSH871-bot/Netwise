"""Stop a rebuild from silently throwing away somebody's hand edits.

WHY THIS EXISTS
    On 7 September the Client Confirmation Letter was rebuilt-checked against
    the copy on disk and the two did not match: the disk copy was 62 words
    shorter and carried one extra paragraph. That was not a bug -- Arsh had
    deleted the instruction box and rewritten a sentence before sending it to
    the client at 10:42 that morning.

    Every builder in this folder writes its document from scratch. Re-running
    build_client_letter.py would have reverted a letter that had already left
    the building, and nothing would have said so. The same trap had already
    been hit once before, when a Kanban screenshot pasted straight into the
    Group Final Report was nearly dropped by a rebuild.

    So the check is performed rather than documented. A comment saying "mind
    the hand edits" is exactly the shape this project keeps failing on: a
    documented practice standing in for a performed one.

WHAT IT DOES NOT DO
    It does not merge, and it does not guess which version is better. It
    refuses, prints what differs, and hands the decision back. `--force` is
    the deliberate override, and it says so in the refusal.
"""
import pathlib
import sys


def blocks(document):
    """Every piece of text in a .docx: paragraphs AND table cells.

    TABLE CELLS ARE NOT OPTIONAL HERE, and leaving them out was the first
    version's bug. The cover sheet of every one of these documents is a table,
    and the cover sheet is exactly where a hand edit lands -- a student ID
    typed straight into Word is a table-cell edit and nothing else. A guard
    that compared paragraphs only would have watched Thursday's rebuild
    silently discard the two IDs we are still waiting on, while reporting that
    it had checked.

    Which is the same defect this whole project is about, built into the thing
    meant to prevent it.
    """
    out = [p.text.strip() for p in document.paragraphs]
    for t in document.tables:
        for row in t.rows:
            out.extend(c.text.strip() for c in row.cells)
    return out


def _on_disk(path):
    """Text of an existing .docx, or None if it cannot be read as one."""
    try:
        from docx import Document
        return blocks(Document(str(path)))
    except Exception:                                   # noqa: BLE001
        return None


def refuse_if_edited(out, new_paragraphs, argv=None):
    """Exit before saving if the file on disk is not what this script last wrote.

    `new_paragraphs` is what the script is about to save. Pass
    `[p.text for p in d.paragraphs]` from the Document you just built.
    """
    argv = sys.argv if argv is None else argv
    out = pathlib.Path(out)
    if "--force" in argv or not out.exists():
        return

    old = _on_disk(out)
    if old is None:
        return                                  # not a readable .docx; let it write
    new = [str(p).strip() for p in new_paragraphs]
    if old == new:
        return

    import difflib
    print(f"\n  REFUSING to overwrite {out.name}")
    print("  The copy on disk is not what this script produces, which means")
    print("  somebody edited it by hand. Rebuilding would discard that.\n")
    shown = 0
    for line in difflib.unified_diff(old, new, "on disk", "this rebuild",
                                     lineterm="", n=0):
        if line.startswith(("---", "+++", "@@")):
            continue
        tag = "on disk only" if line.startswith("-") else "rebuild only"
        print(f"    {tag}: {line[1:][:110]}")
        shown += 1
        if shown >= 12:
            print("    ... (more)")
            break
    print(f"\n  If the rebuild really should win, re-run with --force.\n")
    raise SystemExit(1)
