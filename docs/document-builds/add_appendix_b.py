"""Put the three Appendix B screenshots into build_group_report.py.

Arsh pasted the Kanban screenshot straight into the .docx. Re-running the build
would have thrown it away, because the script writes the file from scratch. So
the image is extracted, saved beside the other two, and referenced from the
build -- which means Thursday's rebuild reproduces all three instead of losing
one.

Single-line anchors only; multi-line ones failed 13 of 14 times earlier today.
"""
import ast
import pathlib

P = pathlib.Path(__file__).resolve().parent / "build_group_report.py"
lines = P.read_text(encoding="utf-8").split("\n")

# Find the Appendix B heading and the action() call under it.
start = next(i for i, l in enumerate(lines) if 'h("Appendix B — Screenshots", 2)' in l)
end = next(i for i, l in enumerate(lines[start:], start)
           if 'h("Appendix C' in l)

NEW = '''h("Appendix B — Screenshots", 2)
p("Three screenshots, taken from a real run on 7 September 2026 against the "
  "repository at commit 00243fb. Nothing here is mocked or staged: the "
  "dashboard and the report were produced by uploading a test configuration "
  "and pressing Scan Now, and the report image is of the file the download "
  "button actually produces.")

figure("1-dashboard-rtr-us5-insecure.png",
       "Screenshot 1. The dashboard after scanning a deliberately insecure test "
       "configuration. The three counts read 5 problems, 0 checked-clean and 1 "
       "could-not-check, and the amber card appears above the problems. The "
       "counts are shown separately and are never added together.", width=5.9)

figure("2-github-projects-board.png",
       "Screenshot 2. The GitHub Projects board, one column per state. This is "
       "the board the team worked from, with one milestone per sprint.", width=5.9)

figure("3-exported-report-could-not-check-first.png",
       "Screenshot 3. The exported HTML report, opened from the file the "
       "download button produces. \\u201cCould not check\\u201d is the first findings "
       "section, before problems found and before the clean results, and the "
       "clean section is present even though it is empty.", width=5.4)

p("The report header names the file as device.cfg although the upload was "
  "rtr-us5.cfg. That is deliberate: the upload never writes a user-supplied "
  "filename to disk, so a client string cannot reach the filesystem. The "
  "dashboard shows the name the user chose; the report names the file we "
  "staged.")
'''

lines[start:end] = NEW.rstrip("\n").split("\n")
src = "\n".join(lines)
P.write_text(src, encoding="utf-8")
ast.parse(src)
print(f"  Appendix B replaced ({end - start} lines -> {len(NEW.splitlines())})")
