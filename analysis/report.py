"""Netwise -- turn a findings list into a report that can leave the screen.

WHY THIS EXISTS
    Findings lived on one screen and nowhere else. There was no way to hand a
    result to somebody who was not watching when it ran, which is most of the
    people who need it: the person who has to fix it, the person who signs off
    that it was fixed, and the auditor who asks six months later.

    Three of the four capabilities proposed for the next phase produce
    something a reader would want to keep, and none of them can until this
    exists.

THE ONE RULE THIS FILE INHERITS (F-4)
    A report is more dangerous than a screen, because it is read later, by
    someone who cannot ask a question, and often by someone deciding whether
    the work is finished.

    So "could not check" is not a footnote here. It is the FIRST section, it
    is rendered even when it is empty, and its count is in the header
    alongside the others. A reader who skims must not be able to come away
    believing a config was fully checked when part of it was not.

    `docs/finding-format.md` is the contract; this module renders it and
    changes nothing about it.

WHY HTML AND CSV, AND NOT PDF
    HTML is self-contained, opens on any machine with no reader installed,
    prints to PDF from any browser, and needs no new dependency. Adding
    reportlab or weasyprint to a security tool to produce a file a browser
    already makes would be a poor trade.

    CSV is the other half: a human report and a machine-readable one answer
    different questions, and neither substitutes for the other.

WHAT THIS MODULE MUST NEVER DO
    Interpret. It renders exactly the findings it is given, in the order F-4
    requires, and adds no judgement of its own. If a number in the report
    disagrees with the screen, the renderer is wrong, not the analysis.
"""

from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from analysis import coverage

#: Worst first, matching web/static/app.js. Duplicated deliberately rather
#: than imported: this module must not depend on the web layer, and a
#: renderer that silently disagreed with the screen about ordering would be
#: worse than one that repeats three lines.
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

#: The F-1 fields, in the order a CSV reader expects to meet them.
CSV_COLUMNS = ("id", "check", "status", "severity", "device",
               "summary", "detail", "source")


def _sections(findings: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """Split findings by status, worst-first within the problems.

    THE ORDER OF THE KEYS IS THE SAFETY PROPERTY.
        `blind` first, always. The dashboard renders "could not check" above
        the results for the same reason, and a report that quietly reversed
        that would undo the decision on the medium where it matters most.
    """
    problems = [f for f in findings if f.get("status") == "found"]
    problems.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99))
    return {
        "blind": [f for f in findings if f.get("status") == "error"],
        "problems": problems,
        "clean": [f for f in findings if f.get("status") == "none"],
    }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def render_csv(findings: Sequence[Dict[str, Any]]) -> str:
    """Every finding, one row each, including the ones that could not run.

    A `status` COLUMN rather than only the rows that found something -- an
    export that silently dropped the error rows would let a spreadsheet
    reader count problems and conclude the rest was clean.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)

    ordered = (_sections(findings)["blind"]
               + _sections(findings)["problems"]
               + _sections(findings)["clean"])
    for finding in ordered:
        evidence = finding.get("evidence") or {}
        writer.writerow([
            finding.get("id", ""),
            finding.get("check", ""),
            finding.get("status", ""),
            finding.get("severity", ""),
            finding.get("device", ""),
            finding.get("summary", ""),
            evidence.get("detail", ""),
            evidence.get("source", ""),
        ])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_STYLE = """
:root{--ink:#16181d;--dim:#5a5f68;--rule:#dfe2e6;--paper:#fff;--sunk:#f4f5f7;
--bad:#a4291c;--bad-b:#fbe9e6;--warn:#8a5a12;--warn-b:#faf0dc;
--good:#20663d;--good-b:#e6f1ea;}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
color:var(--ink);background:var(--paper);margin:0;padding:2.5rem 1.5rem 4rem}
.wrap{max-width:56rem;margin:0 auto}
h1{font-size:1.75rem;margin:0 0 .35rem;letter-spacing:-.02em}
.meta{color:var(--dim);font-size:.87rem;margin:0 0 1.5rem}
.counts{display:flex;gap:1px;background:var(--rule);border:1px solid var(--rule);
border-radius:6px;overflow:hidden;margin-bottom:1.75rem;flex-wrap:wrap}
.count{background:var(--paper);padding:.75rem 1.1rem;flex:1;min-width:9rem}
.count .n{font-size:1.5rem;font-weight:650;font-variant-numeric:tabular-nums;
line-height:1;display:block;margin-bottom:.2rem}
.count .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--dim)}
.count.bad .n{color:var(--bad)}.count.warn .n{color:var(--warn)}
.count.good .n{color:var(--good)}
h2{font-size:1.08rem;margin:2rem 0 .3rem;padding-bottom:.35rem;border-bottom:2px solid var(--ink)}
h2.warn{color:var(--warn);border-color:var(--warn)}
.lede{color:var(--dim);font-size:.88rem;margin:.4rem 0 1rem}
.coverage{border:1px solid var(--rule);border-radius:6px;padding:.85rem 1rem;
margin:1rem 0 1.75rem;background:var(--sunk)}
.coverage.complete{border-color:var(--good);background:var(--good-b)}
.coverage.incomplete{border-color:var(--warn);background:var(--warn-b)}
.coverage .statement{font-weight:650;margin:0 0 .35rem}
.coverage ul{margin:.45rem 0 0;padding-left:1.2rem}
.coverage li{margin:.25rem 0}
.coverage .meta-line{font-size:.78rem;color:var(--dim)}
.f{border:1px solid var(--rule);border-radius:6px;padding:.85rem 1rem;margin-bottom:.6rem;
page-break-inside:avoid}
.f.blind{background:var(--warn-b);border-color:var(--warn)}
.f.found{background:var(--bad-b);border-color:var(--bad)}
.f.clean{background:var(--good-b);border-color:var(--good)}
.f .top{display:flex;gap:.55rem;align-items:baseline;flex-wrap:wrap;margin-bottom:.3rem}
.f .id{font-family:ui-monospace,Consolas,monospace;font-size:.78rem;font-weight:600}
.f .sev{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;
padding:.1rem .4rem;border-radius:3px;background:rgba(0,0,0,.07)}
.f .dev{font-size:.78rem;color:var(--dim)}
.f .sum{font-weight:600}
.f .det{font-family:ui-monospace,Consolas,monospace;font-size:.76rem;
background:var(--sunk);border-radius:4px;padding:.5rem .6rem;margin-top:.45rem;
white-space:pre-wrap;word-break:break-word}
.f .src{font-size:.74rem;color:var(--dim);margin-top:.35rem}
.none{color:var(--dim);font-style:italic;font-size:.9rem;padding:.5rem 0}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--rule);
color:var(--dim);font-size:.8rem}
@media print{body{padding:0}.f{border-width:1px}}
"""


def _finding_html(finding: Dict[str, Any], css_class: str) -> str:
    """One finding. EVERY value escaped.

    This is not routine defensiveness. `evidence.detail` contains config
    text taken verbatim from a file the user uploaded -- an ACL description,
    a hostname, an interface comment. A config containing `<script>` would
    otherwise execute when the report is opened, and a security tool that
    hands you a booby-trapped report about your own firewall is a worse
    outcome than the finding it was reporting.
    """
    evidence = finding.get("evidence") or {}
    esc = html.escape
    parts = [f'<div class="f {esc(css_class)}">', '<div class="top">']
    parts.append(f'<span class="id">{esc(str(finding.get("id", "")))}</span>')
    if finding.get("severity"):
        parts.append(f'<span class="sev">{esc(str(finding["severity"]))}</span>')
    if finding.get("device"):
        parts.append(f'<span class="dev">{esc(str(finding["device"]))}</span>')
    parts.append("</div>")
    parts.append(f'<div class="sum">{esc(str(finding.get("summary", "")))}</div>')
    if evidence.get("detail"):
        parts.append(f'<div class="det">{esc(str(evidence["detail"]))}</div>')
    if evidence.get("source"):
        parts.append(f'<div class="src">{esc(str(evidence["source"]))}</div>')
    parts.append("</div>")
    return "".join(parts)


def _section_html(title: str, lede: str, items: List[Dict], css_class: str,
                  empty_text: str, warn: bool = False) -> str:
    """One section, RENDERED EVEN WHEN EMPTY.

    An absent section and a section saying "none" are different statements,
    and only the second one tells a reader the question was asked. This is
    the same reason the dashboard shows a zero "could not check" tile.
    """
    head = f'<h2 class="warn">{html.escape(title)}</h2>' if warn \
        else f'<h2>{html.escape(title)}</h2>'
    body = ("".join(_finding_html(f, css_class) for f in items) if items
            else f'<p class="none">{html.escape(empty_text)}</p>')
    return f'{head}<p class="lede">{html.escape(lede)}</p>{body}'


def _coverage_html(
    findings: Sequence[Dict[str, Any]],
    conversion_gaps: Sequence[str] = (),
) -> str:
    """The first-class coverage statement (#235), derived from status values.

    It is not a fourth finding section. It is the reading aid that says whether
    the finding sections are complete, and if not, exactly which blind spots
    remain. Removing the gap list is the mutation #235 names: the report would
    still have findings, but no longer name what was not checked.

    `conversion_gaps` (#302 review) is rendered as its OWN list, never merged
    into `gaps` -- a check that could not run and a rule a converter excluded
    before any check ran are different claims, and merging them would lose
    which one happened.
    """
    summary = coverage.summarise(findings, conversion_gaps)
    css = "complete" if summary["complete"] else "incomplete"
    esc = html.escape

    parts = [
        '<h2>Coverage and certainty</h2>',
        f'<div class="coverage {css}">',
        f'<p class="statement">{esc(summary["statement"])}</p>',
    ]

    if summary["gaps"]:
        parts.append("<ul>")
        for gap in summary["gaps"]:
            check = esc(gap["check"].replace("_", " "))
            device = esc(gap["device"])
            reason = esc(gap["summary"])
            detail = esc(gap["detail"])
            source = esc(gap["source"])
            parts.append(
                "<li>"
                f"<strong>{check}</strong> on <strong>{device}</strong>: "
                f"{reason}"
            )
            if detail or source:
                bits = []
                if detail:
                    bits.append(detail)
                if source:
                    bits.append(f"source: {source}")
                parts.append(
                    f'<div class="meta-line">{" · ".join(bits)}</div>'
                )
            parts.append("</li>")
        parts.append("</ul>")
    elif summary["checked"]:
        names = ", ".join(
            f'{item["check"].replace("_", " ")} on {item["device"]}'
            for item in summary["checked"]
        )
        parts.append(
            f'<p class="meta-line">Checked: {esc(names)}.</p>'
        )

    if summary["conversion_gaps"]:
        parts.append(
            '<p class="meta-line"><strong>Excluded during conversion, '
            "before any check ran:</strong></p>"
        )
        parts.append("<ul>")
        for note in summary["conversion_gaps"]:
            parts.append(f"<li>{esc(note)}</li>")
        parts.append("</ul>")

    parts.append("</div>")
    return "".join(parts)


def render_html(findings: Sequence[Dict[str, Any]],
                source: Optional[str] = None,
                generated_at: Optional[str] = None,
                conversion_gaps: Sequence[str] = ()) -> str:
    """A complete, self-contained HTML report. No external files, no scripts.

    `conversion_gaps` (#302 review) names anything a converter (pfSense's,
    today) excluded before this findings list ever existed -- optional, and
    omitting it reproduces this function's exact prior output.
    """
    s = _sections(findings)
    when = generated_at or _now()
    subject = source or "an uploaded configuration"

    counts = (
        f'<div class="counts">'
        f'<div class="count bad"><span class="n">{len(s["problems"])}</span>'
        f'<span class="k">problems found</span></div>'
        f'<div class="count good"><span class="n">{len(s["clean"])}</span>'
        f'<span class="k">checked, nothing found</span></div>'
        f'<div class="count warn"><span class="n">{len(s["blind"])}</span>'
        f'<span class="k">could not check</span></div>'
        f'</div>'
    )

    # "Nothing was skipped" is a COVERAGE claim, and it is only true when
    # something was actually reported AND nothing was excluded before any
    # check ran (#302 review -- conversion_gaps is exactly that second
    # condition, which this sentence did not know about before). With an
    # empty findings list it says nobody-looked in the words of
    # everything-ran -- the same F-4 confusion the coverage box above was
    # fixed for, in a sentence that predates it. One claim, two places; both
    # now read from the same conditions.
    if conversion_gaps:
        blind_empty_text = (
            "Every check that ran found nothing, but part of the uploaded "
            "configuration was excluded before any check saw it -- see "
            "Coverage and certainty above."
        )
    elif findings:
        blind_empty_text = "Every check ran. Nothing was skipped."
    else:
        blind_empty_text = "No check reported a result, so nothing is known either way."

    blind = _section_html(
        "Could not check",
        "These checks did not run. Nothing is known about what they cover. "
        "This is not a pass.",
        s["blind"], "blind",
        blind_empty_text,
        warn=True)

    problems = _section_html(
        "Problems found",
        "Issues the analysis identified, most serious first.",
        s["problems"], "found",
        "No problems were found by the checks that ran.")

    clean = _section_html(
        "Checked — nothing found",
        "These checks ran successfully and found no issues.",
        s["clean"], "clean",
        "No check completed with a clean result.")

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>Netwise report — {html.escape(subject)}</title>"
        f"<style>{_STYLE}</style></head><body><div class=\"wrap\">"
        f"<h1>Netwise analysis report</h1>"
        f'<p class="meta">{html.escape(subject)} &middot; generated '
        f'{html.escape(when)}</p>'
        f"{counts}{_coverage_html(findings, conversion_gaps)}{blind}{problems}{clean}"
        '<footer>Netwise analyses exported configuration files offline. It '
        'never connects to, scans, or modifies a live network. '
        '&ldquo;Could not check&rdquo; means exactly that: those checks did '
        'not run, and this report makes no claim about what they cover.'
        "</footer></div></body></html>"
    )
