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

#: The F-1 fields, in the order a CSV reader expects to meet them, plus one
#: derived column -- see `is_nothing_to_check()` for why it exists and why it
#: is not part of F-1.
CSV_COLUMNS = ("id", "check", "status", "severity", "device",
               "summary", "detail", "source", "nothing_to_check")

#: The `device` value a check uses when a finding is ABOUT THE CHECK rather
#: than about any device. Today exactly one producer emits it --
#: `analysis/checks/policy_compliance.py`, for "your policy has no rules for
#: this check" -- and `tests/test_nothing_to_check.py` pins that join so this
#: renderer cannot quietly stop recognising it.
NOTHING_TO_CHECK_DEVICE = "n/a"


def is_nothing_to_check(finding: Dict[str, Any]) -> bool:
    """True for a `status="none"` finding that means "there was nothing to run".

    THE THIRD CLAIM, AND WHY IT NEEDS ONE (#266)
        F-4 gives three statuses, and `none` currently carries two different
        sentences. "We checked and found nothing wrong" is a result. "You
        supplied no rules for this check, so nothing was asserted and nothing
        was checked" is not -- it is the absence of one, and its own detail
        text says so while the tile above it counts it as a clean pass.

        That is F-4's own failure re-appearing one level down: `none` and
        `error` were separated precisely so "we looked" could not be confused
        with "nobody looked", and this is a third thing hiding inside the
        first.

    WHY THE COUNT DOES NOT MOVE
        It still counts toward "checked, nothing found". Splitting the tile
        into four would trade one confusion for another -- the numbers exist
        to be read at a glance, and a reader cannot hold four. The
        distinction is made on the CARD, where there is room to say it in
        words. The tile total is unchanged in both renderers, and tests pin
        that.

    WHY `device`, AND WHY THAT IS A JOIN WORTH PINNING
        `n/a` is not a device. It is what a check writes when the finding is
        about the check itself, and it is the only signal on the finding that
        separates the two sentences -- `evidence.source` cannot, because it
        reads "the policy file you supplied" for this sentinel and for every
        real user-policy finding alike.

        Nothing in F-1 promises that, so a producer renaming it would return
        this card to looking like a clean pass, silently, with every test
        green. `tests/test_nothing_to_check.py` runs the real check and
        asserts the sentinel it emits still satisfies this predicate -- the
        same class of gap as the PF Sense/policy join, where both halves were
        tested and the join between them was not.
    """
    return (
        finding.get("status") == "none"
        and finding.get("device") == NOTHING_TO_CHECK_DEVICE
    )


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
            # "yes" or EMPTY, not "yes"/"no". A blank cell reads as "this
            # column does not apply here", which is the truth for a problem
            # or a could-not-check row; writing "no" on those would answer a
            # question nobody asked of them and invite a reader to treat the
            # column as a second status. Filterable either way in a
            # spreadsheet, which is the point of having it at all.
            "yes" if is_nothing_to_check(finding) else "",
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
/* Neither green nor amber: a third claim gets a third, deliberately
   NEUTRAL look, so it cannot be misread as either. */
.f.nothing{background:var(--sunk);border-color:var(--rule)}
.f .claim{font-size:.8rem;font-weight:600;color:var(--dim);margin-top:.45rem}
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

    # A "nothing to check" card is styled apart from a genuinely clean one and
    # SAYS SO IN WORDS. The class alone would leave the whole distinction
    # resting on a colour, which fails in greyscale, on a printed page and in
    # a screen reader -- the same discipline as the blind cards' own
    # "this is not a clean result" sentence, and as the summary tiles'
    # captions.
    if is_nothing_to_check(finding):
        css_class = "nothing"

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
    if is_nothing_to_check(finding):
        parts.append(
            '<div class="claim">Nothing was checked here. This is not a '
            'clean result -- no rules were supplied for this check, so '
            'nothing was asserted about the configuration.</div>'
        )
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


def _coverage_html(findings: Sequence[Dict[str, Any]]) -> str:
    """The first-class coverage statement (#235), derived from status values.

    It is not a fourth finding section. It is the reading aid that says whether
    the finding sections are complete, and if not, exactly which blind spots
    remain. Removing the gap list is the mutation #235 names: the report would
    still have findings, but no longer name what was not checked.
    """
    summary = coverage.summarise(findings)
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

    parts.append("</div>")
    return "".join(parts)


def render_comparison_csv(
    introduced: Sequence[Dict[str, Any]],
    resolved: Sequence[Dict[str, Any]],
    unchanged_count: int,
    newly_blind: Sequence[Dict[str, Any]] = (),
    newly_sighted: Sequence[Dict[str, Any]] = (),
) -> str:
    """A before/after comparison, one row per finding that actually moved.

    A `change_type` COLUMN (introduced/resolved/newly_blind/newly_sighted)
    IN PLACE OF `status`.
        `status` alone would be misleading here: a RESOLVED finding still
        carries `status="found"` from the scan where it existed -- it is
        not a "none" or an "error", it is a problem that used to be found
        and now is not. `change_type` says what actually happened, and
        `status` is kept alongside it so the original claim is not lost.

    `newly_blind`/`newly_sighted` (#298 review, @shubhamkataria2005) ARE
    ROWS, NOT A SUMMARY COUNT, UNLIKE `unchanged_count`.
        Before this, a proposal that made a check go blind produced a
        report reading "0 new problems, 0 fixed" -- correct about the two
        buckets it knew about, and silent about the one that actually
        matters. A reader deciding whether to apply a change is more
        likely to read this export than the screen it came from, so the
        disclosure has to survive the trip. Rendered FIRST, matching
        render_html()'s own "blind always first" rule, for the same
        reason: the thing most likely to mislead someone skimming goes
        where it cannot be missed.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(("change_type",) + CSV_COLUMNS)

    ordered_introduced = sorted(
        introduced, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99)
    )
    ordered_resolved = sorted(
        resolved, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99)
    )

    for change_type, rows in (
        ("newly_blind", newly_blind),
        ("newly_sighted", newly_sighted),
        ("introduced", ordered_introduced),
        ("resolved", ordered_resolved),
    ):
        for finding in rows:
            evidence = finding.get("evidence") or {}
            writer.writerow([
                change_type,
                finding.get("id", ""),
                finding.get("check", ""),
                finding.get("status", ""),
                finding.get("severity", ""),
                finding.get("device", ""),
                finding.get("summary", ""),
                evidence.get("detail", ""),
                evidence.get("source", ""),
            ])

    # A summary row, not a silent count buried only in the HTML sibling of
    # this function -- a CSV opened alone, with no report page beside it,
    # should still be able to say how many findings this comparison is NOT
    # showing rather than let the row count alone imply completeness.
    # newly_blind/newly_sighted need no summary row of their own -- unlike
    # unchanged, they ARE rows above, so their count is already visible.
    writer.writerow([])
    writer.writerow(["summary", "introduced", len(ordered_introduced)])
    writer.writerow(["summary", "resolved", len(ordered_resolved)])
    writer.writerow(["summary", "unchanged", unchanged_count])

    return buffer.getvalue()


def render_comparison_html(
    introduced: Sequence[Dict[str, Any]],
    resolved: Sequence[Dict[str, Any]],
    unchanged_count: int,
    description: str,
    source: Optional[str] = None,
    generated_at: Optional[str] = None,
    newly_blind: Sequence[Dict[str, Any]] = (),
    newly_sighted: Sequence[Dict[str, Any]] = (),
) -> str:
    """A before/after comparison for one proposed change, as a self-contained
    HTML report -- the same shape render_html() gives a real scan, answering
    a different question: not "what is true", but "what would this change
    do".

    REUSES _finding_html()/_STYLE RATHER THAN A SECOND TEMPLATE.
        Every escaping rule render_html() enforces (evidence.detail is
        config text taken verbatim from a file someone uploaded, and must
        never be interpreted as markup) applies here identically -- a
        second, hand-rolled template would be a second place for that
        discipline to quietly not hold.

    RESOLVED FINDINGS RENDER WITH THE "clean" CARD STYLE, ON PURPOSE.
        Visually good news, even though the finding itself came from a
        status="found" scan -- the card colour answers "is this good or bad
        for the reader", which is the opposite question from what `status`
        answers about the scan that produced it. See
        render_comparison_csv()'s own docstring for the CSV side of the
        same distinction.

    `introduced`/`resolved` MUST BE status="found" ONLY -- ENFORCED BY THE
    CALLER, NOT HERE.
        `_section_html()` below hard-codes the card status to "found" for
        `introduced`. That is only correct because
        `POST /api/propose/comparison-report` (web/main.py) rejects any
        other status in either list before this is ever called, and
        `diffFindings()` in web/static/app.js filters to status="found" on
        both sides before building the payload in the first place. A
        status="none"/"error" finding reaching this function would render
        under a heading that misstates what happened -- see #298's review
        for the two concrete cases (a check going blind rendered as a fix,
        a check going clean rendered as a new problem) this now prevents
        upstream.

    `newly_blind`/`newly_sighted` RENDER FIRST, BEFORE introduced/resolved
    (#298 review, round two, @shubhamkataria2005).
        The first fix stopped a status transition from being miscategorised
        as introduced/resolved on screen. It did not carry the transition
        into this export at all -- a proposal that made a check go blind
        produced a report reading "0 new problems, 0 fixed", correct about
        the two buckets it knew about and silent about the one that
        actually matters. Reused `_section_html(..., "blind", warn=True)`
        for the disclosure rather than a third template, for the same
        escaping-discipline reason the other two sections already reuse it.
        Rendered first because `render_html()` already renders `blind`
        first, always, for exactly this reason: the thing most likely to
        mislead someone skimming goes where it cannot be missed.
    """
    ordered_introduced = sorted(
        introduced, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99)
    )
    ordered_resolved = sorted(
        resolved, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 99)
    )
    when = generated_at or _now()
    subject = source or "an uploaded configuration"
    esc = html.escape

    counts = (
        f'<div class="counts">'
        f'<div class="count bad"><span class="n">{len(ordered_introduced)}</span>'
        f'<span class="k">new problems this change introduces</span></div>'
        f'<div class="count good"><span class="n">{len(ordered_resolved)}</span>'
        f'<span class="k">problems this change fixes</span></div>'
        f'<div class="count warn"><span class="n">{unchanged_count}</span>'
        f'<span class="k">unaffected -- true either way</span></div>'
        f'</div>'
    )

    blind_section = _section_html(
        "This change stops us being able to check",
        "These checks ran before the change. They cannot run after it.",
        list(newly_blind), "blind",
        "This change does not blind any check that currently runs.",
        warn=True)

    sighted_section = _section_html(
        "This change lets us check something we could not check before",
        "These checks could not run before the change. They run clean after it.",
        list(newly_sighted), "clean",
        "This change does not restore any check that is currently blind.")

    introduced_section = _section_html(
        "New problems this change introduces",
        "Not present in the uploaded config -- caused by this specific change.",
        ordered_introduced, "found",
        "This change introduces no new problems.")

    resolved_section = _section_html(
        "Problems this change fixes",
        "Present in the uploaded config, gone after this change.",
        ordered_resolved, "clean",
        "This change fixes no existing problems.")

    unchanged_note = (
        f'<p class="lede">{unchanged_count} other finding(s) are unaffected '
        f'-- true whether or not this change is made. See the full scan '
        f'report for those.</p>'
        if unchanged_count else ""
    )

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>Netwise comparison -- {esc(subject)}</title>"
        f"<style>{_STYLE}</style></head><body><div class=\"wrap\">"
        f"<h1>Netwise proposed-change comparison</h1>"
        f'<p class="meta">{esc(subject)} &middot; proposed change: '
        f'{esc(description)} &middot; generated {esc(when)}</p>'
        f"{counts}{blind_section}{sighted_section}"
        f"{introduced_section}{resolved_section}{unchanged_note}"
        '<footer>This compares your uploaded config against a SIMULATED '
        'change -- nothing here was applied to any device or to the '
        'config you uploaded. Generated by Netwise, offline.'
        "</footer></div></body></html>"
    )


def render_html(findings: Sequence[Dict[str, Any]],
                source: Optional[str] = None,
                generated_at: Optional[str] = None) -> str:
    """A complete, self-contained HTML report. No external files, no scripts."""
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
    # something was actually reported. With an empty findings list it says
    # nobody-looked in the words of everything-ran -- the same F-4 confusion
    # the coverage box above was fixed for, in a sentence that predates it.
    # One claim, two places; both now read from the same condition.
    blind = _section_html(
        "Could not check",
        "These checks did not run. Nothing is known about what they cover. "
        "This is not a pass.",
        s["blind"], "blind",
        ("Every check ran. Nothing was skipped." if findings
         else "No check reported a result, so nothing is known either way."),
        warn=True)

    problems = _section_html(
        "Problems found",
        "Issues the analysis identified, most serious first.",
        s["problems"], "found",
        "No problems were found by the checks that ran.")

    clean = _section_html(
        "Checked -- nothing found",
        "These checks ran successfully and found no issues.",
        s["clean"], "clean",
        "No check completed with a clean result.")

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>Netwise report -- {html.escape(subject)}</title>"
        f"<style>{_STYLE}</style></head><body><div class=\"wrap\">"
        f"<h1>Netwise analysis report</h1>"
        f'<p class="meta">{html.escape(subject)} &middot; generated '
        f'{html.escape(when)}</p>'
        f"{counts}{_coverage_html(findings)}{blind}{problems}{clean}"
        '<footer>Netwise analyses exported configuration files offline. It '
        'never connects to, scans, or modifies a live network. '
        '&ldquo;Could not check&rdquo; means exactly that: those checks did '
        'not run, and this report makes no claim about what they cover.'
        "</footer></div></body></html>"
    )
