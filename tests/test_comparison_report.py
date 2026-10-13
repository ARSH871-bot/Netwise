"""analysis/report.py's comparison report -- the propose-a-change strengthening
that lets a reader download what a proposed change actually does, not just
what the current config looks like.

WHAT THIS GUARDS
    1. INJECTION. Same reasoning as tests/test_report_export.py -- evidence
       text is config content taken verbatim from an uploaded file, and
       must never be interpreted as markup.

    2. THE THREE-WAY COUNT IS HONEST. introduced/resolved/unchanged must
       each say what they claim, and unchanged findings must not silently
       vanish from the CSV -- their count is a real row, not an omission.

    3. RESOLVED FINDINGS READ AS GOOD NEWS, NOT AS A REPEATED PROBLEM.
       A resolved finding still carries status="found" from the scan that
       originally found it; the HTML must style it as fixed (the "clean"
       card), not as a currently-open problem.

    4. A STATUS TRANSITION SURVIVES THE DOWNLOAD (#298 review, round two).
       newly_blind/newly_sighted must reach both exports, rendered first,
       and the HTML section must appear even when empty -- an absent
       section and "none" are different claims, same as F-4 itself.

RUN
    pytest tests/ -v
"""

from __future__ import annotations

import csv
import io

from analysis import report

HOSTILE = "<script>alert('xss')</script>"


def finding(**kw):
    base = {
        "id": "AC-001", "check": "access_control", "severity": "high",
        "device": "rtr-us5", "status": "found",
        "summary": "Unencrypted web traffic is allowed out",
        "evidence": {"detail": "Expected DENY but got PERMIT",
                     "source": "rtr-us5:acl_in"},
    }
    base.update(kw)
    return base


INTRODUCED = finding(id="AC-002", summary="A new problem this change causes")
RESOLVED = finding(id="AC-001", summary="A problem this change fixes")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def test_csv_has_a_change_type_column_not_just_status():
    text = report.render_comparison_csv([INTRODUCED], [RESOLVED], 3)
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][0] == "change_type"
    data_rows = [r for r in rows[1:] if r and r[0] in ("introduced", "resolved")]
    assert data_rows[0][0] == "introduced"
    assert data_rows[0][1] == "AC-002"
    assert data_rows[1][0] == "resolved"
    assert data_rows[1][1] == "AC-001"


def test_csv_carries_the_original_status_alongside_change_type():
    """A resolved finding is not a "none" or an "error" -- it is a found
    problem that no longer applies. Losing that would be losing the fact
    that it was ever proven in the first place."""
    text = report.render_comparison_csv([], [RESOLVED], 0)
    rows = list(csv.reader(io.StringIO(text)))
    resolved_row = next(r for r in rows if r and r[0] == "resolved")
    status_column = report.CSV_COLUMNS.index("status") + 1  # +1 for change_type
    assert resolved_row[status_column] == "found"


def test_csv_states_the_unchanged_count_even_though_it_has_no_rows():
    """Unchanged findings are not repeated as rows -- see the docstring on
    render_comparison_csv() -- but the count itself must survive, or a CSV
    opened alone with no report page beside it could not tell "3 unaffected"
    from "nothing else was checked"."""
    text = report.render_comparison_csv([], [], 7)
    assert "unchanged" in text
    assert "7" in text


def test_csv_escapes_hostile_evidence():
    hostile_finding = finding(id="AC-003", summary=HOSTILE,
                               evidence={"detail": HOSTILE, "source": HOSTILE})
    text = report.render_comparison_csv([hostile_finding], [], 0)
    # csv.writer already quotes/escapes for the CSV format itself; the
    # property that matters is that the raw script tag reaches the file
    # as DATA (inside a field), not as something a spreadsheet application
    # would execute -- CSV has no markup to inject into, so round-tripping
    # it back out unchanged is the correct, safe behaviour, unlike HTML
    # below where the same string must NOT survive unescaped.
    rows = list(csv.reader(io.StringIO(text)))
    data_row = next(r for r in rows if r and r[0] == "introduced")
    assert HOSTILE in data_row


def test_ordering_is_worst_first_within_each_bucket():
    low = finding(id="AC-009", severity="low", summary="low one")
    high = finding(id="AC-001", severity="high", summary="high one")
    medium = finding(id="AC-005", severity="medium", summary="medium one")

    text = report.render_comparison_csv([low, high, medium], [], 0)
    rows = [r for r in csv.reader(io.StringIO(text)) if r and r[0] == "introduced"]
    ids = [r[1] for r in rows]
    assert ids == ["AC-001", "AC-005", "AC-009"]


BLIND = finding(id="AC-005", status="error", check="access_control",
                 summary="1 supplied rule(s) for this check were not read")
SIGHTED = finding(id="AC-006", status="none",
                   summary="No policy violation found")


def test_csv_carries_newly_blind_and_newly_sighted_as_real_rows():
    """The bug Shubham's second review caught: a blinding proposal's
    export used to say "0 new problems, 0 fixed" and nothing else. These
    are rows, not a summary count, so they cannot be silently dropped."""
    text = report.render_comparison_csv(
        [], [], 0, newly_blind=[BLIND], newly_sighted=[SIGHTED]
    )
    rows = list(csv.reader(io.StringIO(text)))
    blind_row = next(r for r in rows if r and r[0] == "newly_blind")
    sighted_row = next(r for r in rows if r and r[0] == "newly_sighted")
    assert blind_row[1] == "AC-005"
    assert sighted_row[1] == "AC-006"


def test_csv_orders_newly_blind_and_sighted_before_introduced_and_resolved():
    text = report.render_comparison_csv(
        [INTRODUCED], [RESOLVED], 0, newly_blind=[BLIND], newly_sighted=[SIGHTED]
    )
    rows = [r for r in csv.reader(io.StringIO(text))
            if r and r[0] in ("newly_blind", "newly_sighted", "introduced", "resolved")]
    assert [r[0] for r in rows] == ["newly_blind", "newly_sighted", "introduced", "resolved"]


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def test_html_is_a_complete_self_contained_document():
    out = report.render_comparison_html([INTRODUCED], [RESOLVED], 3, "block any to 10.20.0.5 on tcp/80")
    assert out.startswith("<!doctype html>")
    assert "<style>" in out
    assert "</html>" in out


def test_html_names_the_proposed_change_in_the_meta_line():
    description = "block any to 10.20.0.5 on tcp/80 on rtr-us5"
    out = report.render_comparison_html([], [], 0, description)
    assert description in out


def test_html_counts_match_the_three_buckets():
    out = report.render_comparison_html([INTRODUCED], [RESOLVED, RESOLVED], 5, "a change")

    # The tile numbers themselves, not just the card count -- a mismatch
    # between the header tile and the actual rendered cards would be
    # exactly the "report disagrees with itself" failure this whole module
    # exists to prevent.
    assert '<span class="n">1</span>\n<span class="k">new problems this change introduces</span>' \
        in out.replace("</span><span", "</span>\n<span")
    assert '<span class="n">2</span>\n<span class="k">problems this change fixes</span>' \
        in out.replace("</span><span", "</span>\n<span")
    assert '<span class="n">5</span>\n<span class="k">unaffected' \
        in out.replace("</span><span", "</span>\n<span")

    # And the actual rendered cards agree with those numbers.
    assert out.count('<div class="f found">') == 1
    assert out.count('<div class="f clean">') == 2


def test_resolved_findings_get_the_clean_card_style_not_found():
    """A resolved finding still has status="found" in its own dict -- the
    CARD must not reuse that to style it as an open problem, which is the
    exact confusion this whole report exists to prevent."""
    out = report.render_comparison_html([], [RESOLVED], 0, "a change")
    assert '<div class="f clean">' in out
    assert '<div class="f found">' not in out


def test_introduced_findings_get_the_found_card_style():
    out = report.render_comparison_html([INTRODUCED], [], 0, "a change")
    assert '<div class="f found">' in out
    assert '<div class="f clean">' not in out


def test_html_escapes_hostile_evidence_and_description():
    hostile_finding = finding(id="AC-003", summary=HOSTILE,
                               evidence={"detail": HOSTILE, "source": HOSTILE})
    out = report.render_comparison_html([hostile_finding], [], 0, HOSTILE)
    assert "<script>alert" not in out
    assert out.count("&lt;script&gt;") >= 3  # summary, detail, source, description


def test_no_new_problems_section_says_so_in_words_not_silence():
    out = report.render_comparison_html([], [RESOLVED], 3, "a change")
    assert "This change introduces no new problems." in out


def test_no_fixed_problems_section_says_so_in_words_not_silence():
    out = report.render_comparison_html([INTRODUCED], [], 3, "a change")
    assert "This change fixes no existing problems." in out


def test_footer_states_nothing_was_applied():
    out = report.render_comparison_html([], [], 0, "a change")
    assert "SIMULATED" in out
    assert "nothing here was applied to any device" in out


def test_html_renders_the_blind_transition_disclosure():
    """The exact bug Shubham's second review found: a proposal that makes
    a check go blind must show that in the DOWNLOADED report, not just on
    screen. Before this fix, render_comparison_html() had no parameter to
    carry newly_blind/newly_sighted at all."""
    out = report.render_comparison_html(
        [], [], 0, "a change", newly_blind=[BLIND], newly_sighted=[SIGHTED]
    )
    assert BLIND["summary"] in out
    assert SIGHTED["summary"] in out


def test_html_blind_section_renders_even_when_empty():
    """Same F-4 reasoning as render_html()'s own "Could not check" section
    (_section_html's docstring): an absent section and a section saying
    "none" are different claims. A comparison export with no transitions
    must say so, not omit the section entirely."""
    out = report.render_comparison_html([], [], 0, "a change")
    assert "does not blind any check" in out
    assert "does not restore any check" in out


def test_html_blind_section_renders_before_introduced_and_resolved():
    out = report.render_comparison_html(
        [INTRODUCED], [RESOLVED], 0, "a change",
        newly_blind=[BLIND], newly_sighted=[SIGHTED],
    )
    assert out.index(BLIND["summary"]) < out.index(INTRODUCED["summary"])
    assert out.index(SIGHTED["summary"]) < out.index(INTRODUCED["summary"])


def test_html_escapes_hostile_newly_blind_evidence():
    hostile_blind = finding(id="AC-007", status="error", summary=HOSTILE,
                             evidence={"detail": HOSTILE, "source": HOSTILE})
    out = report.render_comparison_html(
        [], [], 0, "a change", newly_blind=[hostile_blind]
    )
    assert "<script>alert" not in out
