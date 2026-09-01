"""A findings report that can leave the screen (#227-adjacent, export gap).

WHAT THIS GUARDS
    Three things, in descending order of how badly they would hurt.

    1. INJECTION. `evidence.detail` is config text taken verbatim from a file
       the user uploaded. A config containing `<script>` would otherwise
       execute when the report is opened. A security tool that hands you a
       booby-trapped report about your own firewall is a worse outcome than
       the finding it was reporting.

    2. F-4, on a medium where it matters more than on screen. A report is
       read later, by someone who cannot ask a question, often by someone
       deciding whether the work is finished. So "could not check" is the
       FIRST section, rendered even when empty, and counted in the header.

    3. Agreement with the screen. A report that disagrees with the dashboard
       is worse than no report, so the endpoint serves what `/api/findings`
       serves rather than re-running the analysis.

NO BATFISH, NO OLLAMA
    `analysis/report.py` is a pure function over a findings list. The
    endpoint tests stub the analysis.
"""

from __future__ import annotations

import csv
import io
import re

import pytest
from fastapi.testclient import TestClient

from analysis import coverage, report
from web import main

client = TestClient(main.app)


def finding(**kw):
    """One F-1 finding, with sane defaults."""
    base = {
        "id": "AC-001", "check": "access_control", "severity": "high",
        "device": "rtr-us5", "status": "found",
        "summary": "Unencrypted web traffic is allowed out",
        "evidence": {"detail": "Expected DENY but got PERMIT",
                     "source": "rtr-us5:acl_in"},
    }
    base.update(kw)
    return base


PROBLEM = finding()
CLEAN = finding(id="PC-000", check="policy_compliance", status="none",
                severity="low", summary="no violations found")
BLIND = finding(id="RT-050", check="routing", status="error",
                summary="2 route assertions could not be checked")


# ---------------------------------------------------------------------------
# 1. Injection -- the one that would actually hurt somebody
# ---------------------------------------------------------------------------


HOSTILE = "<script>alert('xss')</script>"


@pytest.mark.parametrize("field,builder", [
    ("summary", lambda v: finding(summary=v)),
    ("detail", lambda v: finding(evidence={"detail": v, "source": "x"})),
    ("source", lambda v: finding(evidence={"detail": "x", "source": v})),
    ("device", lambda v: finding(device=v)),
    ("id", lambda v: finding(id=v)),
    ("severity", lambda v: finding(severity=v)),
])
def test_config_text_cannot_inject_script_into_the_report(field, builder):
    """Every field a config can reach must be escaped, not just `detail`.

    A hostname, an ACL remark and an interface description all end up in a
    finding, and all of them come from a file somebody uploaded.
    """
    html = report.render_html([builder(HOSTILE)])

    assert "<script>" not in html, (
        f"{field}: raw <script> reached the report -- opening it would "
        f"execute code from an uploaded config file"
    )
    assert "&lt;script&gt;" in html, (
        f"{field}: the hostile text should still be VISIBLE, escaped -- "
        f"silently dropping it would hide evidence from the reader"
    )


def test_a_user_supplied_policy_is_the_live_injection_path():
    """THE VECTOR THAT IS NOT THEORETICAL, MEASURED RATHER THAN ASSUMED.

    I tried to prove the escaping mattered by putting `<script>` in a Cisco
    config and running the real pipeline. It never reached a finding:

        remark text reaches a finding? False
        ACL RULE text reaches one?     True
        device name reaches one?       True

    ACL rule text and device names DO reach `evidence.detail` -- but Cisco
    syntax will not parse `<` in either, so for the Cisco path this escaping
    is defence in depth rather than a hole being closed. Worth saying, since
    the opposite claim would have been easy to make and wrong.

    The live path is the feature landing next. A user-supplied policy is a
    JSON file somebody uploads, `violation_summary` is one of its free-text
    keys, and it becomes a finding's `summary` verbatim:

        access_control.py:313      summary=statement["violation_summary"]
        access_control.py:401      summary=guarantee["violation_summary"]
        policy_compliance.py:424   summary=rule["violation_summary"]

    So once #181 lands, an uploaded file's free text reaches this report
    directly, and the escaping stops being decorative.
    """
    from_policy_file = finding(
        summary=f"Guest network must not reach finance {HOSTILE}",
        evidence={"detail": "Flow ... is permitted but policy requires DENY",
                  "source": "rtr-us5:acl_in"},
    )

    html = report.render_html([from_policy_file])

    assert "<script>" not in html
    assert "&lt;script&gt;" in html, (
        "a policy file's own wording must survive into the report visibly, "
        "escaped -- dropping it would hide what the user actually wrote"
    )


def test_the_escaping_survives_a_real_end_to_end_download():
    """The same attack through the endpoint, not just the renderer."""
    main._uploaded = False
    try:
        response = client.get("/api/report?format=html")
        body = response.text
    finally:
        main._uploaded = False

    assert response.status_code == 200
    # No raw script tags anywhere in a served report, from any source.
    assert not re.search(r"<script[\s>]", body, re.I), (
        "a served report contained a script tag"
    )


# ---------------------------------------------------------------------------
# 2. F-4 -- "could not check" is not a footnote
# ---------------------------------------------------------------------------


def test_could_not_check_comes_before_the_problems():
    """Order is the safety property.

    The dashboard renders errors above results for the same reason. A report
    that quietly reversed that would undo the decision on the medium where a
    reader is most likely to skim.
    """
    html = report.render_html([PROBLEM, CLEAN, BLIND])

    blind_at = html.index("Could not check")
    problems_at = html.index("Problems found")
    clean_at = html.index("Checked")

    assert blind_at < problems_at < clean_at, (
        "could-not-check must be the first section in the report"
    )


def test_the_could_not_check_section_appears_even_when_empty():
    """An absent section and one saying "none" are different statements.

    Only the second tells the reader the question was asked at all.
    """
    html = report.render_html([PROBLEM])

    assert "Could not check" in html, (
        "the section vanished when there were no errors -- a reader cannot "
        "tell 'nothing was skipped' from 'we do not report skips'"
    )
    assert "Every check ran" in html


def test_every_status_is_counted_in_the_header():
    html = report.render_html([PROBLEM, PROBLEM, CLEAN, BLIND, BLIND, BLIND])

    header = html[:html.index("Could not check")]
    assert ">2<" in header and ">1<" in header and ">3<" in header, (
        "the three counts must all appear in the summary, including the "
        "could-not-check count"
    )


def test_could_not_check_is_never_described_as_a_pass():
    html = report.render_html([BLIND])
    assert "This is not a pass" in html


def test_report_has_a_first_class_coverage_statement_even_when_complete():
    """#235: total coverage is a statement, not an omitted section."""
    html = report.render_html([PROBLEM, CLEAN])

    assert "Coverage and certainty" in html
    assert "Every reported check ran. Nothing was skipped." in html
    assert "access control on rtr-us5" in html
    assert "policy compliance on rtr-us5" in html


def test_coverage_statement_names_every_blind_spot_with_reason_and_device():
    """Removing the what-was-not-checked half must fail this test."""
    routing = finding(
        id="RT-000",
        check="routing",
        status="error",
        severity="high",
        device="core-1",
        summary="The routing check failed to run",
        evidence={
            "detail": "BatfishException: Work terminated abnormally",
            "source": "analysis/checks/routing.py",
        },
    )
    policy = finding(
        id="PC-050",
        check="policy_compliance",
        status="error",
        severity="high",
        device="pfsense-us5",
        summary="2 policy rules could not be checked",
        evidence={
            "detail": "No rule matched the converted device name",
            "source": "uploaded policy",
        },
    )

    html = report.render_html([PROBLEM, routing, policy])

    assert "2 reported check/device blind spots remain" in html
    assert "routing</strong> on <strong>core-1</strong>" in html
    assert "The routing check failed to run" in html
    assert "BatfishException: Work terminated abnormally" in html
    assert "policy compliance</strong> on <strong>pfsense-us5</strong>" in html
    assert "2 policy rules could not be checked" in html
    assert "No rule matched the converted device name" in html


def test_coverage_statement_escapes_uploaded_evidence_too():
    blind = finding(
        status="error",
        summary=HOSTILE,
        evidence={"detail": HOSTILE, "source": HOSTILE},
    )

    html = report.render_html([blind])

    assert "<script>" not in html
    assert html.count("&lt;script&gt;") >= 3


def test_an_empty_findings_list_is_not_a_claim_that_nothing_was_skipped():
    """F-4, one layer up: an absence of findings is not a clean bill of health.

    "Every reported check ran. Nothing was skipped." under a green heading is
    the exact sentence a report must not print when NOTHING ran. "We checked
    and found nothing" and "nobody looked" are different claims, and an empty
    list is the second one. This asserts the report says so, and -- just as
    importantly -- that it does not wear the complete/green styling while
    saying it.
    """
    html = report.render_html([])

    assert "Nothing was skipped" not in html, (
        "an empty findings list produced a completeness claim; nothing ran"
    )
    assert "makes no claim about coverage" in html
    assert 'class="coverage incomplete"' in html, (
        "the no-data state is rendered in the same green as a clean run"
    )

    assert coverage.summarise([])["complete"] is False, (
        "the library-level claim is the one another caller would trust"
    )


def test_a_single_blind_spot_reads_as_one():
    """The plural branch was tested; the singular one was not.

    That is why "1 ... blind spot remain" reached a client-facing report: the
    only test of this sentence used two gaps, so the ternary that exists to
    handle one was never executed. The demo config has exactly one blind spot.
    """
    html = report.render_html([PROBLEM, BLIND])

    assert "1 reported check/device blind spot remains" in html
    assert "blind spot remain." not in html


def test_problems_are_ordered_worst_first():
    low = finding(id="AC-009", severity="low", summary="low one")
    high = finding(id="AC-001", severity="high", summary="high one")
    medium = finding(id="AC-005", severity="medium", summary="medium one")

    html = report.render_html([low, medium, high])

    assert html.index("high one") < html.index("medium one") < html.index("low one")


# ---------------------------------------------------------------------------
# 3. CSV -- the machine-readable half
# ---------------------------------------------------------------------------


def _rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_includes_the_findings_that_could_not_run():
    """An export that dropped the error rows would let a spreadsheet reader
    count the problems and conclude the rest was clean."""
    rows = _rows(report.render_csv([PROBLEM, CLEAN, BLIND]))

    statuses = [r["status"] for r in rows]
    assert statuses.count("error") == 1, (
        "the could-not-check finding is missing from the CSV entirely"
    )
    assert set(statuses) == {"found", "none", "error"}


def test_csv_has_a_status_column_at_all():
    """Without it, every row looks like a finding."""
    rows = _rows(report.render_csv([PROBLEM]))
    assert "status" in rows[0]
    assert rows[0]["status"] == "found"


def test_csv_carries_the_evidence_not_just_the_summary():
    rows = _rows(report.render_csv([PROBLEM]))
    assert rows[0]["detail"] == "Expected DENY but got PERMIT"
    assert rows[0]["source"] == "rtr-us5:acl_in"


def test_csv_quotes_a_comma_in_the_evidence():
    """Config text contains commas constantly. An unquoted one shifts every
    later column and silently corrupts the row."""
    nasty = finding(evidence={"detail": "permit ip any any, then deny",
                              "source": "a,b"})
    rows = _rows(report.render_csv([nasty]))

    assert rows[0]["detail"] == "permit ip any any, then deny"
    assert rows[0]["source"] == "a,b"


# ---------------------------------------------------------------------------
# 4. The endpoint -- the other end of the join
# ---------------------------------------------------------------------------


def test_the_report_matches_what_the_dashboard_is_showing(monkeypatch):
    """A report that disagrees with the screen is worse than no report.

    Both go through get_findings(), so a stub there must appear in both.
    """
    monkeypatch.setattr(main, "get_findings",
                        lambda: [dict(PROBLEM), dict(BLIND)])

    body = client.get("/api/report?format=csv").text
    rows = _rows(body)

    assert {r["id"] for r in rows} == {"AC-001", "RT-050"}


def test_an_unknown_format_is_refused_rather_than_guessed(monkeypatch):
    monkeypatch.setattr(main, "get_findings", lambda: [dict(PROBLEM)])
    response = client.get("/api/report?format=pdf")

    assert response.status_code == 400
    assert "pdf" in response.text and "html" in response.text, (
        "the refusal must name what was asked for and what is available"
    )


@pytest.mark.parametrize("fmt,marker", [("html", "<!doctype html>"),
                                        ("csv", "id,check,status")])
def test_both_formats_download_as_a_file(monkeypatch, fmt, marker):
    monkeypatch.setattr(main, "get_findings", lambda: [dict(PROBLEM)])
    response = client.get(f"/api/report?format={fmt}")

    assert response.status_code == 200
    assert marker in response.text
    disposition = response.headers.get("content-disposition", "")
    assert "attachment" in disposition, (
        "without this the browser renders it instead of saving it, and the "
        "point of the feature is that the result can leave the screen"
    )
    assert f".{fmt}" in disposition


def test_no_dashboard_only_text_leaks_into_either_format(monkeypatch):
    """`explanation` and `explanation_source` are added downstream of F-1
    validation for the dashboard. The report renders F-1 and nothing else.

    WHAT THIS TEST CANNOT DO, AND WHY IT SAYS SO
        The first version asserted `set(rows[0]) == set(CSV_COLUMNS)`, which
        is true no matter what the endpoint does -- `csv.writer` emits the
        columns it is given and ignores every other key. Mutating the strip
        away in `web/main.py` left the whole suite green:

            let the dashboard-only keys into the report   621 passed

        A test named for a property it cannot observe is the same defect
        this suite keeps finding elsewhere, so it is rewritten to assert the
        thing that IS observable: the explanation TEXT must not appear in
        either rendered format.
    """
    enriched = dict(PROBLEM)
    enriched["explanation"] = "SENTINEL-EXPLANATION-TEXT"
    enriched["explanation_source"] = "fallback"
    # remediation/remediation_source (#221) are the same shape of key, added
    # the same way, so they get the same leak check rather than a second
    # near-identical test.
    enriched["remediation"] = "SENTINEL-REMEDIATION-TEXT"
    enriched["remediation_source"] = "deterministic"
    monkeypatch.setattr(main, "get_findings", lambda: [enriched])

    csv_body = client.get("/api/report?format=csv").text
    html_body = client.get("/api/report?format=html").text

    assert "SENTINEL-EXPLANATION-TEXT" not in csv_body
    assert "SENTINEL-EXPLANATION-TEXT" not in html_body, (
        "AI-written prose reached a report that documents itself as "
        "rendering F-1 and nothing else"
    )
    assert "SENTINEL-REMEDIATION-TEXT" not in csv_body
    assert "SENTINEL-REMEDIATION-TEXT" not in html_body, (
        "remediation text reached a report that documents itself as "
        "rendering F-1 and nothing else -- see web/main.py's "
        "_attach_remediation() for why that is still an open decision, "
        "not one this test should silently start allowing"
    )
    assert set(_rows(csv_body)[0]) == set(report.CSV_COLUMNS)
