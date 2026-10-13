"""How much of a partly read file Batfish could read (#317, US-24).

WHAT WAS MEASURED, ON REAL BATFISH, 12 OCTOBER
    `tests/fixtures/vendor-asa` is our one partly parsed fixture. Batfish's
    `parseWarning` lists five lines in fw-asa.cfg as "This syntax is
    unrecognized": `nameif` twice, `security-level` twice, and
    `access-group OUTSIDE_IN in interface outside` -- the line behind #373's
    unused-filter misreport. Until this, the user was told only that the file
    was "partly read".

WHY THE DENOMINATOR IS CONFIGURATION LINES, NOT FILE LINES
    The file has 36 lines and 20 of them are `!` comments. "31 of 36 read"
    (86%) would overstate how much of the configuration Batfish understood;
    "11 of 16 configuration lines" (69%) is the honest figure. Comments are
    only excluded where the format's comment marker is known; otherwise the
    sentence counts non-blank lines and says so.

NO BATFISH in parts 1 and 2: a fake session answers with the exact frames
real Batfish returned. Part 3 runs the real pipeline on vendor-asa.
"""

from pathlib import Path

import pandas as pd
import pytest

from analysis import parse_coverage, pipeline
from conftest import needs_batfish

FIXTURES = Path(__file__).parent / "fixtures"
ASA = FIXTURES / "vendor-asa"
UNRECOGNIZED = "This syntax is unrecognized"

#: The five rows real Batfish returned for vendor-asa, 12 October.
ASA_WARNINGS = [
    ("configs/fw-asa.cfg", 18, "nameif outside", "[s_interface_definition s_interface stanza cisco_configuration]", UNRECOGNIZED),
    ("configs/fw-asa.cfg", 19, "security-level 0", "[s_interface_definition s_interface stanza cisco_configuration]", UNRECOGNIZED),
    ("configs/fw-asa.cfg", 23, "nameif inside", "[s_interface_definition s_interface stanza cisco_configuration]", UNRECOGNIZED),
    ("configs/fw-asa.cfg", 24, "security-level 100", "[s_interface_definition s_interface stanza cisco_configuration]", UNRECOGNIZED),
    ("configs/fw-asa.cfg", 29, "access-group OUTSIDE_IN in interface outside", "[cisco_configuration]", UNRECOGNIZED),
]
ASA_STATUS = [("configs/fw-asa.cfg", "PARTIALLY_UNRECOGNIZED", "CISCO_IOS", ["fw-asa"])]


class _Answer:
    def __init__(self, frame):
        self._frame = frame

    def answer(self):
        return self

    def frame(self):
        return self._frame


class _Session:
    def __init__(self, status, warnings):
        class _Q:
            def fileParseStatus(self):
                return _Answer(pd.DataFrame(status, columns=["File_Name", "Status", "File_Format", "Nodes"]))

            def parseWarning(self):
                return _Answer(pd.DataFrame(warnings, columns=["Filename", "Line", "Text", "Parser_Context", "Comment"]))

        self.q = _Q()


def _describe(status=ASA_STATUS, warnings=ASA_WARNINGS, config_dir=ASA):
    return parse_coverage.describe(_Session(status, warnings), config_dir,
                                   status=pipeline.PARTIAL_PARSE_STATUS)


# --- 1. The sentence ----------------------------------------------------------


def test_the_count_is_unrecognised_lines_over_configuration_lines():
    (sentence,) = _describe()
    assert "configs/fw-asa.cfg (PARTIALLY_UNRECOGNIZED)" in sentence
    assert "did not recognise 5 of its 16 configuration lines" in sentence
    assert "11 were read" in sentence


def test_unrecognised_constructs_are_listed_by_kind_with_their_lines():
    (sentence,) = _describe()
    assert "nameif x2 (lines 18, 23)" in sentence
    assert "security-level x2 (lines 19, 24)" in sentence
    assert "access-group x1 (line 29)" in sentence


def test_kinds_come_most_frequent_first_then_by_name():
    (sentence,) = _describe()
    assert sentence.index("nameif") < sentence.index("security-level") < sentence.index("access-group")


def test_comment_lines_are_excluded_only_where_the_marker_is_known(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "dev.conf").write_text(
        "# a comment\n\nset system host-name dev\nbogus line\n", encoding="utf-8")
    status = [("configs/dev.conf", "PARTIALLY_UNRECOGNIZED", "SOMETHING_NEW", ["dev"])]
    warnings = [("configs/dev.conf", 4, "bogus line", "[x]", UNRECOGNIZED)]
    (sentence,) = _describe(status, warnings, tmp_path)
    # No known marker: the comment line is counted, and the sentence says so.
    assert "did not recognise 1 of its 3 non-blank lines" in sentence
    assert "comments not excluded" in sentence


def test_blank_lines_are_not_configuration_lines_either(tmp_path):
    """fw-asa.cfg has no blank lines, so it cannot show this. Found by a
    mutant that counted them and survived every other test."""
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "r.cfg").write_text(
        "!\nhostname r\n\n\ninterface Gi0/0\n nameif inside\n!\n", encoding="utf-8")
    status = [("configs/r.cfg", "PARTIALLY_UNRECOGNIZED", "CISCO_IOS", ["r"])]
    warnings = [("configs/r.cfg", 6, "nameif inside", "[x]", UNRECOGNIZED)]
    (sentence,) = _describe(status, warnings, tmp_path)
    assert "did not recognise 1 of its 3 configuration lines" in sentence


def test_a_file_batfish_read_completely_is_not_described():
    status = ASA_STATUS + [("configs/other.cfg", "PASSED", "CISCO_IOS", ["other"])]
    assert len(_describe(status)) == 1


def test_warnings_other_than_unrecognised_syntax_are_not_counted():
    warnings = ASA_WARNINGS + [("configs/fw-asa.cfg", 30, "something", "[x]", "This feature is not currently supported")]
    (sentence,) = _describe(warnings=warnings)
    assert "did not recognise 5 of" in sentence


def test_a_partly_read_file_with_no_line_listed_says_so_rather_than_zero():
    """"0 of 16 not recognised" would read as fully read. It is not: Batfish
    said PARTIALLY_UNRECOGNIZED and named no line."""
    (sentence,) = _describe(warnings=[])
    assert "named no specific line" in sentence
    assert "0 of" not in sentence


# --- 2. The pipeline never loses the caveat -----------------------------------


@pytest.fixture
def _stubbed_pipeline(monkeypatch):
    monkeypatch.setattr(pipeline, "connect", lambda *a, **k: object())
    monkeypatch.setattr(pipeline, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "classify_parse_status",
                        lambda bf: ([], ["configs/fw-asa.cfg (PARTIALLY_UNRECOGNIZED)"]))
    monkeypatch.setattr(pipeline, "run_check", lambda bf, name: [
        pipeline.findings.no_issues_finding(check=name, summary="ok", detail="stub",
                                            source="test", device="fw-asa")])


def _caveat(results):
    (caveat,) = [f for f in results if "may be incomplete" in f["summary"]]
    return caveat


def test_the_caveat_carries_the_count_when_it_can_be_measured(monkeypatch, _stubbed_pipeline):
    monkeypatch.setattr(parse_coverage, "describe",
                        lambda bf, config_dir, status: ["SENTINEL-PARSE-COVERAGE-SENTENCE"])
    detail = _caveat(pipeline.analyse(str(ASA)))["evidence"]["detail"]
    assert "SENTINEL-PARSE-COVERAGE-SENTENCE" in detail


def test_the_caveat_survives_when_the_count_cannot_be_measured(monkeypatch, _stubbed_pipeline):
    """A failure measuring coverage must never cost the user the caveat."""
    def broken(bf, config_dir, status):
        raise RuntimeError("parseWarning failed")

    monkeypatch.setattr(parse_coverage, "describe", broken)
    caveat = _caveat(pipeline.analyse(str(ASA)))
    assert caveat["status"] == "error"
    assert "configs/fw-asa.cfg (PARTIALLY_UNRECOGNIZED)" in caveat["evidence"]["detail"]


# --- 3. Real Batfish, and every surface that shows findings (#308) -------------


@needs_batfish
def test_real_vendor_asa_caveat_states_how_much_was_read():
    detail = _caveat(pipeline.analyse(str(ASA)))["evidence"]["detail"]
    assert "did not recognise 5 of its 16 configuration lines" in detail
    assert "access-group x1 (line 29)" in detail


@needs_batfish
def test_real_vendor_asa_count_reaches_the_dashboard_and_both_reports(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from web import main

    monkeypatch.setattr(main, "SESSIONS_ROOT", tmp_path / "sessions")
    client = TestClient(main.app)
    cfg = (ASA / "configs" / "fw-asa.cfg").read_bytes()
    assert client.post("/api/upload", files={"file": ("fw-asa.cfg", cfg, "text/plain")}).status_code == 200

    wanted = "did not recognise 5 of its 16 configuration lines"
    dashboard = client.get("/api/findings").json()
    assert any(wanted in f["evidence"]["detail"] for f in dashboard)
    assert wanted in client.get("/api/report?format=html").text
    assert wanted in client.get("/api/report?format=csv").text
