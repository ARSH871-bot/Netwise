"""Netwise -- tests for the config upload endpoint (POST /api/upload),
including PF Sense conversion wired into it.

WHY THIS FILE EXISTS
    /api/upload had no dedicated test file before this -- only the policy
    upload endpoint did. Closing that gap here, not just adding PF Sense
    coverage on top of nothing.

WHAT THIS PROTECTS, SPECIFICALLY FOR PF SENSE
    1. A REFUSED CONVERSION MUST NEVER DESTROY THE PREVIOUS CONFIG.
       analysis.pfsense_convert.convert() is fallible -- an ambiguous rule
       order, a construct it refuses to guess about. The endpoint converts
       BEFORE clearing the old snapshot, the same validate-then-stage
       discipline test_web_policy_upload.py already covers for policies.
       test_a_refused_conversion_leaves_the_previous_config_staged is the
       guard on that order.

    2. THE `skipped` LIST IS THE REAL ONE, NOT A COPY OF ITS WORDING.
       Every assertion about skip/refusal TEXT below calls the real
       analysis.pfsense_convert.convert()/REFUSALS directly rather than
       hardcoding a copy of the string -- the exact lesson #199's review
       found the hard way: a copied literal stops testing anything the
       moment the real wording changes, silently.

NO BATFISH, NO OLLAMA, NO NETWORK. Conversion is pure XML parsing; nothing
here calls analysis.pipeline.analyse().
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from analysis.pfsense_convert import REFUSALS, convert
from web import main

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _post_config(contents: bytes, filename: str, content_type: str = "text/plain"):
    return client.post(
        "/api/upload",
        files={"file": (filename, contents, content_type)},
    )


_LAN_ONLY_XML = b"""<?xml version="1.0"?>
<pfsense>
  <system><hostname>test-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

# One modellable interface (lan), one that is not (wan, DHCP -- no static
# address) -- the client's real shape from CLAUDE.md section 7.
_LAN_AND_DHCP_WAN_XML = b"""<?xml version="1.0"?>
<pfsense>
  <system><hostname>skip-device</hostname></system>
  <interfaces>
    <wan><if>em0</if></wan>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol>
    <source><any/></source><destination><any/></destination></rule>
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <source><any/></source><destination><any/></destination></rule>
  </filter>
</pfsense>
"""

# No <filter> rules at all -- convert() refuses this unconditionally
# (analysis/pfsense_convert.py, REFUSALS["no_filter_rules"]).
_NO_RULES_XML = b"""<?xml version="1.0"?>
<pfsense>
  <system><hostname>bad-device</hostname></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter></filter>
</pfsense>
"""


@pytest.fixture(autouse=True)
def clean_staging():
    """Same reasoning as test_web_policy_upload.py's fixture of the same
    name: module-level paths survive a test, so leftover staged files would
    be visible to the next test.

    pfsense_skips_path() lives BESIDE configs/, not inside it (same reason
    policy.json does -- see its own comment in web/main.py), so clearing
    CONFIGS_DIR does not touch it. Cleaned separately here for the same
    reason the policy upload tests clean POLICY_PATH separately.
    """
    import shutil

    def _clear():
        if main.CONFIGS_DIR.exists():
            shutil.rmtree(main.CONFIGS_DIR)
        main.pfsense_skips_path().unlink(missing_ok=True)
        main.pfsense_skips_path().with_name(
            main.pfsense_skips_path().name + ".tmp"
        ).unlink(missing_ok=True)

    _clear()
    yield
    _clear()


# ---------------------------------------------------------------------------
# The existing, non-PF-Sense path -- unchanged behaviour, now actually tested
# ---------------------------------------------------------------------------


def test_a_plain_cisco_config_is_accepted_and_staged_unchanged():
    response = _post_config(b"hostname rtr-us5\n", "device.cfg")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] is True
    assert body["skipped"] == []

    staged = list(main.CONFIGS_DIR.glob("*"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b"hostname rtr-us5\n"


def test_an_unrecognised_extension_is_still_rejected():
    response = _post_config(b"whatever", "device.bin")

    assert response.status_code == 400
    assert "PF Sense" in response.json()["detail"]


def test_an_empty_file_is_still_rejected():
    response = _post_config(b"", "device.cfg")
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# PF Sense: the happy path
# ---------------------------------------------------------------------------


def test_a_pfsense_export_is_converted_and_staged():
    response = _post_config(_LAN_ONLY_XML, "config.xml", "application/xml")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] is True
    assert body["skipped"] == []
    assert "converted" in body["message"].lower()

    staged = list(main.CONFIGS_DIR.glob("*"))
    assert len(staged) == 1
    text = staged[0].read_text()
    assert "hostname test-device" in text
    assert "permit tcp" in text  # the lan rule really converted


def test_the_pfsense_extension_variant_also_works():
    """PFSENSE_EXTENSIONS has two entries -- both must actually work, not
    just be listed."""
    response = _post_config(_LAN_ONLY_XML, "config.pfsense", "application/xml")
    assert response.status_code == 200, response.text


def test_skipped_interfaces_are_surfaced_and_genuinely_excluded():
    response = _post_config(
        _LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml"
    )

    assert response.status_code == 200, response.text
    body = response.json()

    # Compare against the REAL converter's own output, not a copied string --
    # #199's lesson, applied here.
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(
        suffix=".xml", delete=False
    ) as tmp:
        tmp.write(_LAN_AND_DHCP_WAN_XML)
        tmp_path = Path(tmp.name)
    try:
        expected = convert(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    assert body["skipped"] == expected.skipped
    assert len(body["skipped"]) == 1
    assert "wan" in body["skipped"][0]

    staged_text = list(main.CONFIGS_DIR.glob("*"))[0].read_text()
    assert staged_text == expected.text
    assert "em0" not in staged_text  # the wan rule never reached the output


# ---------------------------------------------------------------------------
# PF Sense: skip notes reach the downloaded report too (#302 review)
#
# Before this, `skipped` reached the user exactly once, in the upload
# response, and was gone -- a report downloaded later from the same staged
# config had no way to know a rule had been excluded, and could claim
# "Every reported check ran. Nothing was skipped." about a config that was
# missing real rules. See analysis/coverage.py and CLAUDE.md section 7 for
# why that specific claim is dangerous, not just imprecise.
# ---------------------------------------------------------------------------


def test_a_plain_cisco_upload_never_stages_a_skip_file():
    _post_config(b"hostname rtr-us5\n", "device.cfg")
    assert not main.pfsense_skips_path().exists()
    assert main._staged_pfsense_skips() == []


def test_a_clean_pfsense_upload_never_stages_a_skip_file():
    """Nothing was skipped, so there is nothing to persist -- a missing
    file and an empty list mean the same thing to _staged_pfsense_skips()."""
    _post_config(_LAN_ONLY_XML, "config.xml", "application/xml")
    assert not main.pfsense_skips_path().exists()
    assert main._staged_pfsense_skips() == []


def test_a_pfsense_upload_with_skips_persists_them_for_the_report():
    response = _post_config(
        _LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml"
    )
    body = response.json()

    assert main.pfsense_skips_path().exists()
    assert main._staged_pfsense_skips() == body["skipped"]
    assert "wan" in main._staged_pfsense_skips()[0]


def test_a_new_upload_clears_the_previous_uploads_skip_notes():
    """The exact reasoning _discard_staged_policy() already has: a skip note
    names a rule and interface from the PREVIOUS config. A plain Cisco
    upload afterwards must not leave it staged, pointing at a file that is
    no longer there."""
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    assert main.pfsense_skips_path().exists()

    _post_config(b"hostname rtr-us5\n", "device.cfg")
    assert not main.pfsense_skips_path().exists()
    assert main._staged_pfsense_skips() == []


def test_a_refused_conversion_does_not_touch_the_previous_uploads_skip_notes():
    """Same validate-then-stage discipline as the staged CONFIG file itself
    (test_a_refused_conversion_leaves_the_previous_config_staged, below) --
    a refused second upload must leave the first upload's skip notes alone,
    same as it leaves the first upload's config alone."""
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    before = main._staged_pfsense_skips()
    assert before

    refused = _post_config(_NO_RULES_XML, "config.xml", "application/xml")
    assert refused.status_code == 400
    assert main._staged_pfsense_skips() == before


def test_the_downloaded_report_names_a_skipped_rule():
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")

    response = client.get("/api/report?format=html")
    assert response.status_code == 200
    assert "Excluded during conversion" in response.text
    assert "wan" in response.text
    assert "no static address configured" in response.text


def test_the_downloaded_report_does_not_falsely_claim_nothing_was_skipped():
    """The exact claim #302's review flagged. It must never appear on a
    report generated from an upload that genuinely skipped something."""
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")

    response = client.get("/api/report?format=html")
    assert "Every reported check ran. Nothing was skipped." not in response.text


def test_a_clean_pfsense_uploads_report_is_unaffected():
    """The fix must not invent a claim where there is genuinely nothing to
    disclose -- a clean conversion still reads exactly as it did before."""
    _post_config(_LAN_ONLY_XML, "config.xml", "application/xml")

    response = client.get("/api/report?format=html")
    assert "Excluded during conversion" not in response.text


# ---------------------------------------------------------------------------
# PF Sense: an unreadable skip record is a THIRD state, not the same as a
# verified-empty one (#302 review, round two, @ARSH871-bot)
#
# Before this, `_staged_pfsense_skips()` returned [] both when there was
# genuinely nothing to disclose AND when the skip record existed but could
# not be parsed -- a truncated write, a corrupted file, valid JSON of the
# wrong type. coverage.summarise() then said "Every reported check ran.
# Nothing was skipped." in both cases, which is a real, positive claim of
# completeness in the second case built on a record nobody actually read.
# ---------------------------------------------------------------------------


def test_an_unreadable_skip_record_returns_none_not_an_empty_list():
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    assert main._staged_pfsense_skips()  # sanity: the file is genuinely there

    main.pfsense_skips_path().write_text("{not valid json", encoding="utf-8")
    assert main._staged_pfsense_skips() is None


def test_a_skip_record_of_the_wrong_json_type_is_also_none():
    """Valid JSON, but not a list -- e.g. a stray object or a bare string.
    Silently returning [] here would be the same false-completeness claim
    the truncated-file case makes, just reached a different way."""
    main.pfsense_skips_path().write_text('{"not": "a list"}', encoding="utf-8")
    assert main._staged_pfsense_skips() is None


def test_a_missing_skip_file_is_still_a_verified_empty_list():
    """The one case that must NOT become None: no file at all means no
    PF Sense conversion happened (or it excluded nothing), which is a real,
    verified absence -- not "we don't know"."""
    assert not main.pfsense_skips_path().exists()
    assert main._staged_pfsense_skips() == []


def test_an_unreadable_skip_record_makes_the_report_say_so_not_claim_clean():
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    main.pfsense_skips_path().write_text("not json", encoding="utf-8")

    response = client.get("/api/report?format=html")
    assert response.status_code == 200
    assert "Every reported check ran. Nothing was skipped." not in response.text
    assert "could not be read" in response.text


def test_the_upload_write_is_atomic_no_tmp_file_survives():
    """#302 review's secondary suggestion: write via a temp file + replace
    so an interrupted write cannot leave a truncated skip record in the
    first place. Checked here as an observable property -- no leftover
    .tmp file after a normal upload -- since a real kill-mid-write is not
    reproducible in a unit test."""
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    tmp_path = main.pfsense_skips_path().with_name(
        main.pfsense_skips_path().name + ".tmp"
    )
    assert not tmp_path.exists()
    assert main._staged_pfsense_skips() is not None


# ---------------------------------------------------------------------------
# /api/findings discloses conversion gaps via headers, persistently
# (#302 review, @shubhamkataria2005)
#
# Before this, `skipped` reached the user exactly once, in the upload
# response, rendered into the transient #upload-message box by
# addSkippedNotes(). A page reload followed by Scan Now showed clean tiles
# with no trace anything had been excluded -- /api/findings itself said
# nothing about it. These two headers are read on every /api/findings
# fetch, so the disclosure survives a reload the same way the count itself
# does.
# ---------------------------------------------------------------------------


def test_api_findings_sets_a_zero_count_header_for_a_plain_upload():
    _post_config(b"hostname rtr-us5\n", "device.cfg")
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.headers["X-Netwise-Conversion-Gap-Count"] == "0"
    assert response.headers["X-Netwise-Conversion-Gaps-Unreadable"] == "false"


def test_api_findings_sets_a_zero_count_header_before_any_upload():
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.headers["X-Netwise-Conversion-Gap-Count"] == "0"
    assert response.headers["X-Netwise-Conversion-Gaps-Unreadable"] == "false"


def test_api_findings_reports_the_real_count_after_a_pfsense_upload_with_skips():
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    response = client.get("/api/findings")
    assert response.headers["X-Netwise-Conversion-Gap-Count"] == "1"
    assert response.headers["X-Netwise-Conversion-Gaps-Unreadable"] == "false"


def test_api_findings_reports_unreadable_not_zero_for_a_corrupted_record():
    """The exact case #302's second review round found: a corrupted skip
    record must never present itself as 'nothing was excluded'."""
    _post_config(_LAN_AND_DHCP_WAN_XML, "config.xml", "application/xml")
    main.pfsense_skips_path().write_text("not json", encoding="utf-8")

    response = client.get("/api/findings")
    assert response.headers["X-Netwise-Conversion-Gaps-Unreadable"] == "true"
    assert response.headers["X-Netwise-Conversion-Gap-Count"] == "0"


def test_get_findings_called_directly_with_no_response_does_not_raise():
    """download_report() and several tests call get_findings() as a plain
    Python function, with no FastAPI-injected Response to attach headers
    to -- http_response must default to something that makes that safe."""
    result = main.get_findings()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# PF Sense: refusal, and the safety property around it
# ---------------------------------------------------------------------------


def test_malformed_xml_returns_400_not_a_500():
    """Found by testing a deliberately broken upload rather than only the
    well-formed refusal fixtures: convert() calls ET.parse() before it ever
    reaches PfSenseConversionError, so a truncated download or a non-XML
    file with an .xml extension raised ET.ParseError uncaught -- a raw 500
    with a traceback instead of a message written for a person."""
    response = _post_config(b"this is not xml at all", "config.xml", "application/xml")

    assert response.status_code == 400, (
        f"malformed XML must be a clean 400, not a {response.status_code}"
    )
    assert "not readable XML" in response.json()["detail"]


def test_a_refused_conversion_returns_400_with_the_real_reason():
    response = _post_config(_NO_RULES_XML, "config.xml", "application/xml")

    assert response.status_code == 400
    # Against the real REFUSALS entry, not a copy of its wording.
    assert REFUSALS["no_filter_rules"] in response.json()["detail"]


def test_a_refused_conversion_leaves_the_previous_config_staged():
    """The property this file exists to protect. A PF Sense export that
    fails to convert must not take the working config down with it."""
    first = _post_config(b"hostname rtr-us5\n", "device.cfg")
    assert first.status_code == 200

    second = _post_config(_NO_RULES_XML, "config.xml", "application/xml")
    assert second.status_code == 400

    staged = list(main.CONFIGS_DIR.glob("*"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b"hostname rtr-us5\n", (
        "the refused PF Sense upload destroyed the previously staged config"
    )


def test_a_refused_conversion_does_not_set_uploaded_true():
    """A rejected upload must not make the dashboard believe something is
    staged when the reject path never reached staging."""
    main._uploaded = False

    response = _post_config(_NO_RULES_XML, "config.xml", "application/xml")

    assert response.status_code == 400
    assert main._uploaded is False
