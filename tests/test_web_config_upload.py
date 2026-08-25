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
    be visible to the next test."""
    import shutil

    if main.CONFIGS_DIR.exists():
        shutil.rmtree(main.CONFIGS_DIR)
    yield
    if main.CONFIGS_DIR.exists():
        shutil.rmtree(main.CONFIGS_DIR)


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
# PF Sense: refusal, and the safety property around it
# ---------------------------------------------------------------------------


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
