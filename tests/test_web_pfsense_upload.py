"""A PF Sense export can be uploaded, converted, and analysed (#78).

WHAT WAS WRONG BEFORE
    `analysis/pfsense_convert.py` was written, hardened against config
    injection and path traversal (#53), against unbound ACLs and unvalidated
    addressing (#54), and against ambiguous rule order (#58, #104). It had
    been run against the client's own anonymised export.

    Nothing in `web/` or `analysis/pipeline.py` imported it. The upload
    rejected `.xml` with the message "converting it is still open work" --
    false for weeks. So the client's actual firewall, the entire reason the
    converter exists, could not be put into the product at all.

THE SAFETY PROPERTY THESE TESTS EXIST FOR
    Batfish reads EVERY file under `configs/`. A PF Sense XML landing there
    would be handed to a parser that cannot read it, producing either a parse
    error blamed on the user's network or -- worse -- a snapshot that
    analyses cleanly while containing a file that is not a config.

    So the XML must never reach the snapshot directory. Only `convert()`'s
    Cisco IOS output is staged. That is asserted directly below, not assumed.

NO BATFISH NEEDED
    Conversion is pure Python. Every test here runs with Docker stopped.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


#: Two interfaces, both with static addresses and filter rules. Converts
#: completely, so `skipped` must come back EMPTY -- the control case.
CLEAN_EXPORT = """<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw-clean</hostname><domain>example.com</domain></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.10.10.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>10.20.0.5</address><port>443</port></destination>
      <quick/>
    </rule>
  </filter>
</pfsense>
"""

#: A WAN on DHCP that CARRIES RULES. There is no address to bind a Cisco ACL
#: to, so those rules cannot be modelled -- and must be named, not dropped.
SKIPPING_EXPORT = """<?xml version="1.0"?>
<pfsense>
  <system><hostname>fw-partial</hostname><domain>example.com</domain></system>
  <interfaces>
    <lan><if>em1</if><ipaddr>10.10.10.1</ipaddr><subnet>24</subnet></lan>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>10.20.0.5</address><port>443</port></destination>
      <quick/>
    </rule>
    <rule>
      <type>block</type><interface>wan</interface><ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination><address>10.10.10.5</address><port>22</port></destination>
      <quick/>
    </rule>
  </filter>
</pfsense>
"""


def _upload(body: bytes, filename: str = "config.xml"):
    return client.post(
        "/api/upload", files={"file": (filename, body, "text/xml")})


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    snapshot = tmp_path / "current"
    (snapshot / "configs").mkdir(parents=True)
    monkeypatch.setattr(main, "SNAPSHOT_DIR", snapshot)
    monkeypatch.setattr(main, "CONFIGS_DIR", snapshot / "configs")
    monkeypatch.setattr(main, "POLICY_PATH", snapshot / "policy.json")
    yield


# ---------------------------------------------------------------------------
# It is accepted at all -- the gap this closes
# ---------------------------------------------------------------------------


def test_a_pfsense_export_is_accepted_rather_than_rejected():
    response = _upload(CLEAN_EXPORT.encode())

    assert response.status_code == 200, response.text
    assert response.json()["converted"] is True


@pytest.mark.parametrize("filename", ["config.xml", "backup.pfsense"])
def test_both_pfsense_extensions_are_accepted(filename):
    assert _upload(CLEAN_EXPORT.encode(), filename).status_code == 200


# ---------------------------------------------------------------------------
# The safety property: the XML must not reach the snapshot
# ---------------------------------------------------------------------------


def test_the_xml_never_lands_in_the_configs_directory():
    """Batfish reads every file under configs/. This one must not be there.

    If it were, Batfish would either fail to parse it and blame the user's
    network, or -- worse -- produce a snapshot that analyses cleanly while
    containing a file that is not a config at all.
    """
    _upload(CLEAN_EXPORT.encode())

    staged = sorted(p.name for p in main.CONFIGS_DIR.iterdir())

    assert staged == ["device.cfg"], (
        f"expected only the converted Cisco text, found {staged}"
    )
    assert not any(name.endswith((".xml", ".pfsense")) for name in staged)


def test_what_is_staged_is_the_converted_cisco_text():
    """Not the XML renamed -- actually converted."""
    _upload(CLEAN_EXPORT.encode())

    text = (main.CONFIGS_DIR / "device.cfg").read_text(encoding="utf-8")

    assert text.lstrip().startswith("hostname "), (
        "the staged file does not look like a Cisco config"
    )
    assert "<pfsense>" not in text, "the XML was staged verbatim"
    assert "ip access-list" in text, "no ACL was emitted from the filter rules"


# ---------------------------------------------------------------------------
# `skipped` -- the account of what was left out
# ---------------------------------------------------------------------------


def test_a_fully_convertible_export_reports_nothing_skipped():
    """The control case. Without it, an always-non-empty list would pass the
    test below while meaning nothing."""
    body = _upload(CLEAN_EXPORT.encode()).json()

    assert body["skipped"] == [], (
        f"nothing in this export is unmodellable, so skipped must be empty: "
        f"{body['skipped']}"
    )


def test_rules_that_cannot_be_modelled_are_named_not_dropped():
    """The WAN is on DHCP and carries rules, so those rules cannot be modelled.

    Reporting "converted" while silently analysing 1 of 2 rule sets is the
    found/error confusion arriving through the front door: the user would
    believe their whole firewall had been checked.
    """
    body = _upload(SKIPPING_EXPORT.encode()).json()

    assert body["skipped"], (
        "the WAN carries rules and has no static address to bind an ACL to, "
        "so those rules were left out -- and saying nothing about it would "
        "let the user believe their whole firewall was analysed"
    )
    assert any("wan" in entry.lower() for entry in body["skipped"]), (
        f"the skipped list must NAME the interface: {body['skipped']}"
    )


def test_the_convertible_half_still_converts():
    """A partial conversion must still produce the part it could model.

    #197's whole point: an unmodellable rule is refused individually, not at
    the cost of the entire file.
    """
    _upload(SKIPPING_EXPORT.encode())

    text = (main.CONFIGS_DIR / "device.cfg").read_text(encoding="utf-8")

    assert "10.20.0.5" in text, (
        "the LAN rule is perfectly modellable and must still be there"
    )


# ---------------------------------------------------------------------------
# Refusals -- a 400 with the reason, never a 500
# ---------------------------------------------------------------------------


def test_unreadable_xml_is_a_400_naming_the_problem():
    response = _upload(b"<pfsense><system>truncated")

    assert response.status_code == 400
    assert "xml" in response.json()["detail"].lower()


def test_an_export_with_nothing_modellable_is_refused_not_analysed():
    """Nothing modellable must not be staged.

    Analysing an empty config reports a clean network -- the most dangerous
    possible answer, because it is indistinguishable from a real all-clear.

    WHICH GUARD THIS ACTUALLY EXERCISES
        `convert()`'s, not the endpoint's. I assumed it reached
        `_convert_upload()`'s empty-text check and it does not: probed
        directly, every empty-ish export is refused by the converter first
        ("no interface has both a static address and a subnet"). The
        endpoint's check is unreachable today and says so in a comment.

        The user-facing behaviour asserted here is right either way, which is
        why the test stays -- but claiming it covers the endpoint guard would
        have been false.
    """
    empty = ("<?xml version='1.0'?><pfsense>"
             "<system><hostname>fw</hostname></system>"
             "<interfaces></interfaces></pfsense>")

    response = _upload(empty.encode())

    assert response.status_code == 400, (
        "an export with nothing modellable in it must be refused; staging it "
        "would report an empty network as clean"
    )
    assert not list(main.CONFIGS_DIR.iterdir()), "nothing may be staged"


def test_a_refusal_stages_nothing_at_all():
    """A rejected upload must leave the previous snapshot untouched."""
    _upload(CLEAN_EXPORT.encode())
    before = (main.CONFIGS_DIR / "device.cfg").read_text(encoding="utf-8")

    _upload(b"<pfsense>not valid")

    assert (main.CONFIGS_DIR / "device.cfg").read_text(encoding="utf-8") == before, (
        "a failed upload overwrote the config that was already staged"
    )
