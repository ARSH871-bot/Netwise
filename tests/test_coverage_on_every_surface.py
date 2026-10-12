"""A coverage statement must reach every surface that shows findings (#308).

THE RULE, AS AGREED ON #308
    "A coverage statement must appear on every surface that renders
    findings. A surface that cannot carry it must say so, not omit it."
    (@SamikaPerera's wording, which builds F-4's asymmetry in: the silent
    surface is the one that looks complete.)

WHAT WAS MEASURED BEFORE THIS TEST EXISTED, on main (`fa568f7`), 8 October
    A PF Sense upload whose DHCP WAN rule could not be converted:

        dashboard   X-Netwise-Conversion-Gap-Count: 1      says so
        HTML        "Excluded during conversion ... wan"   says so
        CSV         three could-not-check rows, nothing    SILENT

    The CSV is the export most likely to be forwarded, and it read as a
    complete account of a firewall that had a rule left out.

THE SURFACES ARE ENUMERATED, NOT DISCOVERED
    This test knows three surfaces: `/api/findings` (whose conversion facts
    travel in response headers that `app.js` renders, pinned by
    tests/js/conversion_gaps_notice_harness.js), the HTML report and the
    CSV report. A fourth surface added later will not be caught here unless
    someone adds it to SURFACES. @SamikaPerera asked for that to be said
    rather than implied, and it is the honest limit of this test.

NO BATFISH
    The upload, the real PF Sense converter and the real skip record are all
    used. Only `pipeline._analyse` is replaced, with canned findings, because
    what is under test is whether a fact about coverage reaches each surface
    -- not what the checks find.
"""

import html

import pytest
from fastapi.testclient import TestClient

from analysis import findings, pipeline
from web import main

# One modellable interface (lan) and one that is not (wan, DHCP): the
# client's real shape, and the converter skips exactly one rule for it.
DHCP_WAN_XML = b"""<?xml version="1.0"?>
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

CISCO = b"hostname rtr-us5\n!\ninterface GigabitEthernet0/0\n ip address 10.10.10.1 255.255.255.0\n"

#: Every check ran clean: the case where a silent surface does the most harm,
#: because nothing else on it hints that anything was left out.
CLEAN = [
    findings.make_finding(check=check, severity="low", device="skip-device",
                          summary=f"No issues found by {check}", detail="ran clean",
                          source="test", status="none", number=0)
    for check in ("access_control", "policy_compliance", "routing")
]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "SESSIONS_ROOT", tmp_path / "sessions")
    monkeypatch.setattr(pipeline, "_analyse", lambda *a, **k: [dict(f) for f in CLEAN])
    return TestClient(main.app)


def _dashboard(client):
    response = client.get("/api/findings")
    assert response.status_code == 200
    return {
        "count": response.headers.get("x-netwise-conversion-gap-count"),
        "unreadable": response.headers.get("x-netwise-conversion-gaps-unreadable"),
    }


def _html(client):
    return client.get("/api/report?format=html").text


def _csv_column(client):
    import csv
    import io

    rows = list(csv.DictReader(io.StringIO(client.get("/api/report?format=csv").text)))
    assert rows, "the CSV has no rows to carry anything"
    assert "excluded_during_conversion" in rows[0], "the CSV has no column for it"
    values = {row["excluded_during_conversion"] for row in rows}
    assert len(values) == 1, f"rows disagree about what was excluded: {values}"
    return values.pop()


SURFACES = ("dashboard", "html", "csv")


def test_a_skipped_rule_is_named_on_every_surface(client):
    upload = client.post("/api/upload", files={"file": ("config.xml", DHCP_WAN_XML, "application/xml")})
    (note,) = upload.json()["skipped"]
    assert "wan" in note

    assert _dashboard(client) == {"count": "1", "unreadable": "false"}
    assert html.escape(note) in _html(client)  # the report escapes every value
    assert _csv_column(client) == note


def test_nothing_excluded_is_claimed_on_no_surface(client):
    """The other direction: a plain upload must not acquire a gap anywhere."""
    client.post("/api/upload", files={"file": ("rtr.cfg", CISCO, "text/plain")})

    assert _dashboard(client) == {"count": "0", "unreadable": "false"}
    assert "Excluded during conversion" not in _html(client)
    assert _csv_column(client) == ""


def test_an_unreadable_record_is_unknown_on_every_surface(client):
    """A record that exists and cannot be read is "we cannot tell", never
    "nothing was excluded" (#302 review). Every surface must say the same."""
    client.post("/api/upload", files={"file": ("config.xml", DHCP_WAN_XML, "application/xml")})
    main.pfsense_skips_path().write_text("{truncated", encoding="utf-8")

    assert _dashboard(client)["unreadable"] == "true"
    assert "could not be read" in _html(client)
    assert _csv_column(client).startswith("UNKNOWN")


def test_every_surface_is_listed():
    """A deliberately dumb guard: if someone removes a surface from this file,
    the docstring's claim of three stops being true without anything failing."""
    assert SURFACES == ("dashboard", "html", "csv")
