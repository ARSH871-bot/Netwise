"""
Netwise -- tests for analysis/pfsense_convert.py.

WHY THESE TESTS EXIST
    The converter itself was verified against live Batfish before any test
    was written: the converted output parses cleanly, and four testFilters
    checks plus one whole-space searchFilters check confirm it encodes
    exactly the same policy as the hand-written tests/fixtures/rtr-us5-secure
    Cisco fixture (see the reference doc for the full account, including the
    exact numbers). These tests exist so that guarantee cannot regress
    silently -- they exercise the converter's pure logic directly, no
    Batfish or Docker needed, so they run in milliseconds like every other
    test in this repo.

RUN
    pytest tests/ -v
"""

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from analysis.pfsense_convert import PfSenseConversionError, convert, write_snapshot

FIXTURE = "tests/fixtures/pfsense-source/config.xml"


def _minimal_xml(
    *, rules_xml: str = "", interfaces_xml: str | None = None, hostname: str = "test-device"
) -> str:
    """Build a minimal, valid PF Sense config.xml string for a single test,
    so each test can vary exactly the one thing it is checking rather than
    editing the shared fixture."""
    if interfaces_xml is None:
        interfaces_xml = """
        <lan>
          <if>em1</if>
          <descr>LAN</descr>
          <ipaddr>10.0.0.1</ipaddr>
          <subnet>24</subnet>
        </lan>
        """
    return f"""<?xml version="1.0"?>
    <pfsense>
      <system><hostname>{hostname}</hostname></system>
      <interfaces>{interfaces_xml}</interfaces>
      <filter>{rules_xml}</filter>
    </pfsense>
    """


def _convert_string(xml_text: str) -> str:
    """convert() takes a path; tests build XML in memory, so write it to a
    real temp file rather than duplicating convert()'s parsing logic here."""
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(xml_text)
        path = Path(f.name)
    try:
        return convert(path)
    finally:
        path.unlink()


# --- The real fixture, end to end -------------------------------------------


def test_the_real_fixture_converts_without_raising():
    output = convert(FIXTURE)
    assert "hostname pfsense-us5" in output


def test_the_real_fixture_produces_the_expected_acl():
    """This is the exact ACL independently verified against live Batfish --
    see the reference doc. Pinning it here means a change to the converter
    that alters this output gets caught immediately, before anyone has to
    re-run Batfish to notice."""
    output = convert(FIXTURE)
    assert "permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq 53" in output
    assert "permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 eq 443" in output
    assert "deny ip any any" in output


def test_the_real_fixture_binds_the_acl_to_the_lan_interface():
    output = convert(FIXTURE)
    assert "ip access-group acl_in in" in output


def test_the_real_fixture_uses_a_valid_cisco_interface_name_not_the_raw_pfsense_one():
    """Regression coverage for the reason interface names are rewritten at
    all: 'em0'/'em1' are FreeBSD device names, not valid Cisco IOS syntax,
    and Batfish's Cisco grammar would fail to parse them."""
    output = convert(FIXTURE)
    assert "interface GigabitEthernet0/0" in output
    assert "interface em0" not in output
    assert "em0" in output  # kept as a comment for traceability, not discarded


# --- Interfaces ----------------------------------------------------------------


def test_wan_and_lan_get_different_synthetic_interface_names():
    xml_text = _minimal_xml(interfaces_xml="""
        <wan><if>em0</if><ipaddr>1.2.3.1</ipaddr><subnet>30</subnet></wan>
        <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    """)
    output = _convert_string(xml_text)
    assert "interface GigabitEthernet0/0" in output
    assert "interface GigabitEthernet0/1" in output


def test_interface_without_a_static_address_is_skipped_not_guessed():
    """A DHCP-assigned interface has no <ipaddr>/<subnet> to convert. Skipping
    it is correct; inventing an address would not be."""
    xml_text = _minimal_xml(interfaces_xml="""
        <wan><if>em0</if></wan>
        <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    """)
    output = _convert_string(xml_text)
    assert output.count("interface Gigabit") == 1


def test_no_interfaces_with_an_address_raises():
    xml_text = _minimal_xml(interfaces_xml="<wan><if>em0</if></wan>")
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


# --- Rules: action and protocol mapping -----------------------------------------


def test_pass_becomes_permit():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    assert "permit tcp any any" in _convert_string(xml_text)


def test_block_becomes_deny():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    assert "deny tcp any any" in _convert_string(xml_text)


def test_reject_also_becomes_deny():
    """PF Sense distinguishes 'block' (silent drop) from 'reject' (drop with
    a response). Cisco ACLs only have one denial verb, so both map to it --
    the distinction is lost, which is acceptable for what this converter is
    for (loading into Batfish for filtering analysis), not hidden."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>reject</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    assert "deny tcp any any" in _convert_string(xml_text)


def test_protocol_any_becomes_cisco_ip():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>any</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    assert "permit ip any any" in _convert_string(xml_text)


def test_unsupported_rule_type_raises():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>match</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_combined_tcp_udp_protocol_raises_rather_than_guessing():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp/udp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


# --- Rules: source/destination resolution ---------------------------------------


def test_network_reference_resolves_to_the_interface_subnet():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><network>lan</network></source><destination><any/></destination></rule>
    """)
    assert "permit tcp 10.0.0.0 0.0.0.255 any" in _convert_string(xml_text)


def test_address_resolves_to_a_host_clause():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>192.0.2.5</address></destination></rule>
    """)
    assert "permit tcp any host 192.0.2.5" in _convert_string(xml_text)


def test_destination_port_is_included_for_tcp():
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>192.0.2.5</address><port>8443</port></destination></rule>
    """)
    assert "eq 8443" in _convert_string(xml_text)


def test_port_is_not_emitted_for_protocol_any():
    """A port clause only makes sense for tcp/udp -- Cisco's 'ip' protocol
    keyword (used for PF Sense's 'any') does not take a port."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>any</protocol>
        <source><any/></source><destination><address>192.0.2.5</address><port>443</port></destination></rule>
    """)
    output = _convert_string(xml_text)
    assert "eq" not in output


def test_a_named_alias_in_address_raises_rather_than_being_emitted_as_a_host():
    """Regression coverage for the review finding: PF Sense's <address> can
    hold a named alias (e.g. "TRUSTED_HOSTS") instead of a literal IP.
    Without validation this became "host TRUSTED_HOSTS" -- not valid Cisco
    syntax, and measured to NOT make Batfish reject the file outright:
    fileParseStatus reports PARTIALLY_UNRECOGNIZED and Batfish silently drops
    just that line. Must raise here, at the layer that knows what went
    wrong, rather than depend on analysis.pipeline's parse strictness (which
    is itself under proposal to relax for real-world configs) as the only
    thing catching it."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>udp</protocol>
        <source><address>TRUSTED_HOSTS</address></source><destination><any/></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_a_named_alias_in_port_raises_rather_than_being_emitted_literally():
    """Same class of gap as the <address> case above, found by auditing the
    rest of the module for the identical pattern once the review pointed
    out the first instance: PF Sense's <port> can hold a named alias (e.g.
    "HTTPS_ALT") instead of a number, which would otherwise become the
    equally invalid "eq HTTPS_ALT"."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.0.0.5</address><port>HTTPS_ALT</port></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_port_zero_and_out_of_range_also_raise():
    """Boundary check for the same validation -- a port must be in the
    valid 1-65535 range, not merely 'looks like digits'."""
    for bad_port in ("0", "65536", "999999"):
        xml_text = _minimal_xml(rules_xml=f"""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><address>10.0.0.5</address><port>{bad_port}</port></destination></rule>
        """)
        with pytest.raises(PfSenseConversionError):
            _convert_string(xml_text)


def test_unresolvable_network_reference_raises():
    """A network alias this converter does not resolve (e.g. PF Sense's
    'lanip', meaning the interface's own address rather than its subnet)
    must raise, not silently fall back to something plausible-looking."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><network>lanip</network></source><destination><any/></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


# --- Rules spanning more than one interface --------------------------------------


def test_rules_on_two_different_interfaces_raises():
    """Batfish/Cisco needs one ACL per interface direction. Merging rules
    from two interfaces into a single ACL would silently change what the
    config means, so this is refused rather than attempted."""
    xml_text = _minimal_xml(
        interfaces_xml="""
            <wan><if>em0</if><ipaddr>1.2.3.1</ipaddr><subnet>30</subnet></wan>
            <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
        """,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


# --- Rule order is preserved -----------------------------------------------------


def test_rules_are_emitted_in_document_order():
    """Cisco ACLs are first-match-wins, so order is meaning, not just
    style -- a converter that reordered rules would change the policy."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.0.0.5</address><port>22</port></destination></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    output = _convert_string(xml_text)
    deny_pos = output.index("deny tcp any host 10.0.0.5 eq 22")
    permit_pos = output.index("permit tcp any any")
    assert deny_pos < permit_pos


# --- Free-text fields cannot inject additional config lines -----------------------
# Regression coverage for a senior-level adversarial QA finding: a literal
# newline inside an XML text node is valid XML, and <hostname>/<descr>/<if>
# were all emitted into the generated Cisco config text unescaped. Cisco IOS
# parses config line by line, and a REPEATED "ip access-list extended NAME"
# block APPENDS to the existing ACL rather than replacing it -- confirmed live,
# an injected line landed inside the real acl_in ACL, evaluated BEFORE the
# legitimate rules. An actual policy bypass in the converted config, not just
# corrupted-looking output.


def test_hostname_with_an_embedded_newline_raises():
    xml_text = _minimal_xml(
        hostname="probe\nip access-list extended acl_in\n permit ip any any"
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_descr_with_an_embedded_newline_does_not_inject_additional_config_lines():
    xml_text = _minimal_xml(
        interfaces_xml="""
        <lan>
          <if>em1</if>
          <descr>LAN&#10;ip access-list extended acl_in&#10; permit ip any any</descr>
          <ipaddr>10.0.0.1</ipaddr>
          <subnet>24</subnet>
        </lan>
        """
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_if_with_an_embedded_newline_also_raises():
    """The raw PF Sense device identifier (e.g. "em0") is emitted into the
    same description line as <descr> -- same field, same injection vector,
    same fix, checked separately since it is read by a different _text()
    call."""
    xml_text = _minimal_xml(
        interfaces_xml="""
        <lan>
          <if>em1&#10;ip access-list extended acl_in&#10; permit ip any any</if>
          <descr>LAN</descr>
          <ipaddr>10.0.0.1</ipaddr>
          <subnet>24</subnet>
        </lan>
        """
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_a_hostname_with_ordinary_punctuation_still_converts():
    """The fix must not become a blanket ban -- real PF Sense hostnames can
    contain dots and hyphens (e.g. "fw-01.branch.example"), and that must
    keep working."""
    xml_text = _minimal_xml(hostname="fw-01.branch-office")
    output = _convert_string(xml_text)
    assert "hostname fw-01.branch-office" in output


# --- write_snapshot() -------------------------------------------------------------
# No test exercised write_snapshot() at all before this -- only convert() was
# covered. Added alongside the fix for the path-traversal bug it had (below),
# since a function with zero tests is also how that bug went unnoticed.


def _write_temp_xml(xml_text: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(xml_text)
        return Path(f.name)


def test_write_snapshot_writes_inside_the_configs_subdirectory():
    xml_path = _write_temp_xml(_minimal_xml(hostname="rtr-normal"))
    with tempfile.TemporaryDirectory() as snapshot_dir:
        try:
            out_path = write_snapshot(xml_path, snapshot_dir)
            expected_dir = (Path(snapshot_dir) / "configs").resolve()
            assert out_path.resolve().parent == expected_dir
            assert out_path.name == "rtr-normal.cfg"
            assert out_path.read_text().startswith("hostname rtr-normal")
        finally:
            xml_path.unlink()


def test_write_snapshot_refuses_a_path_traversal_hostname():
    """Confirmed live before this fix: this exact hostname wrote a file four
    directories above the intended snapshot_dir, entirely outside it."""
    xml_path = _write_temp_xml(_minimal_xml(hostname="../../../../evil"))
    with tempfile.TemporaryDirectory() as snapshot_dir:
        try:
            with pytest.raises(PfSenseConversionError):
                write_snapshot(xml_path, snapshot_dir)
            # Confirm nothing was written anywhere outside the snapshot dir,
            # not just that an exception happened to be raised.
            escaped = Path(snapshot_dir).parent.parent.parent.parent / "evil.cfg"
            assert not escaped.exists()
        finally:
            xml_path.unlink()
