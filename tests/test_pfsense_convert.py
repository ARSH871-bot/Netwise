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


# A benign, single rule on "lan" -- these two tests are about interface
# emission, not filtering, but convert() now refuses an empty rule set
# entirely (see the "Free-text fields..." / F6/F7 section below), so each
# needs at least one rule naming a real interface to exercise what it is
# actually testing.
_ONE_BENIGN_LAN_RULE = """
    <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
    <source><any/></source><destination><any/></destination></rule>
"""


def test_wan_and_lan_get_different_synthetic_interface_names():
    xml_text = _minimal_xml(
        interfaces_xml="""
        <wan><if>em0</if><ipaddr>1.2.3.1</ipaddr><subnet>30</subnet></wan>
        <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    """,
        rules_xml=_ONE_BENIGN_LAN_RULE,
    )
    output = _convert_string(xml_text)
    assert "interface GigabitEthernet0/0" in output
    assert "interface GigabitEthernet0/1" in output


def test_interface_without_a_static_address_is_skipped_not_guessed():
    """A DHCP-assigned interface has no <ipaddr>/<subnet> to convert. Skipping
    it is correct; inventing an address would not be."""
    xml_text = _minimal_xml(
        interfaces_xml="""
        <wan><if>em0</if></wan>
        <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
    """,
        rules_xml=_ONE_BENIGN_LAN_RULE,
    )
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


# --- Multi-interface rule sets (#78 item 1) -------------------------------------

_TWO_INTERFACES = """
    <wan><if>em0</if><ipaddr>1.2.3.1</ipaddr><subnet>30</subnet></wan>
    <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>
"""


def test_rules_on_two_different_interfaces_each_get_their_own_acl():
    """The client's real export needs this -- rules across several
    interfaces, each converting to its own ACL rather than being merged or
    refused."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>block</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    output = _convert_string(xml_text)
    assert "ip access-list extended acl_lan_in" in output
    assert "ip access-list extended acl_wan_in" in output
    assert "ip access-group acl_lan_in in" in output
    assert "ip access-group acl_wan_in in" in output
    # Each ACL carries only its own interface's rule, not the other's.
    lan_block = output.split("ip access-list extended acl_lan_in")[1].split("!")[0]
    wan_block = output.split("ip access-list extended acl_wan_in")[1].split("!")[0]
    assert "permit tcp any any" in lan_block
    assert "deny tcp any any" in wan_block
    assert "deny tcp any any" not in lan_block
    assert "permit tcp any any" not in wan_block


def test_a_single_interface_with_rules_still_uses_the_plain_acl_name():
    """The common case, and the only one hand-verified against
    tests/fixtures/rtr-us5-secure, must convert identically to before #78:
    no role suffix nobody asked for."""
    output = _convert_string(_minimal_xml(rules_xml=_ONE_BENIGN_LAN_RULE))
    assert "ip access-list extended acl_in" in output
    assert "ip access-list extended acl_lan_in" not in output


def test_an_interface_with_an_address_but_no_rules_gets_a_deny_all():
    """PF Sense fails CLOSED with no rules configured on an interface. Left
    unbound, Cisco/Batfish would read that interface as unfiltered -- the
    exact inversion the empty-<filter> refusal already exists to prevent for
    the whole file, reachable here per-interface instead."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    output = _convert_string(xml_text)
    assert "ip access-group acl_wan_in in" in output
    wan_block = output.split("ip access-list extended acl_wan_in")[1].split("!")[0]
    assert "deny ip any any" in wan_block


def test_a_pair_that_would_be_ambiguous_on_one_acl_is_fine_on_two():
    """The false positive this scoping exists to prevent. A block on wan
    followed by an unrelated, broader, non-quick permit on lan is exactly
    the shape #47/#58 flags WITHIN one ACL -- different actions, the earlier
    one not quick, overlapping traffic. Compared globally this pair would
    wrongly refuse a config with nothing wrong in it, because a rule on wan
    and a rule on lan are never evaluated against the same traffic by any
    real firewall."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>block</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    output = _convert_string(xml_text)
    assert "permit tcp any any" in output
    assert "deny tcp any any" in output


def test_a_pair_with_no_quick_rules_now_converts_via_reversal_instead_of_refusing():
    """Superseded by #78 item 2, not merely renamed. This exact pair -- wan's
    own block-then-pass, neither quick -- used to be refused, before this
    module could tell the two evaluation models apart with confidence. Now
    it does not need to: with no quick rule anywhere in wan's list, the
    final decision for any flow is simply the LAST matching rule, which is
    exactly what evaluating the SAME rules reversed, first-match-wins,
    produces. Nothing is left ambiguous, so it converts, correctly, rather
    than being refused."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>block</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    output = _convert_string(xml_text)
    wan_block = output.split("ip access-list extended acl_wan_in")[1].split("!")[0]
    # The later rule (pass) is the real last-match-wins winner, so it comes
    # FIRST in the reversed, first-match-wins ACL.
    assert wan_block.strip().splitlines()[0].strip() == "permit tcp any any"


def test_a_genuinely_mixed_quick_pair_still_raises():
    """The case reversal does NOT resolve: one rule quick, one not, in a
    pattern that first-match-wins and last-match-wins can still disagree
    about. This is the scope #78 item 2 deliberately leaves refused rather
    than guessed -- see the module docstring."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>block</type><interface>wan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol><quick/>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_a_rule_naming_no_interface_alongside_others_that_do_raises():
    """Ambiguous under multi-interface in a way it never was under
    single-interface: which ACL would an interface-less rule join, when more
    than one now exists? Refuse rather than guess."""
    xml_text = _minimal_xml(
        interfaces_xml=_TWO_INTERFACES,
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>block</type><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_a_whitespace_only_interface_gets_the_right_refusal_message():
    """Found by adversarial QA on #78 item 2, not anticipated up front.

    <interface> </interface> -- present, but blank once stripped -- used to
    read as "" rather than None, so it slipped past the unassigned-rule
    refusal above and was instead reported as an unknown interface role,
    blaming "no static address configured" for what was actually a
    malformed tag. Still refused either way (fail-closed, never a bypass),
    but the wrong diagnosis, which matters when someone is actually trying
    to debug a real client export."""
    xml_text = _minimal_xml(
        rules_xml="""
            <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
            <rule><type>block</type><interface> </interface><protocol>tcp</protocol>
            <source><any/></source><destination><any/></destination></rule>
        """,
    )
    with pytest.raises(PfSenseConversionError) as excinfo:
        _convert_string(xml_text)
    message = str(excinfo.value)
    assert "no <interface>" in message, (
        "a blank <interface> tag must be diagnosed as naming no interface, "
        f"not as an unknown one. Got: {message!r}"
    )
    assert "static address" not in message, (
        f"wrong diagnosis -- this is a malformed tag, not a missing address. Got: {message!r}"
    )


# --- Rule order is preserved -----------------------------------------------------


def test_rules_are_emitted_in_document_order():
    """Cisco ACLs are first-match-wins, so order is meaning, not just
    style -- a converter that reordered rules would change the policy.

    The deny is marked quick: these two rules' traffic overlaps (the
    permit is a catch-all), and without quick on the earlier, more
    specific rule, issue #47's rule-order check correctly refuses this
    pair as ambiguous -- see test_a_specific_deny_before_a_broader_permit_
    without_quick_raises below. This test is about output ORDER, not about
    #47, so it uses input the new check accepts, same reasoning as the
    other tests updated when #45/#50's device-scoping check landed."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <quick/>
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
# --- Rule order ambiguity (issue #47) -----------------------------------------
# PF Sense evaluates last-match-wins unless a rule is "quick"; this module
# converts as first-match-wins, exactly like a Cisco ACL. The two models agree
# whenever the earlier of two overlapping rules is quick (both stop there), or
# whenever the two rules have the same action (it does not matter which one
# "wins"). They can disagree otherwise -- demonstrated live in issue #47's own
# probe, a deny-then-permit pair on the same host, neither quick, which
# converted cleanly and reported the permit as "unreachable" while the real
# firewall, evaluating last-match, would have let that exact traffic through.


def test_a_specific_deny_before_a_broader_permit_without_quick_raises():
    """Issue #47's own probe, reproduced here as a regression test. Neither
    rule is quick, their actions differ (deny vs permit), and their traffic
    overlaps (the permit is a subset of what the deny already covers) --
    exactly the condition PF Sense and this converter can disagree about."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address></destination></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address><port>443</port></destination></rule>
    """)
# --- Refuse rather than silently invert or drop the source firewall's policy -----
# Regression coverage for three findings from a senior-level adversarial QA pass,
# all in convert()'s interface/ACL-binding logic and _parse_interfaces().


def test_no_filter_rules_at_all_raises():
    """PF Sense fails closed with no rules (blocks everything); Cisco fails
    open with no ACL bound (permits everything). Converting zero rules into
    zero rules would silently invert the source firewall's actual security
    posture -- confirmed live before this fix: this exact input converted
    to an interface with no ACL and no access-group line at all."""
    xml_text = _minimal_xml(rules_xml="")
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
    # Needs a rule for the same reason the two interface-emission tests above
    # do: convert() now refuses an empty rule set (#54). This test is about
    # hostname punctuation, not about filtering.
    xml_text = _minimal_xml(
        hostname="fw-01.branch-office", rules_xml=_ONE_BENIGN_LAN_RULE
    )
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
    # Same as above: a benign rule so convert() has something to bind an ACL
    # to. This test is about WHERE the file lands, not about its rules.
    xml_path = _write_temp_xml(
        _minimal_xml(hostname="rtr-normal", rules_xml=_ONE_BENIGN_LAN_RULE)
    )
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
def test_the_same_pair_converts_once_the_earlier_rule_is_quick():
    """The earlier rule stops evaluation the instant it matches, in both
    models -- Cisco's first-match and PF Sense's quick mean the same thing
    here, so this specific pair becomes unambiguous regardless of whether
    the later rule is quick too."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <quick/>
        <source><any/></source><destination><address>10.20.0.5</address></destination></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address><port>443</port></destination></rule>
    """)
    output = _convert_string(xml_text)
    assert "deny tcp any host 10.20.0.5" in output
    assert "permit tcp any host 10.20.0.5 eq 443" in output


def test_marking_only_the_later_rule_quick_still_raises():
    """The LATER rule's quick flag never makes a pair safe on its own --
    PF Sense has already evaluated the earlier, non-quick rule and kept
    going before it ever reaches the later one, so the two models can
    still disagree about which action the earlier rule's own match space
    resolves to."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address></destination></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <quick/>
        <source><any/></source><destination><address>10.20.0.5</address><port>443</port></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_overlapping_rules_with_the_same_action_never_raise():
    """If both rules would produce the same outcome, it does not matter
    which model "wins" -- there is nothing to disagree about even though
    the two rules' traffic genuinely overlaps and neither is quick."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address><port>22</port></destination></rule>
        <rule><type>block</type><interface>lan</interface><protocol>any</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    output = _convert_string(xml_text)
    assert "deny tcp any host 10.20.0.5 eq 22" in output
    assert "deny ip any any" in output


def test_disjoint_rules_never_raise_regardless_of_quick():
    """Two rules that genuinely never match the same traffic cannot
    disagree about it, quick or not -- the check is about overlap, not
    about quick in isolation."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol>
        <source><any/></source><destination><address>10.20.0.5</address><port>443</port></destination></rule>
        <rule><type>pass</type><interface>lan</interface><protocol>udp</protocol>
        <source><any/></source><destination><address>10.20.0.6</address><port>53</port></destination></rule>
    """)
    output = _convert_string(xml_text)
    assert "permit tcp any host 10.20.0.5 eq 443" in output
    assert "permit udp any host 10.20.0.6 eq 53" in output


def test_a_single_rule_never_raises():
    """No pair exists with only one rule -- the check must not misfire on
    the trivial case."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><interface>lan</interface><protocol>any</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    assert "deny ip any any" in _convert_string(xml_text)


def test_the_real_fixture_without_quick_now_converts_correctly_instead_of_refusing():
    """Regression coverage for the gap #58 found in the fixture itself, now
    re-checked against #78 item 2's more capable behaviour. The real
    fixture's two pass rules are followed by a catch-all deny, which by
    definition overlaps both of them; before #58 added <quick/> to the two
    pass rules, this exact fixture converted successfully and produced a
    config that was backwards under real PF Sense semantics.

    #58's fix made that refuse. #78 item 2 goes one step further: with NO
    quick rules anywhere (the fixture minus its two <quick/> tags), the
    result is no longer ambiguous, it is exactly determined -- last-match-
    wins means the trailing catch-all deny genuinely does override both
    permits on the real firewall, so the correct conversion DENIES DNS and
    HTTPS, not refuses to say. Confirmed live against Batfish before writing
    this assertion: both testFilters calls returned DENY, and
    filterLineReachability reported both permit lines as dead, correctly
    reflecting that they never take effect once the deny is evaluated last."""
    original = Path(FIXTURE).read_text()
    without_quick = original.replace("<quick/>\n      ", "")
    assert without_quick != original, "the fixture must actually contain <quick/> for this test to mean anything"

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as f:
        f.write(without_quick)
        path = Path(f.name)
    try:
        output = convert(path)
    finally:
        path.unlink()

    # The catch-all deny is now first (last original rule, reversed), so it
    # decides for every flow, including the two the permits were written for.
    acl_block = output.split("ip access-list extended acl_in")[1]
    lines = [ln.strip() for ln in acl_block.strip().splitlines() if ln.strip() and ln.strip() != "!"]
    assert lines[0] == "deny ip any any", (
        "the trailing catch-all deny must be evaluated first once nothing "
        f"is quick, real PF Sense semantics say it overrides both permits. Got: {lines}"
    )


def test_a_rule_with_no_interface_raises_rather_than_producing_an_unbound_acl():
    """Confirmed live before this fix: acl_role defaulted to None, so
    "ip access-group ACL_NAME in" was never written to any interface, but
    the ACL's own permit/deny lines WERE still emitted -- a filter that
    looks present in the file and enforces nothing."""
    xml_text = _minimal_xml(rules_xml="""
        <rule><type>block</type><protocol>tcp</protocol>
        <source><any/></source><destination><any/></destination></rule>
    """)
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_negative_subnet_raises_pfsense_conversion_error_not_a_raw_ipaddress_error():
    xml_text = _minimal_xml(
        interfaces_xml="""
        <lan><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>-1</subnet></lan>
        """,
        rules_xml=_ONE_BENIGN_LAN_RULE,
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)


def test_ipv6_shaped_ipaddr_raises_pfsense_conversion_error_not_a_raw_ipaddress_error():
    """Same class of gap PR #34 already fixed once for <address>/<port>
    inside filter rules, recurring one layer up for interface addressing."""
    xml_text = _minimal_xml(
        interfaces_xml="""
        <lan><if>em1</if><ipaddr>2001:db8::1</ipaddr><subnet>24</subnet></lan>
        """,
        rules_xml=_ONE_BENIGN_LAN_RULE,
    )
    with pytest.raises(PfSenseConversionError):
        _convert_string(xml_text)
