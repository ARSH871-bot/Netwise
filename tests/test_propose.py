"""
Netwise -- tests for ai/propose.py, config-change proposal and simulation
(US-13, US-14).

WHY THIS FILE EXISTS
    ai/propose.py's module docstring explains the shape: a closed template
    parsed with regular expressions (no model, no guessing), resolved
    against a real snapshot, applied only to a throwaway copy of it, and
    judged safe or not by re-running the diff analysis/change_impact.py
    already trusts. Two halves, tested two ways:

      - the parsing and text-editing helpers are pure functions over
        strings, tested directly here, no Batfish needed -- the same way
        tests/test_query_translation.py tests ai/query.py's equivalents;
      - propose_change() itself is tested with Batfish and
        change_impact.analyse_change() both stubbed, the same pattern
        tests/test_change_impact.py already uses for analyse_change() --
        real files on disk (via tmp_path), fake Batfish underneath.

RUN
    pytest tests/ -v
"""

from pathlib import Path

import pytest

from ai import propose

# --- A minimal, realistic single-ACL device config, matching the shape ------
# --- tests/fixtures/rtr-us5-secure/configs/rtr-us5.cfg already uses. -------

_RTR_CFG = """!
hostname rtr-us5
!
interface GigabitEthernet0/0
 ip address 10.10.10.1 255.255.255.0
 ip access-group acl_in in
!
ip access-list extended acl_in
 permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain
 permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 eq 443
 deny   ip any any
!
"""


def _write_snapshot(tmp_path: Path, filename: str = "rtr-us5.cfg", text: str = _RTR_CFG) -> Path:
    snapshot_dir = tmp_path / "snap"
    configs_dir = snapshot_dir / "configs"
    configs_dir.mkdir(parents=True)
    (configs_dir / filename).write_text(text, encoding="utf-8")
    return snapshot_dir


# =============================================================================
# 1. Pure parsing and text-editing helpers -- no Batfish
# =============================================================================


@pytest.mark.parametrize("word", ["block", "Block", "deny", "DENY", "stop"])
def test_find_action_recognises_every_deny_word(word):
    result = propose._find_action(f"{word} 10.0.0.1 to 10.0.0.2 on tcp/80")
    assert result is not None
    action, _ = result
    assert action == "deny"


@pytest.mark.parametrize("word", ["allow", "Allow", "permit", "PERMIT", "let"])
def test_find_action_recognises_every_permit_word(word):
    result = propose._find_action(f"{word} 10.0.0.1 to 10.0.0.2 on tcp/80")
    assert result is not None
    action, _ = result
    assert action == "permit"


def test_find_action_returns_none_when_absent():
    assert propose._find_action("10.0.0.1 to 10.0.0.2 on tcp/80") is None


def test_find_action_remainder_starts_after_the_matched_word():
    _, remainder = propose._find_action("block 10.0.0.1 to 10.0.0.2")
    assert "block" not in remainder.lower()
    assert "10.0.0.1" in remainder


def test_split_source_destination_splits_on_standalone_to():
    split = propose._split_source_destination(" 10.0.0.1 to 10.0.0.2 on tcp/80")
    assert split is not None
    source, destination = split
    assert "10.0.0.1" in source
    assert "10.0.0.2" in destination


def test_split_source_destination_none_without_to():
    assert propose._split_source_destination(" 10.0.0.1 10.0.0.2") is None


def test_split_source_destination_does_not_match_to_inside_a_word():
    """"stockholm" contains "to" but not as a whole word -- must not split
    there."""
    assert propose._split_source_destination(" stockholm 10.0.0.2") is None


def test_find_endpoint_recognises_a_single_ip():
    assert propose._find_endpoint(" 10.10.10.5 ") == "10.10.10.5"


def test_find_endpoint_recognises_a_cidr():
    assert propose._find_endpoint(" 10.10.10.0/24 ") == "10.10.10.0/24"


def test_find_endpoint_recognises_any():
    assert propose._find_endpoint(" any ") == "any"


def test_find_endpoint_none_for_a_service_name():
    """The whole point of shape A: "YouTube" is not an address, and must
    not be silently guessed at."""
    assert propose._find_endpoint(" YouTube ") is None


def test_find_endpoint_rejects_an_ip_shaped_but_invalid_address():
    """"999.1.1.1" matches the regex shape but is not a real address --
    the second, semantic check must catch it."""
    assert propose._find_endpoint(" 999.1.1.1 ") is None


@pytest.mark.parametrize(
    "text, expected_protocol, expected_port",
    [
        ("on tcp/443", "tcp", 443),
        ("on tcp port 443", "tcp", 443),
        ("on udp/53", "udp", 53),
        ("on tcp", "tcp", None),
        ("on icmp", "icmp", None),
        ("on any", "ip", None),
        ("on ip", "ip", None),
    ],
)
def test_find_protocol_and_port(text, expected_protocol, expected_port):
    result = propose._find_protocol_and_port(text)
    assert result == (expected_protocol, expected_port)


def test_find_protocol_and_port_none_when_absent():
    assert propose._find_protocol_and_port("block 10.0.0.1 to 10.0.0.2") is None


def test_find_protocol_and_port_rejects_a_port_above_the_valid_range():
    assert propose._find_protocol_and_port("on tcp/99999") is None


def test_cisco_endpoint_any_stays_any():
    assert propose._cisco_endpoint("any") == "any"


def test_cisco_endpoint_single_address_becomes_host():
    assert propose._cisco_endpoint("10.20.0.5") == "host 10.20.0.5"


def test_cisco_endpoint_network_becomes_address_and_wildcard():
    assert propose._cisco_endpoint("10.10.10.0/24") == "10.10.10.0 0.0.0.255"


def test_bound_inbound_acls_finds_the_one_acl():
    assert propose._bound_inbound_acls(_RTR_CFG) == ["acl_in"]


def test_bound_inbound_acls_empty_when_none_bound():
    text = "!\nhostname rtr\n!\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n!\n"
    assert propose._bound_inbound_acls(text) == []


def test_bound_inbound_acls_dedupes_the_same_name_on_two_interfaces():
    """Not ambiguous: one shared filter, applying the new line to both
    interfaces identically is exactly what was asked."""
    text = (
        "interface Gi0/0\n ip access-group acl_in in\n!\n"
        "interface Gi0/1\n ip access-group acl_in in\n!\n"
    )
    assert propose._bound_inbound_acls(text) == ["acl_in"]


def test_bound_inbound_acls_lists_every_distinct_name():
    text = (
        "interface Gi0/0\n ip access-group acl_wan in\n!\n"
        "interface Gi0/1\n ip access-group acl_lan in\n!\n"
    )
    assert propose._bound_inbound_acls(text) == ["acl_lan", "acl_wan"]


def test_insert_rule_at_top_lands_before_existing_rules():
    result = propose._insert_rule_at_top(_RTR_CFG, "acl_in", "deny tcp host 1.1.1.1 host 2.2.2.2 eq 80")
    lines = result.splitlines()
    header_index = lines.index("ip access-list extended acl_in")
    assert lines[header_index + 1] == " deny tcp host 1.1.1.1 host 2.2.2.2 eq 80"
    # Nothing already there was lost or reordered.
    assert " permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain" in result
    assert " deny   ip any any" in result


def test_insert_rule_at_top_none_when_acl_not_found():
    assert propose._insert_rule_at_top(_RTR_CFG, "no_such_acl", "deny ip any any") is None


def test_device_config_path_matches_by_declared_hostname_not_filename(tmp_path):
    """The filename need not match the hostname -- the declared identity
    inside the file is what is trusted, same discipline
    analysis/checks/access_control.py already applies."""
    configs_dir = tmp_path / "configs"
    configs_dir.mkdir()
    (configs_dir / "whatever.cfg").write_text(_RTR_CFG, encoding="utf-8")

    found = propose._device_config_path(configs_dir, "rtr-us5")
    assert found == configs_dir / "whatever.cfg"


def test_device_config_path_none_for_an_unknown_device(tmp_path):
    configs_dir = tmp_path / "configs"
    configs_dir.mkdir()
    (configs_dir / "rtr-us5.cfg").write_text(_RTR_CFG, encoding="utf-8")
    assert propose._device_config_path(configs_dir, "rtr-does-not-exist") is None


def test_find_device_matches_whole_word_only():
    """Same \\b-boundary regex as ai/query.py's own _find_device(), and the
    same known imprecision: a hyphen counts as a boundary, so "rtr-us5"
    matches inside "office-rtr-us5-backup" too. Documented here rather than
    silently inherited -- see ai/query.py's own _find_device()."""
    assert propose._find_device("something unrelated entirely", {"rtr-us5"}) is None
    assert propose._find_device("on rtr-us5, block ...", {"rtr-us5"}) == "rtr-us5"


# =============================================================================
# 2. propose_change() -- Batfish and change_impact stubbed, real files on disk
# =============================================================================


def _stub_batfish(monkeypatch, *, devices=frozenset({"rtr-us5"}), parse_problems=None, load_raises=False):
    def fake_connect(host="localhost"):
        return object()

    def fake_load_snapshot(bf, config_dir, network_name, snapshot_name):
        if load_raises:
            raise RuntimeError("could not load")

    monkeypatch.setattr(propose, "connect", fake_connect)
    monkeypatch.setattr(propose, "load_snapshot", fake_load_snapshot)
    monkeypatch.setattr(propose, "find_parse_problems", lambda bf: list(parse_problems or []))
    monkeypatch.setattr(propose.snapshot, "device_names", lambda bf: devices)


def _stub_change_impact(monkeypatch, results):
    monkeypatch.setattr(
        propose.change_impact, "analyse_change",
        lambda before_dir, after_dir, host="localhost": results,
    )


GOOD_REQUEST = "block 10.10.10.5 to 10.20.0.5 on tcp/443 on rtr-us5"


def test_empty_request_is_refused():
    result = propose.propose_change("", "unused")
    assert result["grounded"] is False
    assert result["request_understood"] is None


def test_request_with_no_action_is_refused():
    result = propose.propose_change("10.10.10.5 to 10.20.0.5 on tcp/443", "unused")
    assert result["grounded"] is False
    assert "action" in result["answer"]


def test_request_with_no_to_keyword_is_refused():
    result = propose.propose_change("block 10.10.10.5 10.20.0.5 on tcp/443", "unused")
    assert result["grounded"] is False


def test_request_naming_a_service_instead_of_an_address_is_refused():
    """The headline scope limit: "block YouTube" must be refused, not
    guessed at."""
    result = propose.propose_change("block YouTube on tcp/443 on rtr-us5", "unused")
    assert result["grounded"] is False


def test_request_with_no_protocol_is_refused():
    result = propose.propose_change("block 10.10.10.5 to 10.20.0.5 on rtr-us5", "unused")
    assert result["grounded"] is False
    assert "protocol" in result["answer"]


def test_unreachable_batfish_is_refused(monkeypatch):
    def refuse(host="localhost"):
        raise ConnectionError("nothing is listening")

    monkeypatch.setattr(propose, "connect", refuse)
    result = propose.propose_change(GOOD_REQUEST, "unused")
    assert result["grounded"] is False
    assert "docker start batfish" in result["answer"]


def test_a_config_that_will_not_load_is_refused(monkeypatch):
    _stub_batfish(monkeypatch, load_raises=True)
    result = propose.propose_change(GOOD_REQUEST, "unused")
    assert result["grounded"] is False


def test_a_config_that_will_not_parse_is_refused(monkeypatch):
    _stub_batfish(monkeypatch, parse_problems=["rtr-us5.cfg (PARTIALLY_UNRECOGNIZED)"])
    result = propose.propose_change(GOOD_REQUEST, "unused")
    assert result["grounded"] is False


def test_devices_that_could_not_be_determined_is_refused(monkeypatch):
    _stub_batfish(monkeypatch, devices=None)
    result = propose.propose_change(GOOD_REQUEST, "unused")
    assert result["grounded"] is False


def test_a_device_not_in_the_snapshot_is_refused(monkeypatch):
    _stub_batfish(monkeypatch, devices=frozenset({"some-other-router"}))
    result = propose.propose_change(GOOD_REQUEST, "unused")
    assert result["grounded"] is False
    assert "known device" in result["answer"]


def test_a_device_with_multiple_distinct_acls_is_refused(monkeypatch, tmp_path):
    two_acl_cfg = (
        "!\nhostname rtr-us5\n!\n"
        "interface Gi0/0\n ip access-group acl_wan in\n!\n"
        "interface Gi0/1\n ip access-group acl_lan in\n!\n"
        "ip access-list extended acl_wan\n deny ip any any\n!\n"
        "ip access-list extended acl_lan\n deny ip any any\n!\n"
    )
    before_dir = _write_snapshot(tmp_path, text=two_acl_cfg)
    _stub_batfish(monkeypatch)

    result = propose.propose_change(GOOD_REQUEST, before_dir)
    assert result["grounded"] is False
    assert "acl_lan" in result["answer"] and "acl_wan" in result["answer"]


def _found(check="change_impact", severity="high", number=1):
    from analysis import findings
    return findings.make_finding(
        check=check, severity=severity, device="rtr-us5",
        summary="s", detail="d", source="s", status="found", number=number,
    )


def _none_finding():
    from analysis import findings
    return findings.no_issues_finding(
        check="change_impact", device="unknown", summary="No change",
        detail="d", source="s", number=0,
    )


def test_a_well_formed_request_that_opens_something_is_a_warning(monkeypatch, tmp_path):
    before_dir = _write_snapshot(tmp_path)
    _stub_batfish(monkeypatch)
    _stub_change_impact(monkeypatch, [_found(severity="high")])

    result = propose.propose_change(GOOD_REQUEST, before_dir)

    assert result["grounded"] is True
    assert result["verified"] is True
    assert result["warning"] is True
    assert result["proposed_change"] == {
        "device": "rtr-us5",
        "filter": "acl_in",
        "line": "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443",
    }
    assert "Warning" in result["answer"]


def test_a_well_formed_request_that_only_closes_something_is_not_a_warning(monkeypatch, tmp_path):
    before_dir = _write_snapshot(tmp_path)
    _stub_batfish(monkeypatch)
    _stub_change_impact(monkeypatch, [_found(severity="medium")])

    result = propose.propose_change(GOOD_REQUEST, before_dir)

    assert result["verified"] is True
    assert result["warning"] is False
    assert "narrows" in result["answer"]


def test_a_well_formed_request_with_no_detected_effect(monkeypatch, tmp_path):
    before_dir = _write_snapshot(tmp_path)
    _stub_batfish(monkeypatch)
    _stub_change_impact(monkeypatch, [_none_finding()])

    result = propose.propose_change(GOOD_REQUEST, before_dir)

    assert result["verified"] is True
    assert result["warning"] is False
    assert "no detected effect" in result["answer"]


def test_an_impact_that_could_not_be_verified_is_not_called_safe(monkeypatch, tmp_path):
    """F-4's discipline, applied here: an unverified simulation must never
    read the same as "checked and safe"."""
    from analysis import findings

    before_dir = _write_snapshot(tmp_path)
    _stub_batfish(monkeypatch)
    error_finding = findings.error_finding(
        check="change_impact", summary="could not compare", detail="d",
        source="s", number=50,
    )
    _stub_change_impact(monkeypatch, [error_finding])

    result = propose.propose_change(GOOD_REQUEST, before_dir)

    assert result["grounded"] is True
    assert result["verified"] is False
    assert result["warning"] is False
    assert "NOT a claim" in result["answer"]


def test_the_before_snapshot_is_never_written_to(monkeypatch, tmp_path):
    """CLAUDE.md's non-negotiable: generate and simulate only. The original
    config file must be byte-for-byte unchanged after a proposal."""
    before_dir = _write_snapshot(tmp_path)
    original_text = (before_dir / "configs" / "rtr-us5.cfg").read_text(encoding="utf-8")
    _stub_batfish(monkeypatch)
    _stub_change_impact(monkeypatch, [_none_finding()])

    propose.propose_change(GOOD_REQUEST, before_dir)

    assert (before_dir / "configs" / "rtr-us5.cfg").read_text(encoding="utf-8") == original_text


def test_request_understood_names_the_generated_line(monkeypatch, tmp_path):
    """Shape C, the same principle US-11 leans on: the person asking must
    be able to see exactly what was understood and generated."""
    before_dir = _write_snapshot(tmp_path)
    _stub_batfish(monkeypatch)
    _stub_change_impact(monkeypatch, [_none_finding()])

    result = propose.propose_change(GOOD_REQUEST, before_dir)

    assert result["request_understood"] == (
        "On rtr-us5, add to 'acl_in' (at the top): "
        "deny tcp host 10.10.10.5 host 10.20.0.5 eq 443"
    )
