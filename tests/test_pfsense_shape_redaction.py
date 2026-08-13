"""The shape tool must never print a value (constraint 1).

WHY THIS FILE EXISTS
    `tools/pfsense_shape.py` says in its own docstring:

        "It NEVER prints a value. No hostnames, no addresses, no descriptions,
         no interface names."

    That guarantee has now been broken twice by the same mistake -- printing
    something before checking it against a known vocabulary:

    1. @patelankeet2 caught it on #74: `type` and `protocol` were printed
       verbatim and annotated afterwards, so a crafted value appeared directly
       above the tool's own closing line claiming nothing had.
    2. Adding the interface-addressing section repeated it. A rule's
       `<interface>` is element CONTENT, not a tag name, so role names went
       straight to stdout. Real PF Sense roles like `wan` are the product's own
       vocabulary and safe -- but an interface GROUP or a renamed interface is
       user-chosen text and could be anything.

    Twice is a pattern, and the guarantee was only ever enforced by whoever
    wrote the print statement remembering. Now it is enforced here.

These need neither Batfish nor Docker.
"""

from __future__ import annotations

import pytest

from tools.pfsense_shape import DYNAMIC_ADDRESSING, KNOWN_ROLES, _safe_role

REDACTED = "<role outside PF Sense vocabulary, redacted>"


@pytest.mark.parametrize("role", sorted(KNOWN_ROLES) + ["opt1", "opt2", "opt12"])
def test_pf_sense_vocabulary_is_printed(role):
    """Redacting everything would be safe and useless -- the tool exists to say
    which constructs are involved."""
    assert _safe_role(role) == role


@pytest.mark.parametrize("role", ["WAN", "Lan", "OpenVPN", "WireGuard", "OPT1"])
def test_vocabulary_matching_is_case_insensitive(role):
    """PF Sense's own capitalisation varies -- `WireGuard` is how the package
    names itself. Case must not push a reserved word into redaction."""
    assert _safe_role(role) == role


@pytest.mark.parametrize(
    "role",
    [
        "GuestNet_Finance",      # an interface group someone named
        "10.0.0.1",              # an address in the wrong field
        "corp.internal.local",   # a hostname
        "opt",                   # nearly optN, but not
        "optX",
        "wan1",                  # nearly wan, but not
        "",
    ],
)
def test_anything_outside_the_vocabulary_is_redacted(role):
    assert _safe_role(role) == REDACTED, (
        f"{role!r} was printed. This tool's docstring promises it never prints "
        "a value, and an interface role is element content, not a tag name."
    )


def test_the_redaction_marker_leaks_nothing_of_the_input():
    """A marker that echoed the value would defeat the point."""
    secret = "finance-vlan-192.168.44.0"

    assert secret not in _safe_role(secret)
    assert _safe_role(secret) == REDACTED


def test_dynamic_addressing_keywords_are_the_products_own_words():
    """These are printed verbatim by the addressing section, so they must be
    keywords rather than anything a user could choose."""
    assert "dhcp" in DYNAMIC_ADDRESSING
    # No entry may look like an address -- if one did, printing it verbatim
    # would leak on a config that used it.
    for keyword in DYNAMIC_ADDRESSING:
        assert not any(ch.isdigit() and "." in keyword for ch in keyword), keyword
        assert "." not in keyword, f"{keyword!r} looks like an address, not a keyword"


def test_the_tool_runs_on_the_committed_fixture_without_printing_an_address(capsys):
    """End to end, against the fixture we control.

    Weaker than it sounds -- it cannot prove the guarantee for all inputs --
    so it checks the specific thing the fixture contains: a real static
    address that must not appear.
    """
    from tools.pfsense_shape import main

    main("tests/fixtures/pfsense-source/config.xml")
    out = capsys.readouterr().out

    assert "10.10.10.1" not in out, "a static interface address was printed"
    assert "203.0.113.1" not in out, "a static interface address was printed"
    assert "redacted" in out, "the fixture has static addresses; none were redacted"
