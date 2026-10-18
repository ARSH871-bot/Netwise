"""A-3's optional `subject` on a finding (#238, first step).

WHAT THESE PIN
    `make_finding()` accepts `subject` and validates it, and does NOTHING else.
    No check populates it in this change -- A-3 says an optional field nobody
    populates is inert, and the chaining that consumes it (#238) comes next.

    The properties most likely to be broken later:
      * ABSENT IS ABSENT. A finding built without `subject` has exactly the
        seven F-1 keys it always had, never `"subject": None`.
      * ONE SPELLING PER VALUE. Keys are a closed set, protocols a closed set,
        addresses stored canonically -- because two findings about the same
        traffic that spell it differently fail to join, silently. That is the
        failure A-3 removed from regex parsing, and it must not come back
        through a typo or a mask length.
"""

import ast
import ipaddress
from pathlib import Path

import pytest

from analysis import findings

REPO = Path(__file__).resolve().parents[1]
BASE = dict(check="policy_compliance", severity="high", device="rtr-us5",
            summary="s", detail="d", source="x", status="found", number=1)
F1_KEYS = {"id", "check", "severity", "device", "summary", "evidence", "status"}


def subject_of(subject):
    return findings.make_finding(**BASE, subject=subject)["subject"]


# --- absent is absent ---------------------------------------------------------

def test_a_finding_without_subject_is_unchanged():
    f = findings.make_finding(**BASE)
    assert set(f) == F1_KEYS
    assert "subject" not in f, "absent must be no key, not subject=None"


def test_an_explicit_none_is_also_absent():
    assert "subject" not in findings.make_finding(**BASE, subject=None)


def test_the_sentinel_helpers_still_produce_the_plain_shape():
    """A sentinel is about a check, not a flow, so it never carries subject."""
    assert set(findings.no_issues_finding(check="policy_compliance", device="r",
                                          summary="s", detail="d", source="x")) == F1_KEYS
    assert set(findings.error_finding(check="policy_compliance", device="r",
                                      summary="s", detail="d", source="x")) == F1_KEYS


# --- every key, accepted ------------------------------------------------------

def test_all_five_keys_are_carried():
    assert subject_of({"src": "10.10.10.0/24", "dst": "10.20.0.5", "srcPort": 49152,
                       "dstPort": 443, "protocol": "tcp"}) == {
        "src": "10.10.10.0/24", "dst": "10.20.0.5/32", "srcPort": 49152,
        "dstPort": 443, "protocol": "tcp"}


@pytest.mark.parametrize("key", ["src", "dst"])
def test_each_address_key_is_validated(key):
    assert subject_of({key: "10.20.0.5"}) == {key: "10.20.0.5/32"}
    with pytest.raises(ValueError):
        subject_of({key: "not-an-address"})


@pytest.mark.parametrize("key", ["srcPort", "dstPort"])
@pytest.mark.parametrize("port", [0, 65535])
def test_the_port_range_ends_are_accepted(key, port):
    assert subject_of({key: port}) == {key: port}


@pytest.mark.parametrize("key", ["srcPort", "dstPort"])
@pytest.mark.parametrize("port", [-1, 65536, "443", True])
def test_out_of_range_and_non_integer_ports_are_refused(key, port):
    with pytest.raises(ValueError):
        subject_of({key: port})


def test_subject_does_not_replace_the_evidence_sentence():
    f = findings.make_finding(**BASE, subject={"dst": "10.20.0.5"})
    assert f["evidence"] == {"detail": "d", "source": "x"}


# --- one spelling per value ---------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("10.20.0.5", "10.20.0.5/32"),
    ("2001:DB8::1", "2001:db8::1"),
    (ipaddress.ip_address("10.20.0.5"), "10.20.0.5"),
])
def test_two_spellings_of_one_address_are_stored_identically(a, b):
    """They must join. Stored as strings, so an `ipaddress` object is too."""
    assert subject_of({"dst": a}) == subject_of({"dst": b})
    assert isinstance(subject_of({"dst": a})["dst"], str)


def test_host_bits_below_the_prefix_are_refused_not_masked():
    with pytest.raises(ValueError):
        subject_of({"dst": "10.20.0.1/16"})


@pytest.mark.parametrize("value,canonical", [
    ("tcp", "tcp"), (" TCP ", "tcp"), ("6", "tcp"), (6, "tcp"),
    ("udp", "udp"), ("17", "udp"), ("icmp", "icmp"), (1, "icmp"),
])
def test_protocol_names_and_numbers_map_to_one_name(value, canonical):
    assert subject_of({"protocol": value}) == {"protocol": canonical}


@pytest.mark.parametrize("value", ["!tcp", "any", "banana", "", True])
def test_protocols_outside_the_closed_set_are_refused(value):
    """`!tcp` is policy_compliance's own syntax for NOT tcp -- the opposite."""
    with pytest.raises(ValueError):
        subject_of({"protocol": value})


# --- malformed subjects --------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"dest": "10.20.0.5"},        # unknown key
    {},                           # empty
    "10.20.0.5",                  # not a dict
    ["dst"],                      # not a dict -- and NOT caught by the key check
])
def test_a_malformed_subject_fails_loudly(bad):
    with pytest.raises(ValueError):
        findings.make_finding(**BASE, subject=bad)


# --- tripwire: nothing produces it yet ----------------------------------------

def _subject_writers(path):
    """Calls passing `subject=` and assignments to `x["subject"]`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "subject":
            yield node.lineno if hasattr(node, "lineno") else 0
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "subject"):
                    yield node.lineno


def test_no_product_code_populates_subject_yet():
    """A-3's order: the field first, a consumer next (#238). If this fails,
    something started emitting `subject` -- land it in the same change that
    adds the consumer, so the field is never half-used.

    Anchored on this file, not the working directory, and it asserts it
    actually scanned something: a relative path from the wrong directory made
    the first version pass while scanning nothing.
    """
    files = [p for d in ("analysis", "web", "ai") for p in (REPO / d).rglob("*.py")
             if p.name != "findings.py"]
    assert len(files) > 20, f"the tripwire scanned only {len(files)} files"
    writers = {str(p.relative_to(REPO)): lines for p in files
               if (lines := list(_subject_writers(p)))}
    assert writers == {}, writers


def test_the_tripwire_catches_both_shapes(tmp_path):
    """Proves the detector, so the test above cannot pass by being blind."""
    planted = tmp_path / "x.py"
    planted.write_text('make_finding(subject={"dst": "1.1.1.1"})\nf["subject"] = {}\n')
    assert len(list(_subject_writers(planted))) == 2
