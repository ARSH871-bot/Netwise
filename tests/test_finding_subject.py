"""A-3's optional `subject` on a finding (#238, first step).

WHAT THESE PIN
    `make_finding()` accepts `subject` and validates it, and does NOTHING else.
    No check populates it in this change -- A-3 says an optional field nobody
    populates is inert, and the chaining that consumes it (#238) comes next.

    The two properties most likely to be broken later:
      * ABSENT IS ABSENT. A finding built without `subject` has exactly the
        seven F-1 keys it always had, never `"subject": None`.
      * THE KEY SET IS CLOSED. A misspelt key would make two findings about
        the same address fail to join, silently -- the failure A-3 was raised
        to remove from regex parsing, returning through a typo.
"""

import pytest

from analysis import findings

BASE = dict(check="policy_compliance", severity="high", device="rtr-us5",
            summary="s", detail="d", source="x", status="found", number=1)
F1_KEYS = {"id", "check", "severity", "device", "summary", "evidence", "status"}


def test_a_finding_without_subject_is_unchanged():
    f = findings.make_finding(**BASE)
    assert set(f) == F1_KEYS
    assert "subject" not in f, "absent must be no key, not subject=None"


def test_a_finding_with_subject_carries_it():
    f = findings.make_finding(**BASE, subject={"dst": "10.20.0.5", "dstPort": 443, "protocol": "tcp"})
    assert set(f) == F1_KEYS | {"subject"}
    assert f["subject"] == {"dst": "10.20.0.5", "dstPort": 443, "protocol": "tcp"}


def test_every_key_inside_subject_is_optional():
    f = findings.make_finding(**BASE, subject={"dst": "10.20.0.0/16"})
    assert f["subject"] == {"dst": "10.20.0.0/16"}


def test_subject_does_not_replace_the_evidence_sentence():
    f = findings.make_finding(**BASE, subject={"dst": "10.20.0.5"})
    assert f["evidence"] == {"detail": "d", "source": "x"}


def test_protocol_is_normalised_so_tcp_and_TCP_join():
    f = findings.make_finding(**BASE, subject={"protocol": " TCP "})
    assert f["subject"]["protocol"] == "tcp"


@pytest.mark.parametrize("bad,why", [
    ({"dest": "10.20.0.5"}, "unknown key"),
    ({}, "empty"),
    ("10.20.0.5", "not a dict"),
    ({"dst": "not-an-address"}, "bad address"),
    ({"dstPort": 70000}, "port out of range"),
    ({"dstPort": "443"}, "port as string"),
    ({"dstPort": True}, "bool is not a port"),
    ({"protocol": ""}, "empty protocol"),
])
def test_a_malformed_subject_fails_loudly(bad, why):
    with pytest.raises(ValueError):
        findings.make_finding(**BASE, subject=bad)


def test_the_sentinel_helpers_still_produce_the_plain_shape():
    """A sentinel is about a check, not a flow, so it never carries subject."""
    assert set(findings.no_issues_finding(check="policy_compliance", device="r",
                                          summary="s", detail="d", source="x")) == F1_KEYS
    assert set(findings.error_finding(check="policy_compliance", device="r",
                                      summary="s", detail="d", source="x")) == F1_KEYS


def test_no_check_populates_subject_yet():
    """A-3's order: the field first, a consumer next (#238). If this fails,
    a check started emitting `subject` -- update it in the same change that
    adds the consumer, so the field is never half-used."""
    import pathlib
    producers = [p for p in pathlib.Path("analysis").rglob("*.py")
                 if p.name != "findings.py" and "subject=" in p.read_text(encoding="utf-8")]
    assert producers == [], producers
