"""How big is a change? (#420)"""
from analysis import change_impact, findings


def f(sev, status="found", n=1):
    if status == "error":
        return findings.error_finding(check="change_impact", summary="s", detail="d", source="x", number=50)
    return findings.make_finding(check="change_impact", severity=sev, device="r", summary="s",
                                 detail="d", source="x", status=status, number=n)


def test_opening_counts_more_than_closing():
    assert change_impact.score([f("high")])["score"] > change_impact.score([f("medium")])["score"]


def test_the_breakdown_explains_the_number():
    s = change_impact.score([f("high"), f("medium", n=2), f("low", n=3)])
    assert s["score"] == 6 and s["explanation"] == "1 high x3 + 1 medium x2 + 1 low x1 = 6"


def test_incomplete_never_scores_small():
    s = change_impact.score([f("low"), f(None, "error")])
    assert s["band"] == "incomplete" and s["complete"] is False
    assert "may be larger" in s["explanation"]


def test_no_change_is_zero_and_none():
    s = change_impact.score([f("low", "none", 0)])
    assert s["score"] == 0 and s["band"] == "none" and s["complete"]


def test_bands():
    assert change_impact.score([f("low")])["band"] == "small"
    assert change_impact.score([f("high"), f("high", n=2)])["band"] == "moderate"
    assert change_impact.score([f("high", n=i) for i in range(1, 5)])["band"] == "large"
