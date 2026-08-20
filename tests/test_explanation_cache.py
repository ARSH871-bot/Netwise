"""The explanation cache (#92) -- and the collision it must not create.

WHY THIS FILE EXISTS
    /api/findings called the model once per status="found" finding on every
    hit, and `loadFindings()` runs at script load in static/app.js, so every
    page load paid it again. Measured before the fix, counting calls to
    `ollama.generate` rather than timing them:

        hit 1: 5 found  ->  5 model calls
        hit 2: 5 found  ->  5 model calls
        hit 3: 5 found  ->  5 model calls

WHY EVERY TEST HERE COUNTS CALLS
    #92's first acceptance criterion is "repeated calls do not re-invoke the
    model". Timing it would be measuring the machine, not the behaviour --
    and on this project's own hardware that mistake was already made once:
    an apparent 2s-per-explanation cost turned out to be a Windows loopback
    refusal delay that every closed port shares, including ports nothing has
    ever listened on. A call count cannot be wrong that way.

WHY THE COLLISION TEST USES TWO REAL FIXTURE ID SETS
    #92 warned that keying on `id` would serve one network's explanation for
    another's finding. That is not hypothetical -- measured on our own
    fixtures:

        rtr-us5-insecure   ['AC-001', 'AC-002', 'PC-001', 'PC-002', 'PC-003']
        rtr-us5-messy      ['AC-004', 'AC-001', 'PC-004', 'PC-005', 'AC-002',
                            'AC-003']
        ids used by BOTH:  ['AC-001', 'AC-002']

    So the test below builds two findings that share `id`, `check` and
    `device` and differ only in the evidence -- exactly the shape the two
    fixtures produce -- and asserts they are explained separately.

These need neither Batfish nor Ollama: `explain_with_source` is
monkeypatched, the same way tests/test_web_findings_explanation.py already
does it.

RUN
    pytest tests/ -v
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from web import main


def _finding(status: str = "found", **overrides) -> Dict[str, Any]:
    base = {
        "id": "AC-001",
        "check": "access_control",
        "severity": "high",
        "device": "rtr-us5",
        "summary": "A finding",
        "evidence": {"detail": "some evidence", "source": "rtr-us5:acl_in"},
        "status": status,
    }
    base.update(overrides)
    return base


class _Counter:
    """A stand-in for explain_with_source that records what it was asked.

    Returns a DIFFERENT string each call, so a cache hit and a fresh call
    are distinguishable in the output as well as in the count. A stub that
    returned the same text every time could not tell them apart.
    """

    def __init__(self, source: str = "model"):
        self.calls: List[Dict[str, Any]] = []
        self.source = source

    def __call__(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        self.calls.append(dict(finding))
        return f"explanation #{len(self.calls)}", self.source

    @property
    def n(self) -> int:
        return len(self.calls)


# --- Criterion 1: repeated calls do not re-invoke the model -------------------


def test_a_second_identical_request_makes_no_model_call(monkeypatch):
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    first = main._attach_explanations([_finding()])
    assert stub.n == 1

    second = main._attach_explanations([_finding()])
    assert stub.n == 1, (
        f"the model was called again for an unchanged finding "
        f"({stub.n} calls across two requests, expected 1)"
    )
    assert second[0]["explanation"] == first[0]["explanation"]
    assert second[0]["explanation_source"] == "model"


def test_five_findings_cost_five_calls_once_not_once_per_request(monkeypatch):
    """The measured shape of the defect, as a test.

    rtr-us5-insecure produces five status="found" findings. Before the
    cache that was five model calls per page load, for ever.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    findings = [_finding(id=f"AC-00{i}", summary=f"finding {i}")
                for i in range(1, 6)]

    for _ in range(3):
        main._attach_explanations([dict(f, evidence=dict(f["evidence"]))
                                   for f in findings])

    assert stub.n == 5, (
        f"three requests over five findings made {stub.n} model calls; "
        f"expected 5 (once each), was 15 before the cache"
    )


def test_re_explaining_an_already_explained_list_is_still_a_hit(monkeypatch):
    """The two keys this module adds must not change the fingerprint.

    _attach_explanations() mutates in place, so a caller that passed the
    same list twice would present a dict that now carries "explanation" and
    "explanation_source". If those took part in the key, the second pass
    would miss every time and the cache would silently do nothing.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    findings = [_finding()]
    main._attach_explanations(findings)
    assert "explanation" in findings[0]

    main._attach_explanations(findings)      # same list, now carrying the keys
    assert stub.n == 1


# --- Criterion 2: a new upload never serves the previous network's text -------


def test_two_networks_sharing_an_id_are_explained_separately(monkeypatch):
    """The failure #92 exists to prevent, in the exact shape our fixtures
    produce: same `id`, same `check`, same `device`, different evidence."""
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    insecure = _finding(
        id="AC-001",
        evidence={"detail": "permit ip any any on acl_in",
                  "source": "rtr-us5:acl_in"},
    )
    messy = _finding(
        id="AC-001",
        evidence={"detail": "ACL rule never takes effect in acl_in",
                  "source": "rtr-us5:acl_in"},
    )

    (a,) = main._attach_explanations([insecure])
    (b,) = main._attach_explanations([messy])

    assert stub.n == 2, (
        "two different findings that share an id were served one "
        "explanation -- this is the id-keyed cache bug #92 warns about"
    )
    assert a["explanation"] != b["explanation"]


def test_a_change_to_any_field_is_a_miss(monkeypatch):
    """Every F-1 field takes part in the key.

    Parametrised over the fields rather than spot-checking one, because a
    fingerprint that happens to cover the field someone tested and misses
    another is the weaker claim standing in for the stronger one that this
    project keeps cataloguing.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    main._attach_explanations([_finding()])
    baseline = stub.n
    assert baseline == 1

    variants = [
        _finding(id="AC-999"),
        _finding(check="policy_compliance"),
        _finding(severity="low"),
        _finding(device="rtr-hq"),
        _finding(summary="a different summary"),
        _finding(evidence={"detail": "different", "source": "rtr-us5:acl_in"}),
        _finding(evidence={"detail": "some evidence", "source": "elsewhere"}),
    ]
    for variant in variants:
        main._attach_explanations([variant])

    assert stub.n == baseline + len(variants), (
        f"{baseline + len(variants) - stub.n} of {len(variants)} single-field "
        f"changes were served a cached explanation belonging to a different "
        f"finding"
    )


def test_a_nested_evidence_change_is_a_miss(monkeypatch):
    """`evidence` is a dict, so a shallow key would miss changes inside it.

    This is the one that would break if the fingerprint ever became
    `str(finding.keys())` or a tuple of top-level values.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    main._attach_explanations([_finding(
        evidence={"detail": "line 10 permits", "source": "rtr-us5:acl_in"})])
    main._attach_explanations([_finding(
        evidence={"detail": "line 20 permits", "source": "rtr-us5:acl_in"})])

    assert stub.n == 2


# --- Criterion 3: a failed explanation is not cached --------------------------


def test_fallback_text_is_never_cached(monkeypatch):
    """A transient Ollama outage must not become permanent.

    `source="fallback"` means the model could not be reached and the text is
    `ai.explain._fallback_plain_restatement()` -- correct and grounded
    (#52), but nothing a later working Ollama should be prevented from
    improving on.
    """
    down = _Counter(source="fallback")
    monkeypatch.setattr(main, "explain_with_source", down)

    main._attach_explanations([_finding()])
    main._attach_explanations([_finding()])
    assert down.n == 2, "fallback text was cached and reused"

    # Ollama comes back.
    up = _Counter(source="model")
    monkeypatch.setattr(main, "explain_with_source", up)
    (result,) = main._attach_explanations([_finding()])

    assert up.n == 1
    assert result["explanation_source"] == "model", (
        "a working Ollama was shadowed by cached fallback text"
    )


def test_an_exception_is_not_cached(monkeypatch):
    """The boundary's own guarantee, extended to the cache.

    ai/explain.py promises never to raise; web/main.py does not own that
    guarantee and already catches anyway. If a raise ever happened, nothing
    should be stored -- otherwise one bad moment is remembered for ever.
    """
    def explodes(finding):
        raise RuntimeError("Ollama said no")

    monkeypatch.setattr(main, "explain_with_source", explodes)
    (result,) = main._attach_explanations([_finding()])
    assert "explanation" not in result

    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)
    (result,) = main._attach_explanations([_finding()])
    assert stub.n == 1
    assert result["explanation"] == "explanation #1"


# --- Criterion 4: none and error still never reach the model (#56) ------------


def test_a_none_finding_still_never_reaches_the_model(monkeypatch):
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)
    (result,) = main._attach_explanations([_finding("none")])
    assert stub.n == 0
    assert "explanation" not in result
    assert "explanation_source" not in result


def test_an_error_finding_still_never_reaches_the_model(monkeypatch):
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)
    (result,) = main._attach_explanations([_finding("error")])
    assert stub.n == 0
    assert "explanation" not in result
    assert "explanation_source" not in result


def test_a_none_finding_cannot_be_served_a_found_findings_explanation(monkeypatch):
    """The dangerous version of a cache collision, tested directly.

    If the cache were ever keyed on something that ignored `status`, a
    "could not check" card could acquire prose written for a real finding --
    F-4's failure reached through the cache. `status` is part of the
    fingerprint, and nothing that is not "found" is looked up at all, so
    this is belt and braces.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)

    main._attach_explanations([_finding("found")])
    (result,) = main._attach_explanations([_finding("none")])

    assert stub.n == 1
    assert "explanation" not in result


# --- The cache is bounded -----------------------------------------------------


def test_the_cache_does_not_grow_without_limit(monkeypatch):
    """An unbounded cache in a tool that reads firewall exports is its own
    kind of defect. Drives it past the cap and checks it holds."""
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)
    monkeypatch.setattr(main, "EXPLANATION_CACHE_MAX", 8)

    for i in range(30):
        main._attach_explanations([_finding(summary=f"finding {i}")])

    assert stub.n == 30
    assert len(main._explanation_cache) <= 8, (
        f"cache holds {len(main._explanation_cache)} entries, cap is 8"
    )


def test_the_cap_evicts_the_least_recently_used(monkeypatch):
    """Not just "small" -- the RIGHT entries survive.

    A cache that evicted the most recent entry would still pass the size
    test above while being useless, which is the weaker claim standing in
    for the stronger one.
    """
    stub = _Counter()
    monkeypatch.setattr(main, "explain_with_source", stub)
    monkeypatch.setattr(main, "EXPLANATION_CACHE_MAX", 3)

    a, b, c = (_finding(summary=s) for s in ("a", "b", "c"))
    for f in (a, b, c):
        main._attach_explanations([dict(f, evidence=dict(f["evidence"]))])
    assert stub.n == 3

    # Touch "a" so it is the most recently used, then push the cap.
    main._attach_explanations([dict(a, evidence=dict(a["evidence"]))])
    assert stub.n == 3, "'a' should still have been cached"

    main._attach_explanations([_finding(summary="d")])
    assert stub.n == 4

    # "b" was the least recently used, so it is the one that should be gone.
    main._attach_explanations([dict(a, evidence=dict(a["evidence"]))])
    assert stub.n == 4, "the most recently used entry was evicted"

    main._attach_explanations([dict(b, evidence=dict(b["evidence"]))])
    assert stub.n == 5, "the least recently used entry survived eviction"


# --- The fingerprint itself ---------------------------------------------------


def test_the_fingerprint_ignores_key_order():
    """Two equal findings built in different orders must agree.

    Python dicts preserve insertion order, so a naive str() of the dict
    would give two different keys for the same finding depending on how the
    check happened to build it.
    """
    one = {"id": "AC-001", "status": "found", "device": "rtr-us5"}
    two = {"device": "rtr-us5", "id": "AC-001", "status": "found"}
    assert main._finding_fingerprint(one) == main._finding_fingerprint(two)


def test_the_fingerprint_survives_a_value_it_cannot_serialise():
    """A fingerprint that cannot be computed must not break the response.

    F-1 values are strings and dicts today. If one ever is not, `default=str`
    keeps this working rather than raising inside the findings endpoint.
    """
    class Odd:
        def __str__(self):
            return "odd-value"

    key = main._finding_fingerprint({"id": "AC-001", "summary": Odd()})
    assert isinstance(key, str) and len(key) == 64
