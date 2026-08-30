"""Tests for POST /api/business-context and its effect on /api/findings.

WHAT THIS PROTECTS
    Three things, and none is obvious from reading the endpoint:

    1. A REJECTED CONTEXT MUST NEVER BE STAGED. If validation fails and the
       file lands anyway, the user sees an error and still has a broken
       context in the staging location, silently re-rating the next
       analysis. The endpoint validates into a temp file and copies to
       BUSINESS_CONTEXT_PATH only after the loader returns.

    2. A CONTEXT MUST NEVER LAND IN configs/. Batfish reads every file
       there; a JSON asset list handed to a config parser either fails and
       blames the user's network, or produces a snapshot that analyses
       cleanly while containing a file that is not a config.

    3. WITH NO STAGED CONTEXT, NOTHING RUNS. Not "runs and changes
       nothing" -- the calls are skipped entirely, so anyone who never
       uploads one is on precisely the old code path. Asserted against a
       recorded baseline rather than argued in a comment.

WHY THE EQUIVALENCE TEST AT THE BOTTOM MATTERS
    The web layer applies the context in two calls --
    `sort_findings(apply_business_context(...))` -- instead of the single
    `refine(results, context)` the pipeline cannot make, because
    POST_PROCESSORS' one-argument signature is the ADOPTED F-3 shape. Those
    two routes must not be allowed to drift apart, so their equality is
    tested rather than assumed.

NO BATFISH, NO OLLAMA, NO NETWORK. The endpoint validates with
`analysis.business_context.load_business_context_file()`, which is pure
standard library; the findings path is driven with a stubbed analyse().
"""

import json
from pathlib import PurePosixPath, PureWindowsPath

import pytest
from fastapi.testclient import TestClient

from analysis.checks.risk import refine
from web import main

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _post_context(body, filename="business-context.json"):
    """POST a business context. `body` may be a list (encoded) or raw bytes."""
    if isinstance(body, (bytes, bytearray)):
        payload = bytes(body)
    else:
        payload = json.dumps(body).encode("utf-8")
    return client.post(
        "/api/business-context",
        files={"file": (filename, payload, "application/json")},
    )


def _post_config(text=b"hostname rtr-us5\n", filename="device.cfg"):
    return client.post("/api/upload", files={"file": (filename, text, "text/plain")})


VALID_CONTEXT = [
    {
        "device": "rtr-us5",
        "tier": "critical",
        "description": "Edge router, carries all site traffic",
    },
    {"device": "sw-lab-1", "tier": "standard"},
]


def _finding(**overrides):
    base = {
        "id": "AC-001",
        "check": "access_control",
        "severity": "medium",
        "device": "rtr-us5",
        "summary": "A rule allows traffic that policy forbids",
        "evidence": {"detail": "flow permitted", "source": "testFilters"},
        "status": "found",
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def clean_staging():
    """Leave no staged context behind, in either direction.

    Module-level paths survive a test, so a context staged by one test would
    otherwise be visible to the next -- which is the stale-state confusion
    these tests are about.
    """
    main._discard_staged_business_context()
    yield
    main._discard_staged_business_context()


@pytest.fixture
def analysed(monkeypatch):
    """Drive /api/findings off a fixed finding list, with no Batfish.

    THE STUB RUNS refine() ITSELF, AND THAT IS NOT A DETAIL.
        The real `analyse()` returns findings that have already been through
        POST_PROCESSORS, so `risk.refine()` has already applied R-1..R-4 by
        the time /api/findings sees them. A stub returning raw findings
        would put the endpoint on a path that exists nowhere in production.

        Written that way first, and it made the equivalence test at the
        bottom of this file pass for the wrong reason: with R-3 skipped, a
        routing finding kept `high`, was capped at `high` by escalation, and
        matched the one-pass answer of medium-then-escalated-to-high by
        arithmetic accident. Fixed by having the stub do what the pipeline
        does -- call refine() with ONE argument, exactly as POST_PROCESSORS
        does -- so the context is applied by the endpoint and nothing else.

    Explanations are stubbed out too: this file is about severities, and a
    real explain() call would make it depend on whether Ollama is installed.
    """
    state = {"results": []}

    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(
        main.analysis_pipeline,
        "analyse",
        lambda *a, **k: refine([dict(f) for f in state["results"]]),
    )
    monkeypatch.setattr(main, "_attach_explanations", lambda results: results)
    main.reset_analysis_cache()

    def use(*results):
        state["results"] = list(results)
        main.reset_analysis_cache()

    return use


# ---------------------------------------------------------------------------
# The endpoint: accepted
# ---------------------------------------------------------------------------


def test_a_valid_context_is_accepted_and_staged():
    response = _post_context(VALID_CONTEXT)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] is True
    assert body["asset_count"] == 2
    assert body["is_empty"] is False
    assert main.BUSINESS_CONTEXT_PATH.exists()

    # Staged verbatim: what the loader validated and what a later request
    # reads cannot differ.
    assert (
        json.loads(main.BUSINESS_CONTEXT_PATH.read_text(encoding="utf-8"))
        == VALID_CONTEXT
    )


def test_the_message_says_what_will_actually_happen():
    """Unlike the policy upload, this one IS applied -- so the message says
    so, and says the one thing it does rather than implying more."""
    body = _post_context(VALID_CONTEXT).json()

    assert "accepted" in body["message"]
    assert "critical" in body["message"]
    assert "one severity level" in body["message"]


def test_an_empty_list_is_accepted_as_a_deliberate_choice():
    body = _post_context([]).json()

    assert body["is_empty"] is True
    assert body["asset_count"] == 0
    assert "keeps exactly the severity the rules gave it" in body["message"]


def test_a_subnet_entry_is_reported_as_unusable_rather_than_silently_accepted():
    """"Accepted" plus no visible change is how a user concludes their
    context was applied when nothing matched it."""
    body = _post_context(
        [{"subnet": "10.10.10.0/24", "tier": "critical", "description": "Finance"}]
    ).json()

    assert body["accepted"] is True
    assert len(body["unusable"]) == 1
    assert "Finance" in body["unusable"][0]


def test_a_device_only_context_reports_nothing_unusable():
    assert _post_context(VALID_CONTEXT).json()["unusable"] == []


# ---------------------------------------------------------------------------
# The endpoint: rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        ([{"device": "rtr-us5", "tier": "high"}], "unknown tier"),
        ([{"device": "rtr-us5", "tier": "Critical"}], "did you mean 'critical'"),
        ([{"device": "rtr-us5", "tier": "critical", "owner": "me"}], "unknown key"),
        ([{"tier": "critical"}], "must identify one asset"),
        ([{"subnet": "finance-vlan", "tier": "critical"}], "literal IP address"),
        ({"device": "rtr-us5"}, "list of entries"),
    ],
)
def test_an_invalid_context_is_rejected_with_the_loaders_own_message(body, expected):
    """The message is passed through unchanged.

    `analysis/business_context.py` already names the entry and offers a
    did-you-mean; rephrasing here could only degrade it, and would let the
    API and the loader start disagreeing about what a file's problem is.
    """
    response = _post_context(body)

    assert response.status_code == 400
    assert expected in response.json()["detail"]


def test_a_rejected_context_is_never_staged():
    """The safety property the validate-then-stage order exists for."""
    _post_context([{"device": "rtr-us5", "tier": "critical"}])
    assert main.BUSINESS_CONTEXT_PATH.exists()

    main._discard_staged_business_context()
    response = _post_context([{"device": "rtr-us5", "tier": "nonsense"}])

    assert response.status_code == 400
    assert not main.BUSINESS_CONTEXT_PATH.exists()


def test_a_rejected_context_does_not_replace_a_good_one_already_staged():
    """Worse than not staging: staging a broken file OVER a working one."""
    _post_context(VALID_CONTEXT)

    assert _post_context([{"device": "x", "tier": "nope"}]).status_code == 400
    assert (
        json.loads(main.BUSINESS_CONTEXT_PATH.read_text(encoding="utf-8"))
        == VALID_CONTEXT
    )


def test_malformed_json_is_rejected_with_line_and_column():
    response = _post_context(b'[{"device": "rtr-us5",}]')

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "not valid JSON" in detail and "line" in detail


@pytest.mark.parametrize("filename", ["context.yaml", "context.yml", "context.txt", "context"])
def test_a_non_json_extension_is_refused(filename):
    response = _post_context(VALID_CONTEXT, filename=filename)

    assert response.status_code == 400
    assert "not a business context" in response.json()["detail"]


def test_an_empty_upload_is_refused_and_says_how_to_mean_it():
    """An empty FILE is a valid empty context to the loader, but a zero-byte
    UPLOAD is far likelier to be a mistake -- and accepting it would stage
    "no asset matters more than any other" without the user saying it."""
    response = _post_context(b"")

    assert response.status_code == 400
    assert "empty list `[]`" in response.json()["detail"]


#: Client-supplied filenames that carry a directory component. Both
#: separator styles, plus an absolute path, because a browser on any OS can
#: put any of them in a multipart filename field.
TRAVERSAL_NAMES = [
    "../../../../etc/passwd.json",
    r"..\..\windows\system32\evil.json",
    "/tmp/absolute.json",
]


@pytest.mark.parametrize("sent", TRAVERSAL_NAMES)
def test_the_staged_filename_is_always_ours_whatever_the_client_sent(sent):
    """THE ACTUAL SAFETY PROPERTY, and it holds on every platform.

    The client's string is never joined onto a path. The staged file is
    always the one location this module chose, whatever arrives -- so a
    traversal attempt cannot write anywhere, regardless of how the running
    platform happens to interpret separators.

    This is the assertion that matters. The one below it, about the echoed
    name, is a defence-in-depth check on a string that only ever reaches a
    message.
    """
    response = _post_context(VALID_CONTEXT, filename=sent)

    assert response.status_code == 200, response.text
    assert main.BUSINESS_CONTEXT_PATH.exists()
    assert main.BUSINESS_CONTEXT_PATH.name == "business-context.json"
    assert main.BUSINESS_CONTEXT_PATH.parent == main.SNAPSHOT_DIR

    # Nothing was written anywhere else under the snapshot either.
    strays = [
        f.name
        for f in main.SNAPSHOT_DIR.glob("*.json")
        if f.name not in {"business-context.json", "policy.json"}
    ]
    assert strays == [], f"unexpected file(s) staged: {strays}"


@pytest.mark.parametrize(
    "sent", ["../../../../etc/passwd.json", "/tmp/absolute.json"]
)
def test_a_forward_slash_path_is_reduced_to_a_basename(sent):
    """Forward slashes are reduced on EVERY platform, so this is safe to
    assert unconditionally -- `/` is a separator to both PurePosixPath and
    PureWindowsPath.

    This is also what keeps the mutation honest: deleting `Path(...).name`
    from the endpoint fails this test on Windows and on Linux alike.
    """
    response = _post_context(VALID_CONTEXT, filename=sent)

    assert response.status_code == 200, response.text
    echoed = response.json()["filename"]
    assert "/" not in echoed
    assert echoed.endswith(".json")


def test_the_backslash_reduction_is_platform_dependent_and_that_is_recorded():
    """Pins the real behaviour rather than the behaviour I assumed.

    This test previously asserted that the echoed name contained neither
    separator, which is simply not true cross-platform: `Path` resolves to
    PureWindowsPath on Windows and PurePosixPath on Linux, and only the
    former treats a backslash as a separator. It passed on my machine and
    failed in CI, which is the wrong way round for a test whose whole
    subject is a security boundary.

    The safety property is unaffected -- the staged filename is fixed by
    the server on both platforms, which the test above asserts. What is
    genuinely inconsistent is `display_name` itself, and the same idiom is
    used by /api/upload and /api/policy. That is filed rather than fixed
    here, because a shared helper touching three endpoints does not belong
    in a business-context branch.
    """
    windows_style = r"..\..\windows\system32\evil.json"

    assert PureWindowsPath(windows_style).name == "evil.json"
    assert PurePosixPath(windows_style).name == windows_style, (
        "POSIX does not treat a backslash as a separator -- this is the "
        "difference the old test was blind to"
    )

    # Both agree on forward slashes, which is why the test above can assert
    # that unconditionally.
    posix_style = "../../../../etc/passwd.json"
    assert PureWindowsPath(posix_style).name == "passwd.json"
    assert PurePosixPath(posix_style).name == "passwd.json"


def test_staging_a_context_does_not_throw_away_a_cached_analysis():
    """The inverse of what a comment here used to claim.

    An earlier version called `reset_analysis_cache()` on upload, justified
    by "or the escalation would not appear". That mechanism does not exist:
    the cache holds the findings analyse() returned, before any context, and
    /api/findings applies the context downstream of the cache read on every
    request. A mutation deleting the call survived, because it changed
    nothing -- so it was removed rather than kept as false reassurance, and
    this pins the behaviour that made it unnecessary.

    `test_uploading_a_new_context_takes_effect_immediately` is the other
    half: the escalation still appears on the next request.
    """
    main.reset_analysis_cache()
    main._analysis_cache["sentinel"] = []

    _post_context(VALID_CONTEXT)

    assert "sentinel" in main._analysis_cache


def test_a_context_never_lands_in_the_configs_directory():
    """Batfish reads every file under configs/. This one must never be there."""
    _post_context(VALID_CONTEXT)

    assert main.BUSINESS_CONTEXT_PATH.parent == main.SNAPSHOT_DIR
    if main.CONFIGS_DIR.exists():
        assert not list(main.CONFIGS_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Clearing: a new config must not inherit the old network's context
# ---------------------------------------------------------------------------


def test_uploading_a_config_clears_a_staged_context():
    _post_context(VALID_CONTEXT)
    assert main.BUSINESS_CONTEXT_PATH.exists()

    body = _post_config().json()

    assert not main.BUSINESS_CONTEXT_PATH.exists()
    assert body["business_context_cleared"] is True


def test_the_clearing_is_reported_rather_than_silent():
    """A user who uploaded a context and then a config needs to be told it
    went, not discover it by wondering why a severity dropped back."""
    _post_context(VALID_CONTEXT)

    assert _post_config().json()["business_context_cleared"] is True


def test_uploading_a_config_with_no_staged_context_reports_nothing_cleared():
    assert _post_config().json()["business_context_cleared"] is False


def test_clearing_the_context_does_not_disturb_the_policy_flag():
    """Both are cleared on a config upload, and each reports itself. A
    single flag covering both would tell the user something vaguer than
    either fact."""
    _post_context(VALID_CONTEXT)

    body = _post_config().json()

    assert body["business_context_cleared"] is True
    assert body["policy_cleared"] is False


# ---------------------------------------------------------------------------
# End to end: a critical device really does show an escalated severity
# ---------------------------------------------------------------------------


def test_a_critical_device_shows_an_escalated_severity_through_the_api(analysed):
    """The whole point of the feature, through a real HTTP request."""
    analysed(_finding(id="AC-001", device="rtr-us5", severity="medium"))

    before = client.get("/api/findings").json()
    assert [f["severity"] for f in before] == ["medium"]

    assert _post_context(VALID_CONTEXT).status_code == 200

    after = client.get("/api/findings").json()
    assert [f["severity"] for f in after] == ["high"]


def test_an_unmatched_device_is_unchanged_through_the_api(analysed):
    """Absence of context is not information, asserted end to end."""
    analysed(_finding(id="AC-001", device="rtr-hq", severity="medium"))
    _post_context(VALID_CONTEXT)

    assert [f["severity"] for f in client.get("/api/findings").json()] == ["medium"]


def test_findings_are_identical_with_no_context_staged(analysed):
    """Provably the old path: the baseline is recorded with no context file,
    and compared to the same request after one is staged and cleared."""
    analysed(
        _finding(id="AC-001", device="rtr-us5", severity="medium"),
        _finding(id="RT-050", device="rtr-us5", check="routing", severity="high"),
        _finding(id="PC-001", device="rtr-us5", status="error", severity="low"),
    )

    baseline = client.get("/api/findings").json()

    _post_context(VALID_CONTEXT)
    main._discard_staged_business_context()

    assert client.get("/api/findings").json() == baseline


def test_the_escalation_reorders_the_list_on_screen(analysed):
    analysed(
        _finding(id="AC-002", device="sw-lab-1", severity="medium"),
        _finding(id="AC-001", device="rtr-us5", severity="medium"),
    )

    assert [f["id"] for f in client.get("/api/findings").json()] == ["AC-002", "AC-001"]

    _post_context(VALID_CONTEXT)

    assert [f["id"] for f in client.get("/api/findings").json()] == ["AC-001", "AC-002"]


def test_an_error_finding_is_not_escalated_through_the_api(analysed):
    """F-4 end to end: an unrunnable check is a blind spot whatever tier the
    device carries."""
    analysed(_finding(id="PC-001", device="rtr-us5", status="error", severity="low"))
    _post_context(VALID_CONTEXT)

    assert [f["severity"] for f in client.get("/api/findings").json()] == ["low"]


def test_repeated_requests_do_not_escalate_twice(analysed):
    """The cache-poisoning failure, which would be invisible and progressive.

    `results` may be the list held in _analysis_cache. Escalating it in
    place would bake the change in, and each request would escalate the
    already-escalated copy: medium, then high, then -- via R-4 reading the
    severity back as a default -- no further, but a `low` finding would
    climb the whole scale over three page loads.
    """
    analysed(_finding(id="AC-001", device="rtr-us5", severity="low"))
    _post_context(VALID_CONTEXT)

    severities = [client.get("/api/findings").json()[0]["severity"] for _ in range(4)]

    assert severities == ["medium", "medium", "medium", "medium"]


def test_uploading_a_new_context_takes_effect_immediately(analysed):
    """A cached analysis has its severities baked in, so staging a context
    has to invalidate the cache or the escalation would not appear until
    something else evicted the entry."""
    analysed(_finding(id="AC-001", device="rtr-us5", severity="medium"))

    assert client.get("/api/findings").json()[0]["severity"] == "medium"

    _post_context([{"device": "rtr-us5", "tier": "critical"}])

    assert client.get("/api/findings").json()[0]["severity"] == "high"


def test_a_corrupt_staged_file_does_not_take_down_the_findings(analysed):
    """Nothing unvalidated can reach the staged path, so this means the file
    changed underneath us. Scoring as if no context existed is the honest
    response; losing every finding over a refinement is not."""
    analysed(_finding(id="AC-001", device="rtr-us5", severity="medium"))
    main.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    main.BUSINESS_CONTEXT_PATH.write_text("{ not json", encoding="utf-8")

    response = client.get("/api/findings")

    assert response.status_code == 200
    assert [f["severity"] for f in response.json()] == ["medium"]


# ---------------------------------------------------------------------------
# The two routes must not drift apart
# ---------------------------------------------------------------------------


def test_the_web_layer_route_equals_a_single_refine_call(analysed):
    """`sort_findings(apply_business_context(...))` after the pipeline's own
    `refine()` must equal `refine(results, context)` in one pass.

    The web layer cannot make that single call: POST_PROCESSORS' one-argument
    signature is the ADOPTED F-3 shape and changing it needs the team. So the
    equality is tested rather than assumed, and this test fails the day the
    two routes stop agreeing.
    """
    raw = [
        _finding(id="AC-001", device="rtr-us5", severity="medium"),
        _finding(id="AC-002", device="sw-lab-1", severity="low"),
        # A routing finding on an UNLISTED device: R-3 pulls it high -> medium
        # and no escalation follows. This is the row that makes the test
        # discriminating -- on a critical device the escalation caps at high
        # and both routes agree whether or not R-3 ran, so a version of this
        # test carrying only the critical case passed by arithmetic accident.
        _finding(id="RT-050", device="rtr-hq", check="routing", severity="high"),
        _finding(id="RT-051", device="rtr-us5", check="routing", severity="high"),
        _finding(id="PC-001", device="rtr-us5", status="error", severity="low"),
    ]
    analysed(*raw)
    _post_context(VALID_CONTEXT)

    through_the_api = client.get("/api/findings").json()

    context = main._staged_business_context()
    in_one_pass = refine([dict(f) for f in raw], context)

    assert through_the_api == in_one_pass
