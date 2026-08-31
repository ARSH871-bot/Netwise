"""Netwise -- Layer 3, the web backend.

RUN IT
    pip install -r requirements.txt
    uvicorn web.main:app --reload
    open http://127.0.0.1:8000          (API docs at /docs)

Run from the repository root, so `analysis` and `web` both import.

WHAT THIS SERVES (US-10)
    Before any upload: mock F-1 findings from web/mock_findings.py, so the
    dashboard has something to render on a fresh start.
    After an upload:  real findings from analysis.pipeline.analyse().

    The shape is identical either way, which is why the frontend needed no
    changes when the pipeline was wired in.

THE SEAM
    analysis.pipeline.analyse(snapshot_dir) -> list[dict] is the whole backend
    API. It does not raise for operational failures -- an unreachable Batfish
    or an unparseable config come back AS findings with status="error". So the
    error path needs no extra code here: it is already findings the dashboard
    knows how to render, which is exactly the F-4 guarantee end to end.
"""

import hashlib
from datetime import datetime, timezone
import json
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi import Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ai.explain import explain_with_source
from ai.propose import propose_change
from ai.query import answer_question
from analysis import findings, pipeline as analysis_pipeline, report
from analysis.business_context import (
    TIERS,
    BusinessContextError,
    load_business_context_file,
)
from analysis.checks.risk import (
    apply_business_context,
    sort_findings,
    unusable_entries,
)
from analysis.pfsense_convert import PfSenseConversionError, convert as pfsense_convert
from analysis.policy import PolicyError, load_policy_file
from web import mock_findings
from web.session import (
    DEFAULT_SESSION,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    current_session_id,
    is_valid_session_id,
    new_session_id,
    reset_current_session,
    set_current_session,
)

# --- Upload validation rules ------------------------------------------------
#
# These live here, on the SERVER, because that is the only place they can be
# enforced. The same checks exist in the frontend (see static/app.js), but
# those are a courtesy to the user -- instant feedback without a round trip.
# Anyone can bypass the browser. Client-side validation is UX; this is the
# actual control.

# Extensions we will accept. Cisco IOS exports are .cfg or .conf; .txt is
# common when someone has copied a config out of a terminal.
ALLOWED_EXTENSIONS = {".cfg", ".conf", ".txt"}

# Extensions we recognise as a PF Sense export and CONVERT before staging.
#
# Batfish does not read PF Sense XML natively (see CLAUDE.md section 7), so
# analysis.pfsense_convert.convert() translates it into Cisco IOS text first,
# which re-enters exactly the same staging path as an uploaded .cfg. This
# used to be a flat rejection ("converting it is still open work") -- that
# stopped being true once the converter existed; it was just never wired to
# the upload path. See CLAUDE.md section 7 for what the converter can and
# cannot model, and REFUSALS in pfsense_convert.py for exactly why it refuses
# when it does.
PFSENSE_EXTENSIONS = {".xml", ".pfsense"}

# 2 MB. A router config is tens of kilobytes; a firewall config with large
# object groups might reach a few hundred. Two megabytes is generous for a real
# config and small enough that a mistaken upload (a disk image, a packet
# capture) is rejected before we spend memory on it.
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

# Read the upload in pieces rather than all at once, so an oversized file is
# rejected after 64 KB instead of after we have swallowed the whole thing.
CHUNK_BYTES = 64 * 1024

STATIC_DIR = Path(__file__).parent / "static"

# --- Where an uploaded config is staged for analysis ------------------------
#
# The layout matters, and getting it wrong is the single most common way to end
# up with a silently empty snapshot. Batfish wants the device files one level
# down from the snapshot root, in a `configs/` subfolder:
#
#     uploaded_configs/          <- CONFIG_ROOT
#       current/                 <- SNAPSHOT_DIR   ** this is what analyse() gets **
#         configs/               <- configs_dir()
#           device.cfg           <- the uploaded file
#
# analysis.pipeline.load_snapshot checks for that `configs/` subfolder and
# raises if it is missing, so passing the wrong level fails loudly rather than
# analysing nothing and reporting all clear.
# PER SESSION SINCE #242. The layout above is unchanged -- it just sits one
# level down, under the session that staged it:
#
#     uploaded_configs/
#       sessions/
#         <session id>/
#           current/           <- snapshot_dir(), what analyse() gets
#             configs/         <- configs_dir()
#               device.cfg
CONFIG_ROOT = Path(__file__).parent / "uploaded_configs"
SESSIONS_ROOT = CONFIG_ROOT / "sessions"
SNAPSHOT_NAME = "current"


def _effective_session() -> str:
    """Which session a path call belongs to, in or out of a request.

    INSIDE a request the ContextVar holds the real session and is used --
    that is what isolates concurrent users, and `_last_session_id` is never
    consulted there.

    OUTSIDE one -- a test fixture calling `_discard_staged_policy()`, a
    script, the CLI -- the ContextVar is still at DEFAULT_SESSION. Resolving
    to that would point at a directory no request ever wrote to, so a
    fixture would clean one place while the thing it is cleaning up after
    lives in another. That mismatch is not theoretical: it left 25 tests
    failing in the full run while every one of them passed alone.

    So out-of-request callers get the last session that made a request,
    which is what a single-session caller means by "the staged file".
    """
    session_id = current_session_id()
    return _last_session_id if session_id == DEFAULT_SESSION else session_id


def snapshot_dir(session_id: Optional[str] = None) -> Path:
    """The snapshot root for a session -- the folder that CONTAINS configs/."""
    return SESSIONS_ROOT / (session_id or _effective_session()) / SNAPSHOT_NAME


def configs_dir(session_id: Optional[str] = None) -> Path:
    """Where Batfish reads device files from, for a session."""
    return snapshot_dir(session_id) / "configs"

# --- Where an uploaded POLICY is staged (#87) -------------------------------
#
# DELIBERATELY OUTSIDE configs/, AND THAT IS THE POINT.
#     Batfish reads every file under `configs/`. A policy landing there would
#     be handed to the parser as if it were a device, which produces either a
#     parse error blamed on the user's network or -- worse -- a snapshot that
#     analyses cleanly while quietly containing a file that is not a config.
#
#     So it sits beside the snapshot rather than inside it, and nothing that
#     walks `configs/` can ever see it.
#
#         uploaded_configs/
#           current/
#             configs/            <- Batfish reads THIS
#               device.cfg
#             policy.json         <- and never this
def policy_path(session_id: Optional[str] = None) -> Path:
    """Where a session's uploaded policy is staged."""
    return snapshot_dir(session_id) / "policy.json"

#: A policy is JSON and only JSON. `analysis/policy.py` explains why the
#: loader is JSON-only rather than YAML -- picking YAML would add a runtime
#: dependency to a security tool on one person's say-so -- and this endpoint
#: must not accept a format the loader cannot read.
POLICY_EXTENSIONS = {".json"}

# --- Where an uploaded BUSINESS CONTEXT is staged (#87, risk side) ----------
#
# Beside the policy, and outside `configs/` for the identical reason: Batfish
# reads every file under `configs/`, and a JSON asset list handed to a config
# parser is either a parse error blamed on the user's network or a snapshot
# that analyses cleanly while containing a file that is not a config.
#
#     uploaded_configs/
#       current/
#         configs/                 <- Batfish reads THIS
#           device.cfg
#         policy.json              <- and never this
#         business-context.json    <- nor this
def business_context_path(session_id: Optional[str] = None) -> Path:
    """Where a session's uploaded business context is staged."""
    return snapshot_dir(session_id) / "business-context.json"

#: JSON only, matching `analysis/business_context.py`'s own limit. This
#: endpoint must not accept a format the loader cannot read.
BUSINESS_CONTEXT_EXTENSIONS = {".json"}

# Has a config been uploaded in this process? Until one has, /api/findings
# serves mock data, because there is genuinely nothing to analyse yet.
#
# Module-level state is only defensible because this is a single-user local
# tool. Two people uploading at once would overwrite each other's snapshot.
# If Netwise ever serves more than one user, this becomes per-session state.
_last_session_id: str = DEFAULT_SESSION

_uploaded: bool = False


#: Sessions that have staged a config. A set rather than a dict of flags:
#: the only fact tracked is "has this session uploaded", and a set cannot
#: grow a second meaning by accident.
#:
#: UNBOUNDED, DELIBERATELY, AND SMALL. One short string per browser that has
#: ever uploaded, in a process that serves a handful of people on one
#: machine. Evicting entries would mean deciding when a session is over,
#: which is a question this feature does not answer and should not pretend
#: to -- see #242's own scope.
_uploaded_sessions: "set[str]" = set()


def _is_uploaded() -> bool:
    """Has THIS session staged a config?

    THE MODULE-LEVEL `_uploaded` IS STILL HONOURED, AS AN OVERRIDE.
        Fourteen tests across six files set it directly to drive the
        endpoints without performing an upload. Those tests use ONE client,
        so "this process is in the uploaded state" is exactly what they
        mean, and honouring it keeps them passing unchanged.

        Nothing SETS it any more -- a real upload records the session
        instead. So it can only ever be True because a caller deliberately
        made it True, and it cannot leak one user's upload to another: a
        second session sees it only if a test put the whole process in that
        state on purpose.
    """
    return _uploaded or current_session_id() in _uploaded_sessions

app = FastAPI(
    title="Netwise",
    description=(
        "Reads exported network device configuration files, finds security "
        "misconfigurations, and explains them in plain English. Runs entirely "
        "offline -- it never connects to, scans, or modifies a live network."
    ),
    version="0.1.0",
)


# --- Per-session identity (#242) ---------------------------------------------
#
# Every request carries a session id, issued on the first one and kept in a
# cookie. Everything else in this module that used to be one shared value --
# the staged config, the `_uploaded` flag, the analysis cache -- keys off it.
#
# WHY A MIDDLEWARE RATHER THAN A DEPENDENCY ON EACH ROUTE
#     A dependency has to be remembered on every new endpoint, and the cost
#     of forgetting is not an error -- it is an endpoint quietly sharing the
#     default session with everyone. A middleware cannot be forgotten.
#
# THE CONTEXTVAR IS RESET IN A `finally`
#     Starlette reuses tasks and threads. Leaving a session installed after
#     the response would let the NEXT request on the same worker inherit it
#     before its own middleware runs -- which is the bug this whole feature
#     exists to remove, arriving through the mechanism meant to fix it.


@app.middleware("http")
async def attach_session(request: Request, call_next):
    """Give this request a session, issuing one if the browser has none."""
    sent = request.cookies.get(SESSION_COOKIE)

    # A cookie is client-supplied text and this value becomes a DIRECTORY
    # NAME, so anything not shaped like an id we issued is discarded rather
    # than repaired -- see is_valid_session_id().
    if is_valid_session_id(sent):
        session_id, issued = sent, False
    else:
        session_id, issued = new_session_id(), True

    global _last_session_id
    _last_session_id = session_id

    token = set_current_session(session_id)
    try:
        response = await call_next(request)
    finally:
        reset_current_session(token)

    if issued:
        # httponly: no page script needs to read this, and not handing it to
        # JavaScript costs nothing. samesite=lax: the dashboard is the only
        # thing that calls these endpoints.
        response.set_cookie(
            SESSION_COOKIE,
            session_id,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
    return response


# --- Backwards-compatible module attributes (#242) ---------------------------
#
# `SNAPSHOT_DIR`, `CONFIGS_DIR`, `POLICY_PATH` and `BUSINESS_CONTEXT_PATH`
# were module-level Paths before sessions existed, and forty-four assertions
# across five test files read them. They resolve dynamically now, via PEP 562.
#
# WHY THE SHIM RESOLVES TO THE LAST SESSION THAT MADE A REQUEST
#     A caller reading `main.POLICY_PATH` is outside any request -- a test
#     asserting a file landed, or a script. The ContextVar is already reset
#     by then, so resolving it there would give the DEFAULT session and point
#     at a directory the request never wrote to.
#
#     `_last_session_id` is what the single-session caller means: "the
#     session that just did the thing I am checking". For one client that is
#     exact.
#
# THIS IS A READ-SIDE CONVENIENCE AND NOTHING ELSE.
#     No request handler uses these names -- every one of them calls
#     `configs_dir()` / `policy_path()` and reads the ContextVar, which is
#     what actually isolates concurrent requests. `_last_session_id` is
#     racy by construction under concurrency, and that is tolerable ONLY
#     because nothing that serves a request reads it.
#
#     tests/test_session_isolation.py asserts that separation directly, so
#     a handler that started using the shim would fail rather than quietly
#     de-isolate itself.

_SESSION_SCOPED_ATTRS = {
    "SNAPSHOT_DIR": snapshot_dir,
    "CONFIGS_DIR": configs_dir,
    "POLICY_PATH": policy_path,
    "BUSINESS_CONTEXT_PATH": business_context_path,
}


def __getattr__(name: str):
    """Resolve the legacy path names against the last active session."""
    resolver = _SESSION_SCOPED_ATTRS.get(name)
    if resolver is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return resolver()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the dashboard page."""
    return FileResponse(STATIC_DIR / "index.html")


# --- The explanation cache (#92) ---------------------------------------------
#
# WHY THIS EXISTS
#     /api/findings called the model once per status="found" finding on EVERY
#     hit, and `loadFindings()` runs at script load (static/app.js), so every
#     page load paid it again. Measured on rtr-us5-insecure before this
#     change, counting calls to ollama.generate rather than timing them:
#
#         hit 1: 5 found  ->  5 model calls
#         hit 2: 5 found  ->  5 model calls
#         hit 3: 5 found  ->  5 model calls
#
# WHY THE KEY IS THE FINDING AND NOT ITS `id`
#     #92 warned that keying on `id` would serve a stale explanation for a
#     DIFFERENT network. That is not hypothetical -- two of our own fixtures
#     already collide:
#
#         rtr-us5-insecure   AC-001  AC-002  PC-001  PC-002  PC-003
#         rtr-us5-messy      AC-001  AC-002  AC-003  AC-004  PC-004  PC-005
#                            ^^^^^^  ^^^^^^ used by BOTH
#
#     An id-keyed cache would print one network's explanation onto the other
#     network's finding, and the text would read as though it had been
#     written for what is on screen. Same class as #82, and worse.
#
#     So the key is a hash of the whole finding, with only the two keys this
#     module itself adds removed. Anything a reader would notice changing --
#     any F-1 field, and any field a future amendment adds -- changes the
#     key. The failure direction is a wasted regeneration, never a wrong hit.
#
# WHY FALLBACK TEXT IS NEVER CACHED
#     `explanation_source == "fallback"` means the model could not be
#     reached. Caching that would make a transient Ollama outage permanent
#     for the life of the process, which is #92's third acceptance criterion.
#     Storing only "model" results satisfies it by construction rather than
#     by a separate check that could drift.
#
# BOUNDED
#     An OrderedDict used as an LRU, capped, so a long-running server cannot
#     grow without limit on a big config. Unbounded caches in a tool that
#     reads firewall exports are their own kind of defect.

#: How many explanations to keep. 256 is roughly forty times the largest
#: finding count any configuration we can currently analyse produces.
EXPLANATION_CACHE_MAX = 256

_explanation_cache: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()

#: The keys THIS module adds downstream of F-1 validation. They are the
#: output of the computation being cached, so they cannot be part of its key.
#: Everything else in the dict participates, including fields F-1 does not
#: have yet -- a narrower allow-list would silently stop distinguishing
#: findings the day the contract is amended.
_DOWNSTREAM_KEYS = ("explanation", "explanation_source")


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """A stable hash of the finding as the pipeline produced it.

    `sort_keys=True` so two equal dicts built in different orders agree.
    `default=str` so an unexpected value type degrades to a distinct string
    rather than raising -- a fingerprint that cannot be computed must not be
    able to take down the findings response.
    """
    payload = {k: v for k, v in finding.items() if k not in _DOWNSTREAM_KEYS}
    encoded = json.dumps(payload, sort_keys=True, default=str,
                         ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _cached_explanation(key: str) -> Optional[Tuple[str, str]]:
    """Return a cached ("text", "model") pair, or None. Refreshes LRU order."""
    hit = _explanation_cache.get(key)
    if hit is not None:
        _explanation_cache.move_to_end(key)
    return hit


def _remember_explanation(key: str, explanation: str, source: str) -> None:
    """Store a MODEL explanation. Fallback text is deliberately not stored."""
    if source != "model":
        return
    _explanation_cache[key] = (explanation, source)
    _explanation_cache.move_to_end(key)
    while len(_explanation_cache) > EXPLANATION_CACHE_MAX:
        _explanation_cache.popitem(last=False)


def reset_explanation_cache() -> None:
    """Empty the cache.

    Exported for tests. `tests/conftest.py` calls it between every test,
    because module-level state that survives a test is how one test starts
    passing for a reason belonging to another one.
    """
    _explanation_cache.clear()


# --- The analysis cache (#92b) -----------------------------------------------
#
# WHY THIS IS SEPARATE FROM THE EXPLANATION CACHE ABOVE
#     It is the LARGER cost, and the one nobody was counting. Measured on
#     rtr-us5-insecure, Batfish up:
#
#         hit 1:  3.72s   6 findings
#         hit 2:  3.61s   6 findings
#         hit 3:  3.61s   6 findings
#         hit 4:  3.60s   6 findings
#
#     Unlike the model calls, that price is paid **whether or not Ollama is
#     installed** -- so on CI, and on every machine we have demonstrated
#     this on, it was the entire observable cost of a page load.
#
# WHY THE KEY IS THE SNAPSHOT'S CONTENT
#     Same discipline as the explanation cache: content, never a name. A key
#     of "the current snapshot" would serve one network's findings for
#     another the moment a second config is staged at the same path -- which
#     is precisely what an upload does. Hashing the bytes makes a different
#     config a different key by construction.
#
# WHY AN OUTAGE IS NEVER CACHED, AND HOW THAT IS DETECTED
#     Caching a failed analysis would freeze "we could not check" as the
#     permanent answer -- F-4's own failure, made durable. That is the same
#     mistake as caching fallback explanation text, one layer down.
#
#     Measured rather than guessed, because the obvious rule ("refuse if any
#     finding is an error") would disable the cache entirely -- every fixture
#     legitimately produces one structural error on every healthy run:
#
#         BATFISH UP     rtr-us5-insecure  {'found': 5, 'error': 1}
#                        rtr-us5-secure    {'none': 2,  'error': 1}
#                          the error is RT-050, routing assertions that name
#                          rtr-hq/rtr-branch and do not apply here. Stable,
#                          correct, and present every single run.
#
#         BATFISH DOWN   rtr-us5-insecure  {'error': 3}
#                        rtr-us5-secure    {'error': 3}
#                          AC-000 / PC-000 / RT-000, "Analysis could not run:
#                          Batfish is not reachable" -- EVERY check, and no
#                          found or none anywhere.
#
#     So the rule is: cache only if at least one check produced a real
#     result. That separates the two measured cases exactly, without parsing
#     a summary string or depending on id numbering.
#
#     KNOWN LIMIT, stated rather than papered over: if one check were
#     transiently broken while the others worked, its error would be cached
#     alongside their real results. All three checks share one Batfish
#     session, so a transient failure takes all three (measured above); a
#     single-check failure is a bug in that check, which is stable rather
#     than transient. Small, and real.

#: How many analysed snapshots to remember. Small on purpose: this is a
#: single-user local tool and each entry holds a whole findings list.
ANALYSIS_CACHE_MAX = 8

_analysis_cache: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()


def _snapshot_fingerprint(configs_dir: Path) -> Optional[str]:
    """Hash every staged config file: names and bytes.

    Returns None if the directory cannot be read, which disables the cache
    for that request rather than inventing a key. A fingerprint that cannot
    be computed must never collapse to a constant -- that would make every
    snapshot share one entry, which is the id-keyed mistake with a different
    hat on.
    """
    try:
        digest = hashlib.sha256()
        for path in sorted(configs_dir.rglob("*")):
            if not path.is_file():
                continue
            digest.update(path.relative_to(configs_dir).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()
    except OSError:
        return None


def _staged_policy():
    """The validated policy the user uploaded, or None if there is not one.

    Returns None rather than raising when the staged file will not load.
    That cannot normally happen -- `/api/policy` validates BEFORE staging,
    so a file only reaches policy_path() after `load_policy_file()` returns --
    but a file edited on disk between upload and scan would otherwise take
    down an endpoint that has nothing to do with it.

    Falling back to None means "analyse against our built-in example rules",
    which is exactly what the run would have done before a policy existed,
    and `policy_compliance` says which of the two it used in every finding's
    evidence. So the degraded path is still self-describing rather than
    silently pretending the user's rules were applied.
    """
    if not policy_path().exists():
        return None
    try:
        return load_policy_file(policy_path())
    except (PolicyError, OSError):
        return None


def _analysis_key() -> Optional[str]:
    """One cache key covering BOTH inputs the analysis depends on.

    The config fingerprint alone is not enough once a policy can change the
    result -- see the block comment in `get_findings()`. A policy that is
    absent, present, or edited must each produce a different key.
    """
    config_part = _snapshot_fingerprint(configs_dir())
    if config_part is None:
        # The config half could not be fingerprinted, so the cache is already
        # disabled for this request. Do not invent half a key.
        return None
    digest = hashlib.sha256()
    digest.update(config_part.encode())
    # A domain separator. Deliberately NOT covered by a test: `config_part`
    # is always a 64-character hex digest, so the boundary is already
    # unambiguous and removing this line changes no key. Mutation-tested and
    # it survives, which is the correct outcome for defensive clarity rather
    # than a gap -- recorded here so nobody later mistakes it for one.
    digest.update(b"\0policy\0")
    try:
        digest.update(policy_path().read_bytes() if policy_path().exists()
                      else b"<no policy>")
    except OSError:
        return None
    return digest.hexdigest()


def _analysis_is_worth_caching(results: List[Dict[str, Any]]) -> bool:
    """Did any check actually produce a result?

    See the block comment above for the measurements this encodes. An
    all-error list means nothing ran, and remembering it would turn a
    stopped container into a permanent verdict.
    """
    return any(f.get("status") in ("found", "none") for f in results)


def _cached_analysis(key: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    if key is None:
        return None
    hit = _analysis_cache.get(key)
    if hit is not None:
        _analysis_cache.move_to_end(key)
    return hit


def _remember_analysis(key: Optional[str], results: List[Dict[str, Any]]) -> None:
    if key is None or not _analysis_is_worth_caching(results):
        return
    _analysis_cache[key] = results
    _analysis_cache.move_to_end(key)
    while len(_analysis_cache) > ANALYSIS_CACHE_MAX:
        _analysis_cache.popitem(last=False)


def reset_analysis_cache() -> None:
    """Empty the analysis cache.

    Called on every upload (see upload_config) and by tests. Content-keying
    already makes a stale hit impossible, so this is belt and braces rather
    than the mechanism -- but #82 exists because a staged config and a
    checked one were once confused, and a cache is exactly where that could
    come back. Cheap insurance on the path that matters.
    """
    _analysis_cache.clear()


def _attach_explanations(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a plain-English explanation to every status="found" finding
    (US-19 / #31).

    THE SHAPE CHOSEN, AND WHY
        The explanation is added as an extra "explanation" key on the
        response dict, NOT a new field in the F-1 contract itself. F-1's
        fields are defined in docs/finding-format.md and enforced by
        analysis/findings.py -- changing THAT needs agreement from all
        four team members (CLAUDE.md section 7a). This key is added here,
        downstream of that validation, purely for this endpoint's JSON
        response; analysis.pipeline.analyse() and every check still return
        (and are still validated against) the F-1 shape unchanged. #31's
        own text names this as the option that "avoids that entirely".

        A second extra key, "explanation_source" ("model" or "fallback"),
        is added the same way, for the same reason (#109): the dashboard
        labels every explanation "AI explanation" unconditionally, and on a
        machine without Ollama that text is
        `ai.explain._fallback_plain_restatement()`, deterministic string
        concatenation of the finding's own fields -- correct and grounded
        (#52), but no model wrote it. Attaching the real source here, downstream
        of F-1 validation like "explanation" itself, is Option B from #109:
        it keeps ai.explain.explain_with_source()'s contract narrow (report
        the fact, do not decide what the dashboard does with it) and leaves
        the byline/CSS decision to whoever owns that presentation.

    WHY ONLY status="found"
        A "none" finding has nothing to explain beyond its own summary,
        and an "error" finding has no real Batfish output to ground an
        explanation in -- asking the model to write prose about a check
        that never ran is the invented-network-behaviour failure
        CLAUDE.md constraint 2 forbids. static/app.js's rendering already
        encodes this same rule for which cards get the explanation slot
        at all; this keeps the two in agreement.

    WHY THE EXTRA try/except, WHEN explain_with_source() IS BUILT NOT TO RAISE
        ai/explain.py's own module docstring guarantees explain() never
        raises, and explain_with_source() is the same computation with one
        more fact reported alongside it -- an unreachable Ollama, a model
        that was never built, or a malformed finding all degrade to
        deterministic fallback text internally (see _try_generate() and the
        thin-evidence guard). This except is a second, independent layer at
        a boundary this module does not own: if that guarantee is ever
        wrong, one explanation failing must not take down the WHOLE
        findings response. Same reasoning analysis.pipeline.run_check()
        already applies to one check's crash not being allowed to break the
        other three, one layer further out. Neither key is attached in that
        case -- the finding still renders, just without them, matching
        #31's acceptance criterion for an unreachable Ollama exactly.

    DOES NOT MUTATE `results` -- and that changed in #92b
        This used to add the two keys to the caller's dicts in place. The
        docstring said so, and said exactly when it would stop being safe:

            "Would stop being safe the moment either of those changes (a
             cached analyse() result, or a second consumer of the same list
             that expects exactly the F-1 shape); switch to building a new
             list of shallow copies at that point."

        #92b is that moment. `get_findings()` now serves a CACHED findings
        list, so mutating in place would write `explanation` and
        `explanation_source` onto the cached dicts -- and the next request
        would find them already there, on an object F-1 validation is
        entitled to see in its exact contracted shape. The warning was
        written for this change and this change honours it rather than
        re-deciding whether it still applies.

        So each finding is shallow-copied before the keys are added, and a
        new list is returned. The nested `evidence` dict is deliberately
        SHARED rather than deep-copied: nothing here writes to it, deep
        copying every finding on every request would undo the cost this
        change exists to remove, and a test asserts the cached original is
        never modified.
    """
    attached: List[Dict[str, Any]] = []
    for original in results:
        # A shallow copy per finding: the caller's dict (which may be the
        # cached one) must come out of this function exactly as it went in.
        finding = dict(original)
        attached.append(finding)
        if finding.get("status") != "found":
            continue
        try:
            # The fingerprint is computed BEFORE the two keys are attached,
            # and they are excluded from it anyway -- so re-explaining an
            # already-explained list still produces the same key.
            key = _finding_fingerprint(finding)
            hit = _cached_explanation(key)
            if hit is not None:
                explanation, source = hit
            else:
                explanation, source = explain_with_source(finding)
                _remember_explanation(key, explanation, source)
            finding["explanation"] = explanation
            finding["explanation_source"] = source
        except Exception:
            pass
    return attached


# --- The report download -----------------------------------------------------
#
# WHY IT REUSES get_findings() RATHER THAN CALLING analyse() ITSELF
#     A report that could disagree with the screen is worse than no report.
#     Going through the same function means the same cache, the same
#     explanations, and the same ordering -- so "download" cannot silently
#     re-run the analysis and produce a different answer from the one the
#     user is looking at.
#
# WHY THE EXPLANATIONS ARE STRIPPED BACK OUT
#     `explanation` and `explanation_source` are added downstream of F-1
#     validation for the dashboard's benefit. The report renders F-1 and
#     nothing else, so it does not inherit a field the contract does not
#     have. If explanations belong in the report, that is a deliberate
#     decision to take, not something to acquire by accident.
#
#     AND IT IS CURRENTLY UNOBSERVABLE, WHICH IS SAID HERE RATHER THAN
#     LEFT TO LOOK LIKE A CONTROL. Mutation-tested: removing this strip
#     changes no output at all.
#
#         let the dashboard-only keys into the report   621 passed
#
#     Both renderers read NAMED fields -- `_finding_html()` reads six of
#     them, `render_csv()` writes a fixed column list -- so an extra key
#     cannot reach either format however it arrives. The strip is cheap
#     insurance against a future renderer that iterates keys instead, and
#     `tests/test_report_export.py` asserts the observable property (the
#     explanation TEXT never appears) so such a renderer would be caught.
#     It is not a guard that is currently holding anything up.
REPORT_FORMATS = {
    "html": ("text/html; charset=utf-8", "html"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}


@app.get("/api/report")
def download_report(format: str = "html") -> Response:
    """The findings, as a file that can leave the screen.

    Serves whatever `/api/findings` would serve right now -- including the
    mock findings before any upload, because a report of demo data is less
    confusing than an error, and the report says what it is describing.
    """
    if format not in REPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=(f"Unknown report format {format!r}. "
                    f"Choose one of: {', '.join(sorted(REPORT_FORMATS))}."),
        )

    results = [
        {k: v for k, v in finding.items() if k not in _DOWNSTREAM_KEYS}
        for finding in get_findings()
    ]
    uploaded = _is_uploaded()
    subject = configs_dir().name if uploaded else "example findings (no upload yet)"
    if uploaded:
        staged = sorted(p.name for p in configs_dir().glob("*") if p.is_file())
        subject = ", ".join(staged) or "an uploaded configuration"

    media_type, extension = REPORT_FORMATS[format]
    body = (report.render_html(results, source=subject) if format == "html"
            else report.render_csv(results))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition":
                f'attachment; filename="netwise-report-{stamp}.{extension}"'
        },
    )


@app.get("/api/findings")
def get_findings() -> List[Dict[str, Any]]:
    """Return the current findings, in the F-1 format, plus a plain-English
    "explanation" on every status="found" finding (US-19 / #31).

    Serves mock data until a config has been uploaded, then calls the real
    pipeline. The response shape is identical either way, including
    status="error" findings when analysis cannot run at all.

    Note snapshot_dir(), not CONFIG_ROOT: analyse() wants the snapshot root, the
    folder that CONTAINS `configs/`. See the layout diagram at the top.

    Mock findings are NOT explained. #31's acceptance criterion is about a
    real finding from a real uploaded config; explaining fabricated demo
    data risks a viewer mistaking a rephrased invention for a rephrased
    fact, which is exactly the distinction this whole project exists to
    keep clear.
    """
    if not _is_uploaded():
        return mock_findings.get_mock_findings()

    # #92b: re-analysing an unchanged snapshot costs ~3.6s of real Batfish
    # work on every page load. The key is the staged config's CONTENT, so a
    # new upload is a new key and no stale result can be served; an analysis
    # that could not run is never stored. See the block comment above.
    #
    # THE KEY COVERS THE POLICY TOO, AND IT MUST (#181).
    #     POLICY_PATH lives beside `configs/`, not inside it, so
    #     `_snapshot_fingerprint(configs_dir())` cannot see it. Wiring the
    #     policy into analyse() without also widening the key produces a
    #     feature that silently does nothing:
    #
    #         upload config, Scan   -> analysed, cached under K
    #         upload policy, Scan   -> same K, so the PRE-POLICY result is
    #                                  served and the policy appears inert
    #
    #     That is worse than not shipping it. The user gets a green
    #     "policy accepted" message and findings computed without it.
    key = _analysis_key()
    results = _cached_analysis(key)
    if results is None:
        results = analysis_pipeline.analyse(
            snapshot_dir(),
            snapshot_name=SNAPSHOT_NAME,
            policy=_staged_policy(),
        )
        _remember_analysis(key, results)

    # --- Business context (#87, risk side) ---------------------------------
    #
    # Applied here rather than inside the pipeline -- see the block comment
    # above /api/business-context for why, and for why calling refine() a
    # second time would be wrong rather than merely redundant.
    #
    # WITH NO STAGED FILE, NOTHING RUNS AT ALL.
    #     Not "runs and changes nothing" -- the calls are skipped, so the
    #     list returned is the same object graph as before this feature
    #     existed. That is deliberately provable rather than argued: a user
    #     who never uploads a context is on exactly the old path.
    #
    # BOTH CALLS COPY, WHICH THE CACHE DEPENDS ON.
    #     `results` may be the list held in _analysis_cache. escalating in
    #     place would bake the escalation into the cached entry, and the
    #     NEXT request would escalate the already-escalated copy again --
    #     medium, high, and R-4 would carry it further still. Both
    #     apply_business_context() and sort_findings() return new lists, and
    #     tests/test_business_context_scoring.py pins the copying.
    context = _staged_business_context()
    if context is not None:
        results = sort_findings(apply_business_context(results, context))

    # _attach_explanations() copies rather than mutating, so the list held in
    # the cache never acquires the two extra keys. That is not incidental --
    # it is the condition this module's own docstring set for caching here.
    return _attach_explanations(results)


@app.post("/api/upload")
async def upload_config(file: UploadFile) -> Dict[str, Any]:
    """Accept a config file, validating it before we do anything with it,
    stage it, and clear whatever was staged (or analysed) before it.

    Rejections come back as HTTP 400 with a message written for a person, not
    a stack trace -- "that file is 5.2 MB; the limit is 2 MB" rather than
    "413". The frontend shows the message verbatim.

    A PF Sense export (.xml, .pfsense) is CONVERTED before staging, via
    analysis.pfsense_convert.convert() -- see PFSENSE_EXTENSIONS above. Two
    things this deliberately gets right, both easy to get wrong:

      1. Write the staged file under a directory WE choose, using a filename
         WE generate. Never join a client-supplied name onto a path:
         `display_name` is used for display only, reduced to its basename
         first, precisely so it can never walk out of a directory. Batfish
         expects device files one level down, in <snapshot>/configs/ -- see
         analysis.pipeline.load_snapshot, which fails loudly about this.
      2. A refused PF Sense conversion must not destroy the previous config.
         Conversion happens BEFORE the old snapshot is cleared, the same
         validate-then-stage discipline the policy upload already follows.
    """
    # Path(...).name strips any directory component a client may have sent --
    # "../../etc/passwd" becomes "passwd". We only ever display this string,
    # but reducing it at the boundary means a later change cannot make it
    # dangerous by accident.
    display_name = Path(file.filename or "").name
    if not display_name:
        raise HTTPException(status_code=400, detail="No file was uploaded.")

    extension = Path(display_name).suffix.lower()
    allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
    is_pfsense = extension in PFSENSE_EXTENSIONS

    if not is_pfsense and extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is not a config file we can read. "
                f"Netwise accepts {allowed} files, or a PF Sense config.xml "
                "export."
            ),
        )

    # Read in chunks and stop as soon as the limit is passed, rather than
    # trusting a Content-Length header the client controls. The bytes are
    # accumulated as we go so the file can be staged once it has passed every
    # check -- nothing touches disk until we know we want it.
    size = 0
    contents = bytearray()
    while chunk := await file.read(CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            limit_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{display_name}' is larger than the {limit_mb:.0f} MB "
                    "limit. Network configs are normally well under this -- "
                    "is this definitely a config file?"
                ),
            )
        contents.extend(chunk)

    if size == 0:
        raise HTTPException(
            status_code=400, detail=f"'{display_name}' is empty."
        )

    # --- Convert, if this is a PF Sense export ------------------------------
    #
    # Deliberately BEFORE clearing the previous config, not after. convert()
    # can refuse (PfSenseConversionError) -- an ambiguous rule order, a
    # construct it will not guess about, see REFUSALS in pfsense_convert.py.
    # A refused upload must leave whatever was staged before it untouched,
    # the same reasoning the policy upload already follows: validate first,
    # destroy nothing until the replacement is known-good.
    #
    # skipped names every interface pfsense_convert could not model (#78) --
    # e.g. a DHCP WAN or an undeclared VPN role -- so the response can show
    # it on screen rather than silently converting less than the user thinks.
    skipped: List[str] = []
    device_text: Optional[str] = None
    if is_pfsense:
        with tempfile.NamedTemporaryFile(
            suffix=".xml", delete=False
        ) as tmp_file:
            tmp_file.write(bytes(contents))
            tmp_path = Path(tmp_file.name)
        try:
            conversion = pfsense_convert(tmp_path)
        except PfSenseConversionError as error:
            raise HTTPException(
                status_code=400,
                detail=f"'{display_name}' could not be converted: {error}",
            ) from error
        except ET.ParseError as error:
            # convert() calls ET.parse() before it ever reaches its own
            # refusal logic -- a truncated download or a non-XML file with
            # an .xml extension fails here, not there. Uncaught, this was a
            # raw 500 with a traceback instead of a message written for a
            # person, found by testing against a deliberately malformed
            # upload rather than only the well-formed refusal fixtures.
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{display_name}' is not readable XML ({error}). If "
                    "this is a PF Sense export, check it downloaded "
                    "completely."
                ),
            ) from error
        finally:
            tmp_path.unlink(missing_ok=True)
        device_text = conversion.text
        skipped = conversion.skipped

    # --- Stage the file for analysis ---------------------------------------
    #
    # The previous upload is removed first, so a snapshot only ever contains
    # the config currently being analysed. Leaving an old device file behind
    # would silently mix two networks into one model. Reached only once the
    # upload is known-good -- a PF Sense refusal above never gets here.
    #
    # The filename is OURS ("device" plus the validated extension, or
    # "device.cfg" for a converted PF Sense export), never the client's.
    # display_name was already reduced to a basename above; this means the
    # client's string never reaches the filesystem at all.
    if configs_dir().exists():
        shutil.rmtree(configs_dir())
    configs_dir().mkdir(parents=True, exist_ok=True)

    if is_pfsense:
        staged_path = configs_dir() / "device.cfg"
        staged_path.write_text(device_text)
    else:
        staged_path = configs_dir() / f"device{extension}"
        staged_path.write_bytes(bytes(contents))

    # A NEW NETWORK MUST NOT INHERIT THE OLD NETWORK'S POLICY (#87, #82).
    #     The policy names devices -- `node: rtr-us5` -- so a policy written
    #     for the previous upload asserts nothing true about this one. Leaving
    #     it staged would either check the new config against rules meant for
    #     a different network, or report "could not check" for every rule and
    #     blame the new config for it.
    #
    #     Same discipline as clearing the findings, and the same reason: #82
    #     exists because a staged file and a checked one were once confused.
    #     Two files staged from two different intentions is that failure with
    #     one more moving part.
    policy_was_staged = policy_path().exists()
    _discard_staged_policy()

    # A NEW NETWORK MUST NOT INHERIT THE OLD NETWORK'S BUSINESS CONTEXT.
    #     Exactly the policy's reasoning, and if anything sharper. A context
    #     names devices -- `device: rtr-us5` -- and the failure is silent
    #     rather than loud: a stale entry that happens to match a device name
    #     on the NEW network would escalate findings there on the strength of
    #     a judgement the user made about a different machine. A policy that
    #     does not apply reports "could not check"; a context that does not
    #     apply just quietly re-rates the wrong box.
    context_was_staged = business_context_path().exists()
    _discard_staged_business_context()

    # Records THIS session, rather than putting the whole process into an
    # uploaded state. Before #242 this was `global _uploaded; _uploaded =
    # True`, which meant one person's upload made every other browser's
    # /api/findings start analysing a config they had never sent.
    _uploaded_sessions.add(current_session_id())

    # #92b / #82. Content-keying already makes a stale hit impossible, so
    # this is belt and braces -- but #82 exists precisely because a staged
    # config and a checked one were once confused, and a cache is where that
    # could return. Clearing on upload means the invariant holds even if the
    # fingerprint is ever weakened, which is the failure worth insuring
    # against rather than the one we expect.
    reset_analysis_cache()

    # Uploading stages the file and stops there -- the analysis starts when
    # the user clicks Scan Now. So this says what has happened and what has
    # NOT: accepted and staged, nothing checked yet. It previously said
    # "Loading results now...", which was true when the upload triggered
    # the analysis itself and would now describe work nobody has started.
    #
    # Naming the button matters. "Staged for analysis" alone reads like
    # something is already underway, which is the impression this whole
    # flow change exists to remove.
    if is_pfsense:
        message = (
            f"'{display_name}' is a PF Sense export -- converted to Cisco "
            f"IOS ({size:,} bytes read) and staged. Nothing has been "
            "analysed yet — click Scan Now to check it."
        )
    else:
        message = (
            f"'{display_name}' accepted ({size:,} bytes) and staged. "
            "Nothing has been analysed yet — click Scan Now to check it."
        )

    return {
        "filename": display_name,
        "size_bytes": size,
        "accepted": True,
        "message": message,
        # Reported rather than done silently: a user who uploaded a policy and
        # then a config needs to know the policy went with it, not discover it
        # by wondering why their rules stopped appearing.
        "policy_cleared": policy_was_staged,
        # Every interface pfsense_convert could not model, named with why
        # (#78) -- [] for a normal upload, or a PF Sense export nothing was
        # skipped on. Always present, never omitted when empty, matching the
        # project's own "an absent row is a weaker statement than an
        # explicit zero" rule for the findings summary tiles.
        "skipped": skipped,
        # Same reasoning as policy_cleared: a user who uploaded a context and
        # then a config needs to know it went with them, not discover it by
        # wondering why a severity dropped back.
        "business_context_cleared": context_was_staged,
    }


# --- The policy upload (#87) -------------------------------------------------
#
# WHY THIS IS A SEPARATE ENDPOINT AND NOT A SECOND EXTENSION ON /api/upload
#     A config and a policy share nothing except arriving as files. They have
#     different accepted extensions, different destinations, different
#     validation (`load_policy_file()` versus Batfish's parser), and different
#     consequences when they are wrong. Widening ALLOWED_EXTENSIONS to include
#     `.json` would let a policy be staged into `configs/` as a device file,
#     which is the one place it must never land.
#
# WHAT THIS ENDPOINT DOES WITH THE POLICY -- #181, AND #182 GATES THE MERGE
#     It stages a validated policy, and `/api/findings` now passes it to
#     `analyse()`. That was deliberately NOT done for most of this PR's life,
#     and the reason is worth keeping:
#
#         #181  this PR -- installs the policy in module-level state, so the
#               ADOPTED `run(bf)` signature never changes (option D)
#         #182  the decision request asking the team to choose between that
#               and three alternatives
#
#     Calling `set_active_policy()` from here picks the winner of that
#     decision. It is written now because option D has three of four recorded
#     positions and this PR already implements it -- the web call is the same
#     decision one layer out, not a second one. It must NOT merge before #182
#     is recorded, which is a review gate rather than anything the code can
#     enforce.
#
#     Until it does merge, the dashboard hint tells the user the policy is
#     staged and not applied, because on `main` that is still true.
#
# THE SAFETY PROPERTY, WHICH IS WHY VALIDATION HAPPENS BEFORE STAGING
#     A rejected policy must never reach POLICY_PATH. If it did, a user who
#     saw an error message would still have a broken policy staged, and the
#     next analysis would either fail on it or -- once #181 lands -- run
#     against a file nobody accepted. So the bytes go to a temp file the
#     loader can read, and the staged copy is written ONLY after
#     `load_policy_file()` has returned without raising.


def _discard_staged_policy() -> None:
    """Remove the staged policy file, if there is one.

    Not `set_active_policy(None)` -- see the block comment above. This only
    unstages the FILE, which is all this branch is entitled to do until
    #181/#182 settle how a policy reaches a check.
    """
    policy_path().unlink(missing_ok=True)


@app.post("/api/policy")
async def upload_policy(file: UploadFile) -> Dict[str, Any]:
    """Accept and validate a policy file, staging it only if it loads.

    Mirrors `upload_config()`'s discipline deliberately: reduce the client's
    filename to a basename at the boundary, check the extension, read in
    chunks against a size limit, refuse an empty upload, and write our own
    filename rather than theirs. The differences are the accepted extension,
    the destination, and that the CONTENT is validated rather than merely
    accepted.

    A rejection comes back as HTTP 400 carrying `PolicyError`'s own message,
    unchanged. That message names the entry and offers a did-you-mean for an
    unknown key -- work `analysis/policy.py` already did, and which a
    rephrasing here could only degrade.
    """
    display_name = Path(file.filename or "").name
    if not display_name:
        raise HTTPException(status_code=400, detail="No file was uploaded.")

    extension = Path(display_name).suffix.lower()
    if extension not in POLICY_EXTENSIONS:
        allowed = ", ".join(sorted(POLICY_EXTENSIONS))
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is not a policy file Netwise can read. "
                f"A policy is {allowed}. YAML is not supported yet -- see "
                f"analysis/policy.py for why."
            ),
        )

    size = 0
    contents = bytearray()
    while chunk := await file.read(CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            limit_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{display_name}' is larger than the {limit_mb:.0f} MB "
                    "limit. A policy file is a short list of rules -- is this "
                    "definitely a policy?"
                ),
            )
        contents.extend(chunk)

    if size == 0:
        # NOT the same as an empty POLICY. `load_policy_file()` treats an
        # empty file as a policy that asserts nothing, which is valid (D4).
        # But a zero-byte UPLOAD is far more likely to be a mistake -- the
        # wrong file, or a failed export -- and accepting it would stage "I
        # assert nothing" on the user's behalf without them having said it.
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is empty. To assert nothing deliberately, "
                "upload a policy whose sections are empty rather than an "
                "empty file, so that it is a choice on the record."
            ),
        )

    # --- Validate BEFORE staging ------------------------------------------
    #
    # The temp file exists so `load_policy_file()` can be used unchanged: it
    # takes a path, and it produces the JSON error messages -- with line and
    # column -- that the `--policy` command line already produces. Parsing
    # the bytes here instead would mean writing a second set of messages for
    # the same failures, which is how two paths start disagreeing about what
    # the same file means.
    handle, temp_name = tempfile.mkstemp(suffix=".json")
    temp_path = Path(temp_name)
    try:
        with open(handle, "wb") as staging:
            staging.write(bytes(contents))
        policy = load_policy_file(temp_path)
    except PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    finally:
        temp_path.unlink(missing_ok=True)

    # --- Only now does anything reach the staging location -----------------
    snapshot_dir().mkdir(parents=True, exist_ok=True)
    policy_path().write_bytes(bytes(contents))

    rule_count = sum(len(entries) for entries in policy.sections.values())
    if policy.is_empty:
        summary = (
            "It asserts nothing, which is a valid choice -- every "
            "policy-driven check will say so rather than fall back to ours."
        )
    else:
        sections = ", ".join(
            f"{name} {len(entries)}"
            for name, entries in sorted(policy.sections.items())
            if entries
        )
        summary = f"{rule_count} rule(s): {sections}."

    return {
        "filename": display_name,
        "size_bytes": size,
        "accepted": True,
        "rule_count": rule_count,
        "is_empty": policy.is_empty,
        # Corrected legacy key names, reported rather than applied silently.
        # A user who wrote `start_node:` should learn the name changed in
        # #159 -- accepting it and saying nothing is how one vocabulary
        # splits back into the dialects D1 was agreed to remove.
        "renamed": list(policy.renamed),
        # The same honest-staging pattern as #82: say what has happened and
        # what has NOT.
        #
        # THIS MESSAGE SAID "Not yet applied -- wiring to the analysis lands
        # with #181" UNTIL #181 LANDED, AND THEN KEPT SAYING IT. On screen
        # that read: your policy is not applied, followed immediately by a
        # scan whose findings had changed because it was. A control that
        # understates itself is not the safe direction of the #82 rule; it is
        # the same defect pointing the other way, and it is worse here because
        # the user has no way to tell which statement to believe.
        #
        # What it must keep saying is WHICH checks read it. `policy_compliance`
        # does; `access_control` and `routing` still assert our built-in rules
        # whatever is uploaded (#87). "Your policy is now in force" would be
        # the overclaim this message was originally written to avoid.
        "message": (
            f"'{display_name}' accepted ({size:,} bytes) and staged. {summary} "
            "Applied to the checks that read a policy — policy compliance. "
            "Access control and routing still use our built-in rules (#87)."
        ),
    }


# --- The business-context upload (#87, risk side) ---------------------------
#
# WHY THIS ONE IS WIRED UP WHEN THE POLICY UPLOAD DELIBERATELY IS NOT
#     `/api/policy` stages and stops, because how a policy reaches a check
#     was an open team decision (#181, #182) and picking the winner from
#     inside a feature branch is what that issue exists to prevent.
#
#     Business context has no such open question, for a structural reason:
#     it is consumed by a POST-PROCESSOR, which already receives the finished
#     findings. A check needs a policy handed to it before it runs; `risk`
#     needs the context only after everything has run. So there is nothing to
#     decide about how it gets there.
#
# WHERE IT IS APPLIED, AND WHY NOT IN THE PIPELINE
#     `refine()` is not called from this module. `analysis/pipeline.py` calls
#     it, through POST_PROCESSORS, with exactly one argument -- that
#     signature is the ADOPTED F-3 shape, and CLAUDE.md is explicit that the
#     three shapes are settled and need the team to change.
#
#     So the context is applied HERE, to the findings `analyse()` returns,
#     using the two functions `risk` exposes for it. The result is identical
#     to a single `refine(results, context)` call -- escalation applies to
#     the severity the ruleset settled on either way -- and
#     `test_business_context_wiring.py` proves that equivalence rather than
#     asserting it. If the team later decides a post-processor may take a
#     second argument, this becomes one line in the pipeline and this block
#     goes away.
#
# WHY NOT SIMPLY CALL refine() A SECOND TIME
#     Because it is not idempotent, and the way it fails is quiet. R-4 --
#     "everything else keeps its default" -- reads the severity ON the
#     finding. A `low` finding escalated to `medium` would, on a second pass,
#     have `medium` read back as its default and escalate again to `high`.
#     Two page loads, two different severities, no upload in between.


def _discard_staged_business_context() -> None:
    """Remove the staged business-context file, if there is one."""
    business_context_path().unlink(missing_ok=True)


def _staged_business_context():
    """The staged business context, or None if there is not one.

    Returns None on a file that will not load, rather than raising. Nothing
    unvalidated can reach this path -- the endpoint stages only after
    `load_business_context_file()` has returned -- so a failure here means
    the file changed underneath us or was written by something else. The
    honest response to that is to score exactly as if no context existed,
    which is what "absence of context is not information" already requires.

    It must never take down /api/findings: a business context is a refinement
    of a severity, and losing it is not worth losing the findings over.
    """
    if not business_context_path().exists():
        return None
    try:
        return load_business_context_file(business_context_path())
    except (BusinessContextError, OSError):
        return None


@app.post("/api/business-context")
async def upload_business_context(file: UploadFile) -> Dict[str, Any]:
    """Accept and validate a business context, staging it only if it loads.

    Mirrors `upload_policy()` exactly -- basename at the boundary, extension
    check, chunked read against the size limit, empty upload refused, our
    filename rather than theirs, and validation strictly BEFORE staging so a
    rejected file can never reach business_context_path().

    A rejection is HTTP 400 carrying `BusinessContextError`'s own message
    unchanged. That message names the entry and offers a did-you-mean for a
    miscased tier -- work `analysis/business_context.py` already did, and
    which rephrasing here could only degrade.
    """
    display_name = Path(file.filename or "").name
    if not display_name:
        raise HTTPException(status_code=400, detail="No file was uploaded.")

    extension = Path(display_name).suffix.lower()
    if extension not in BUSINESS_CONTEXT_EXTENSIONS:
        allowed = ", ".join(sorted(BUSINESS_CONTEXT_EXTENSIONS))
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is not a business context Netwise can "
                f"read. A business context is {allowed}."
            ),
        )

    size = 0
    contents = bytearray()
    while chunk := await file.read(CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            limit_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{display_name}' is larger than the {limit_mb:.0f} MB "
                    "limit. A business context is a short list of assets -- "
                    "is this definitely the right file?"
                ),
            )
        contents.extend(chunk)

    if size == 0:
        # NOT the same as an empty CONTEXT. The loader treats an empty file
        # as a context that says nothing, which is valid. A zero-byte UPLOAD
        # is far likelier to be a mistake, and accepting it would stage "no
        # asset matters more than any other" without the user saying it.
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is empty. To say nothing about any asset "
                "deliberately, upload an empty list `[]` rather than an "
                "empty file, so that it is a choice on the record."
            ),
        )

    # --- Validate BEFORE staging ------------------------------------------
    handle, temp_name = tempfile.mkstemp(suffix=".json")
    temp_path = Path(temp_name)
    try:
        with open(handle, "wb") as staging:
            staging.write(bytes(contents))
        context = load_business_context_file(temp_path)
    except BusinessContextError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    finally:
        temp_path.unlink(missing_ok=True)

    # --- Only now does anything reach the staging location -----------------
    snapshot_dir().mkdir(parents=True, exist_ok=True)
    business_context_path().write_bytes(bytes(contents))

    # NO reset_analysis_cache() HERE, AND THAT IS DELIBERATE.
    #     A `reset_analysis_cache()` call stood here, with a comment saying a
    #     new context had to invalidate the cache or the escalation would not
    #     appear until something evicted the entry. That was simply false: the
    #     cache holds the findings `analyse()` returned, BEFORE any context is
    #     applied, and /api/findings applies the context downstream of the
    #     cache read on every request. The escalation appears on the very next
    #     request whether the cache was cleared or not.
    #
    #     A mutation deleting the call survived, which is what exposed it --
    #     no test could fail, because the call changed nothing. Kept, it would
    #     have cost a full re-analysis (~3.6s of real Batfish work, #92b) on
    #     every context upload, in exchange for a mechanism that does not
    #     exist. A comment asserting a false mechanism is worse than no
    #     comment: the next reader would have built on it.

    # Entries that cannot affect anything are named, not swallowed. A user
    # who tagged their finance VLAN by subnet, saw "accepted", and saw no
    # change would reasonably conclude their context had been applied.
    unusable = unusable_entries(context)

    if context.is_empty:
        summary = (
            "It names no assets, which is a valid choice -- every finding "
            "keeps exactly the severity the rules gave it."
        )
    else:
        tiers = Counter(entry["tier"] for entry in context.entries)
        summary = f"{len(context)} asset(s): " + ", ".join(
            f"{tier} {tiers[tier]}" for tier in TIERS if tiers[tier]
        ) + "."

    return {
        "filename": display_name,
        "size_bytes": size,
        "accepted": True,
        "asset_count": len(context),
        "is_empty": context.is_empty,
        # Reported, never silently ignored -- see unusable_entries().
        "unusable": unusable,
        "message": (
            f"'{display_name}' accepted ({size:,} bytes) and staged. {summary} "
            "Findings on a 'critical' asset will be raised one severity level."
        ),
    }


class AskRequest(BaseModel):
    question: str


@app.post("/api/ask")
def ask_question(request: AskRequest) -> Dict[str, Any]:
    """Answer one plain-English question about the uploaded config (US-11).

    Always returns ai.query.answer_question()'s three keys
    (question_understood, answer, grounded), whether the question was
    answerable or refused. Never a 500 for an operational failure -- an
    empty question, no upload yet, an unreachable Batfish, or a config
    that will not load are all refusals in the same shape, the same
    convention analysis.pipeline.analyse() already holds for
    /api/findings and explain() now holds for an unreachable Ollama.

    Connects and loads the snapshot fresh on every call rather than
    reusing a cached session, the same choice /api/findings already
    makes for analyse() -- consistency over a caching optimisation
    nothing here has needed yet.
    """
    if not _is_uploaded():
        return {
            "question_understood": None,
            "answer": "Upload a config first, there is nothing to ask about yet.",
            "grounded": False,
        }

    try:
        bf = analysis_pipeline.connect()
        analysis_pipeline.load_snapshot(bf, snapshot_dir(), "netwise", SNAPSHOT_NAME)
    except Exception as error:
        return {
            "question_understood": None,
            "answer": (
                "Could not reach Batfish or load the snapshot. The "
                "underlying reason: " + findings.describe_error(error)
            ),
            "grounded": False,
        }

    return answer_question(request.question, bf)


class ProposeRequest(BaseModel):
    request: str


@app.post("/api/propose")
def propose_change_endpoint(body: ProposeRequest) -> Dict[str, Any]:
    """Propose one config change from plain English, and simulate its
    impact before returning it (US-13, US-14).

    Always returns ai.propose.propose_change()'s shape (request_understood,
    proposed_change, impact, verified, warning, grounded, answer), whether
    the request was understood or refused. Never a 500 for an operational
    failure -- no upload yet, an unreachable Batfish, or a request that
    does not resolve are all refusals in the same shape, the same
    convention /api/ask and /api/findings already hold.

    propose_change() connects and loads the snapshot fresh itself, the same
    "no caching" choice /api/ask already makes for answer_question() -- this
    endpoint does no connecting of its own, unlike /api/ask, because
    propose_change() also needs to read the raw config text to generate and
    apply a candidate line, which answer_question() never does.

    NEVER APPLIED TO A LIVE DEVICE, and never to the uploaded snapshot
    itself. propose_change() only ever writes to a throwaway copy -- see its
    own module docstring and CLAUDE.md's non-negotiable constraint 4. This
    endpoint adds no write path of its own.

    `impact`'s status="found" findings get the same plain-English
    explanation /api/findings already attaches to a found finding (US-19),
    reusing _attach_explanations() rather than a second mechanism -- a
    warning naming the exact ACL lines that changed is more useful read in
    plain English than as a raw Batfish diff.
    """
    if not _is_uploaded():
        return {
            "request_understood": None,
            "proposed_change": None,
            "impact": [],
            "verified": False,
            "warning": False,
            "grounded": False,
            "answer": (
                "Upload a config first, there is nothing to propose a "
                "change against yet."
            ),
        }

    result = propose_change(body.request, snapshot_dir())
    result["impact"] = _attach_explanations(result["impact"])
    return result


class NoCacheStatic(StaticFiles):
    """Serve static files with `Cache-Control: no-cache`, so browsers revalidate.

    WHY THIS EXISTS
        Starlette's StaticFiles sends ETag and Last-Modified but no
        Cache-Control. With no explicit directive a browser falls back to
        HEURISTIC freshness -- roughly 10% of the age since Last-Modified --
        and serves the file from cache WITHOUT revalidating. The ETag is never
        checked, so an edited app.js or style.css simply does not arrive.

        We lost real time to this. A change to the finding-card renderer was
        correct on disk, correct in the served bytes, and correct in a fresh
        browser, while the developer's browser kept running the previous
        script. A stale asset presents exactly like a bug in code that has
        nothing wrong with it, and there is no message anywhere saying so.

    WHY no-cache AND NOT no-store
        "no-cache" means "you may keep it, but revalidate before using it". The
        ETag above then makes revalidation cheap: unchanged files come back 304
        with no body. "no-store" would forbid caching entirely and re-download
        every asset on every request, which is slower for no added safety.

    NOTE the args passthrough: file_response()'s signature has changed between
    Starlette releases, so this deliberately does not restate it.
    """

    def file_response(self, *args: Any, **kwargs: Any) -> Any:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


# Mounted last so it cannot shadow the API routes above.
app.mount("/static", NoCacheStatic(directory=STATIC_DIR), name="static")
