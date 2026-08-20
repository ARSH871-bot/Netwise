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
import json
import shutil
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ai.explain import explain_with_source
from ai.query import answer_question
from analysis import findings, pipeline as analysis_pipeline
from web import mock_findings

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

# Extensions we RECOGNISE but cannot analyse yet. These get their own message.
#
# Why this exists: the client's real firewall is PF Sense, which exports XML,
# and Batfish does not read PF Sense XML natively (see CLAUDE.md section 7).
# Telling them "that is not a config file we can read" would be wrong and would
# look like a bug -- it plainly IS a config file. The honest answer is that we
# recognise it and cannot analyse it YET, which is a known limitation rather
# than a rejection of their file.
UNSUPPORTED_EXTENSIONS = {
    ".xml": (
        "This looks like a PF Sense export. Netwise cannot analyse PF Sense "
        "XML yet -- our analysis engine does not read that format natively, "
        "and converting it is still open work."
    ),
    ".pfsense": (
        "This looks like a PF Sense export. Netwise cannot analyse PF Sense "
        "XML yet -- our analysis engine does not read that format natively, "
        "and converting it is still open work."
    ),
}

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
#         configs/               <- CONFIGS_DIR
#           device.cfg           <- the uploaded file
#
# analysis.pipeline.load_snapshot checks for that `configs/` subfolder and
# raises if it is missing, so passing the wrong level fails loudly rather than
# analysing nothing and reporting all clear.
CONFIG_ROOT = Path(__file__).parent / "uploaded_configs"
SNAPSHOT_NAME = "current"
SNAPSHOT_DIR = CONFIG_ROOT / SNAPSHOT_NAME
CONFIGS_DIR = SNAPSHOT_DIR / "configs"

# Has a config been uploaded in this process? Until one has, /api/findings
# serves mock data, because there is genuinely nothing to analyse yet.
#
# Module-level state is only defensible because this is a single-user local
# tool. Two people uploading at once would overwrite each other's snapshot.
# If Netwise ever serves more than one user, this becomes per-session state.
_uploaded: bool = False

app = FastAPI(
    title="Netwise",
    description=(
        "Reads exported network device configuration files, finds security "
        "misconfigurations, and explains them in plain English. Runs entirely "
        "offline -- it never connects to, scans, or modifies a live network."
    ),
    version="0.1.0",
)


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

    NOTE: MUTATES `results` IN PLACE
        Flagged in review, worth stating rather than leaving implicit.
        Safe today because `get_findings()` calls `analyse()` fresh on
        every request and nothing re-validates or caches that list
        afterwards -- the extra key is never observed anywhere F-1
        validation runs. Would stop being safe the moment either of those
        changes (a cached analyse() result, or a second consumer of the
        same list that expects exactly the F-1 shape); switch to building
        a new list of shallow copies at that point rather than assuming
        this comment still holds.

        STILL TRUE AFTER #92, and worth saying because the cache above
        invites the opposite assumption. What #92 caches is the explanation
        TEXT, keyed by a hash of the finding -- never the findings list
        itself. `get_findings()` still calls `analyse()` fresh on every
        request, so the dict mutated here is a new one every time and no
        cached object ever acquires these two keys. Caching `analyse()` is
        the change that would break this, and it is deliberately left to a
        separate issue for exactly that reason.
    """
    for finding in results:
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
    return results


@app.get("/api/findings")
def get_findings() -> List[Dict[str, Any]]:
    """Return the current findings, in the F-1 format, plus a plain-English
    "explanation" on every status="found" finding (US-19 / #31).

    Serves mock data until a config has been uploaded, then calls the real
    pipeline. The response shape is identical either way, including
    status="error" findings when analysis cannot run at all.

    Note SNAPSHOT_DIR, not CONFIG_ROOT: analyse() wants the snapshot root, the
    folder that CONTAINS `configs/`. See the layout diagram at the top.

    Mock findings are NOT explained. #31's acceptance criterion is about a
    real finding from a real uploaded config; explaining fabricated demo
    data risks a viewer mistaking a rephrased invention for a rephrased
    fact, which is exactly the distinction this whole project exists to
    keep clear.
    """
    if not _uploaded:
        return mock_findings.get_mock_findings()
    results = analysis_pipeline.analyse(SNAPSHOT_DIR, snapshot_name=SNAPSHOT_NAME)
    return _attach_explanations(results)


@app.post("/api/upload")
async def upload_config(file: UploadFile) -> Dict[str, Any]:
    """Accept a config file, validating it before we do anything with it.

    Rejections come back as HTTP 400 with a message written for a person, not
    a stack trace -- "that file is 5.2 MB; the limit is 2 MB" rather than
    "413". The frontend shows the message verbatim.

    NOTE: this validates and reports. It does not yet persist the file or run
    the analysis -- that is the wire-up story. Two things must happen there,
    and both are easy to get wrong, so they are written down now:

      1. Write the file under a directory WE choose, using a filename WE
         generate. Never join a client-supplied name onto a path: `filename`
         below is used for display only, and is reduced to its basename first
         precisely so it can never walk out of a directory.
      2. Batfish expects device files one level down, in <snapshot>/configs/.
         See analysis.pipeline.load_snapshot, which fails loudly about this.
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

    # Check the recognised-but-unsupported list FIRST, so a PF Sense export
    # gets the explanation rather than the generic rejection.
    if extension in UNSUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}': {UNSUPPORTED_EXTENSIONS[extension]} "
                f"Cisco IOS configs ({allowed}) work today."
            ),
        )

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{display_name}' is not a config file we can read. "
                f"Netwise accepts {allowed} files."
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

    # --- Stage the file for analysis ---------------------------------------
    #
    # The previous upload is removed first, so a snapshot only ever contains
    # the config currently being analysed. Leaving an old device file behind
    # would silently mix two networks into one model.
    #
    # The filename is OURS ("device" plus the validated extension), never the
    # client's. display_name was already reduced to a basename above; this
    # means the client's string never reaches the filesystem at all.
    if CONFIGS_DIR.exists():
        shutil.rmtree(CONFIGS_DIR)
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    staged_path = CONFIGS_DIR / f"device{extension}"
    staged_path.write_bytes(bytes(contents))

    global _uploaded
    _uploaded = True

    return {
        "filename": display_name,
        "size_bytes": size,
        "accepted": True,
        # Uploading stages the file and stops there -- the analysis starts when
        # the user clicks Scan Now. So this says what has happened and what has
        # NOT: accepted and staged, nothing checked yet. It previously said
        # "Loading results now...", which was true when the upload triggered
        # the analysis itself and would now describe work nobody has started.
        #
        # Naming the button matters. "Staged for analysis" alone reads like
        # something is already underway, which is the impression this whole
        # flow change exists to remove.
        "message": (
            f"'{display_name}' accepted ({size:,} bytes) and staged. "
            "Nothing has been analysed yet — click Scan Now to check it."
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
    if not _uploaded:
        return {
            "question_understood": None,
            "answer": "Upload a config first, there is nothing to ask about yet.",
            "grounded": False,
        }

    try:
        bf = analysis_pipeline.connect()
        analysis_pipeline.load_snapshot(bf, SNAPSHOT_DIR, "netwise", SNAPSHOT_NAME)
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
