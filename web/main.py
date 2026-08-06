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

import shutil
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ai.explain import explain
from analysis import pipeline as analysis_pipeline
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

    WHY ONLY status="found"
        A "none" finding has nothing to explain beyond its own summary,
        and an "error" finding has no real Batfish output to ground an
        explanation in -- asking the model to write prose about a check
        that never ran is the invented-network-behaviour failure
        CLAUDE.md constraint 2 forbids. static/app.js's rendering already
        encodes this same rule for which cards get the explanation slot
        at all; this keeps the two in agreement.

    WHY THE EXTRA try/except, WHEN explain() IS BUILT NOT TO RAISE
        ai/explain.py's own module docstring guarantees explain() never
        raises -- an unreachable Ollama, a model that was never built, or
        a malformed finding all degrade to deterministic fallback text
        internally (see _try_generate() and the thin-evidence guard).
        This except is a second, independent layer at a boundary this
        module does not own: if that guarantee is ever wrong, one
        explanation failing must not take down the WHOLE findings
        response. Same reasoning analysis.pipeline.run_check() already
        applies to one check's crash not being allowed to break the other
        three, one layer further out. No explanation is attached in that
        case -- the finding still renders, just without one, matching
        #31's acceptance criterion for an unreachable Ollama exactly.
    """
    for finding in results:
        if finding.get("status") != "found":
            continue
        try:
            finding["explanation"] = explain(finding)
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
        "message": (
            f"'{display_name}' accepted ({size:,} bytes) and staged for "
            "analysis. Refresh findings to see real results."
        ),
    }


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
