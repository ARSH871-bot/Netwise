"""Netwise -- Layer 3, the web backend.

RUN IT
    pip install -r requirements.txt
    uvicorn web.main:app --reload
    open http://127.0.0.1:8000          (API docs at /docs)

Run from the repository root, so `analysis` and `web` both import.

WHAT THIS SERVES TODAY
    Mock F-1 findings, from web/mock_findings.py. The analysis pipeline is NOT
    wired in yet -- that is deliberate, and marked with a single TODO below.
    The dashboard is being built first, against the shape the pipeline already
    returns, so the two can be joined by changing one function.

THE SEAM
    analysis.pipeline.analyse(config_dir) -> list[dict] is the whole backend
    API. It already returns the F-1 list this file hands to the frontend, and
    it does not raise for operational failures -- an unreachable Batfish or an
    unparseable config come back AS findings with status="error". So wiring it
    up is a substitution, not a redesign, and the error path needs no extra
    code here: it is already findings the dashboard knows how to render.
"""

from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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


@app.get("/api/findings")
def get_findings() -> List[Dict[str, Any]]:
    """Return the current findings, in the F-1 format.

    Today these are mocks. The response SHAPE is the real contract, so the
    frontend built against it will not change when the pipeline is wired in.

    TODO (wire-up story): replace the return below with
        return analysis.pipeline.analyse(uploaded_config_dir)
    That function already returns this exact shape, including status="error"
    findings when it cannot run at all.
    """
    return mock_findings.get_mock_findings()


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
    # trusting a Content-Length header the client controls.
    size = 0
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

    if size == 0:
        raise HTTPException(
            status_code=400, detail=f"'{display_name}' is empty."
        )

    return {
        "filename": display_name,
        "size_bytes": size,
        "accepted": True,
        # Said plainly so the dashboard never implies an analysis has happened.
        "message": (
            f"'{display_name}' accepted ({size:,} bytes). Analysis is not "
            "connected yet -- the findings below are sample data."
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
