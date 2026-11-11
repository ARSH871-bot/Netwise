"""The upload size limit holds on the request BODY, not only on the parsed file.

WHAT WAS WRONG
    `MAX_UPLOAD_BYTES` (2 MB) is checked inside the three upload endpoints,
    `/api/upload`, `/api/policy` and `/api/business-context`. But FastAPI
    parses the whole multipart body before an endpoint runs, so the check
    only ever saw a file that had already arrived. Measured on 9 November
    against a real uvicorn: a 200 MB upload was received in full and spooled
    to a 200 MB temporary file before the 400 came back, on all three
    endpoints. A chunked body with no Content-Length did the same on 11
    November. The 400 and its message were right; the work before it was not.

WHAT THESE TESTS PIN
    How many body bytes the APP reads, counted at the ASGI receive channel
    rather than inferred from a temporary file. A 200 MB body may cost at
    most the limit, the 64 KB allowance and one chunk of this harness --
    with or without Content-Length. The answer itself must not change: the
    same 400 and the same message, byte for byte, written by the endpoint,
    and an extension refusal still wins over a size refusal for a file that
    is both.

    Two cases exist because a cut can go wrong in the dangerous direction.
    If the body is ended inside a SECOND part, or after headers too long for
    the allowance, closing the multipart cleanly would hand the endpoint a
    shortened file that is under the limit -- and it would be staged and
    scanned as if it were the user's config. Measured while writing this:
    a decoy part followed by a cut `file` part, closed cleanly, came back
    200 with a 112-byte file. So the cut may never end in a 200.

NO BATFISH, NO OLLAMA. Nothing here scans; uploads only stage.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Iterator, List, Optional, Tuple

import pytest

from web import main

MB = 1024 * 1024
LIMIT = 2 * MB
CHUNK = 64 * 1024
BOUNDARY = b"netwiseTestBoundary7f3a"
CRLF = b"\r\n"

# Written out, not read from web.main: a test that took the allowance from
# the module would grow with it, and "raise the allowance" would pass.
MOST_THE_APP_MAY_READ = LIMIT + 64 * 1024 + CHUNK

BIG = 200 * MB

ENDPOINTS = [
    (
        "/api/upload",
        "big.txt",
        "'big.txt' is larger than the 2 MB limit. Network configs are normally "
        "well under this -- is this definitely a config file?",
    ),
    (
        "/api/policy",
        "big.json",
        "'big.json' is larger than the 2 MB limit. A policy file is a short "
        "list of rules -- is this definitely a policy?",
    ),
    (
        "/api/business-context",
        "big.json",
        "'big.json' is larger than the 2 MB limit. A business context is a "
        "short list of assets -- is this definitely the right file?",
    ),
]


@pytest.fixture(autouse=True)
def remove_new_sessions():
    """Every request here arrives without a cookie, so each one is a new
    session with its own staging folder. Remove the ones this test made."""
    before = set(main.SESSIONS_ROOT.glob("*")) if main.SESSIONS_ROOT.exists() else set()
    yield
    if main.SESSIONS_ROOT.exists():
        for path in set(main.SESSIONS_ROOT.glob("*")) - before:
            shutil.rmtree(path, ignore_errors=True)


# --- A request driven straight through the ASGI app --------------------------


def part_head(filename: str, name: str = "file", extra_header: bytes = b"") -> bytes:
    return (
        b"--" + BOUNDARY + CRLF
        + b'Content-Disposition: form-data; name="' + name.encode()
        + b'"; filename="' + filename.encode() + b'"' + CRLF
        + extra_header
        + b"Content-Type: application/octet-stream" + CRLF + CRLF
    )


CLOSING = CRLF + b"--" + BOUNDARY + b"--" + CRLF


def file_bytes(size: int, fill: bytes = b"hostname r1\n") -> Iterator[bytes]:
    """`size` bytes of config-shaped text, in CHUNK pieces, without ever
    holding more than one chunk -- a 200 MB body costs this test nothing."""
    block = (fill * (CHUNK // len(fill) + 1))[:CHUNK]
    left = size
    while left > 0:
        yield block[: min(CHUNK, left)]
        left -= min(CHUNK, left)


def one_file_body(filename: str, size: int, fill: bytes = b"hostname r1\n") -> Iterator[bytes]:
    yield part_head(filename)
    yield from file_bytes(size, fill)
    yield CLOSING


def rechunk(pieces: Iterator[bytes], size: int) -> Iterator[bytes]:
    """The same bytes in pieces of exactly `size`, so a cut can be made to
    land on any byte, not only on a chunk edge."""
    pending = b""
    for piece in pieces:
        pending += piece
        while len(pending) >= size:
            yield pending[:size]
            pending = pending[size:]
    if pending:
        yield pending


class Result:
    def __init__(self, status: int, headers: List[Tuple[bytes, bytes]], body: bytes, read: int):
        self.status = status
        self.headers = headers
        self.body = body
        self.read = read

    @property
    def detail(self) -> Optional[str]:
        try:
            return json.loads(self.body).get("detail")
        except (ValueError, AttributeError):
            return None

    def header(self, name: bytes) -> List[bytes]:
        return [v for k, v in self.headers if k.lower() == name]


def post(
    path: str,
    pieces: Iterator[bytes],
    *,
    content_length: Optional[int] = None,
    method: str = "POST",
    content_type: bytes = b"multipart/form-data; boundary=" + BOUNDARY,
    app=None,
) -> Result:
    """One request through `main.app` (or `app`) over plain ASGI.

    Counts every body byte the application pulls from `receive`, which is
    the number a server would actually have to take off the network. Once
    the body is exhausted, `receive` behaves like uvicorn's: it waits until
    the response is complete and then reports a disconnect.
    """
    sent: List[dict] = []
    read = 0

    async def run() -> None:
        nonlocal read
        finished = asyncio.Event()
        source = iter(pieces)
        nxt = next(source, None)

        async def receive() -> dict:
            nonlocal nxt, read
            if nxt is None:
                await finished.wait()
                return {"type": "http.disconnect"}
            piece, nxt = nxt, next(source, None)
            read += len(piece)
            return {"type": "http.request", "body": piece, "more_body": nxt is not None}

        async def send(message: dict) -> None:
            sent.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                finished.set()

        headers = [(b"host", b"testserver"), (b"content-type", content_type)]
        if content_length is not None:
            headers.append((b"content-length", str(content_length).encode()))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
        }
        await (app or main.app)(scope, receive, send)

    asyncio.run(run())
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return Result(start["status"], start.get("headers", []), body, read)


def length_of(filename: str, size: int) -> int:
    return len(part_head(filename)) + size + len(CLOSING)


# --- A 200 MB body costs about the limit, not 200 MB -------------------------


@pytest.mark.parametrize("path, filename, message", ENDPOINTS)
def test_a_200_mb_body_with_content_length_is_read_only_to_about_the_limit(path, filename, message):
    r = post(path, one_file_body(filename, BIG), content_length=length_of(filename, BIG))

    assert r.read <= MOST_THE_APP_MAY_READ, f"the app read {r.read:,} bytes of a 200 MB body"
    assert r.status == 400
    assert r.detail == message


@pytest.mark.parametrize("path, filename, message", ENDPOINTS)
def test_a_200_mb_chunked_body_with_no_content_length_is_read_only_to_about_the_limit(
    path, filename, message
):
    r = post(path, one_file_body(filename, BIG), content_length=None)

    assert r.read <= MOST_THE_APP_MAY_READ, f"the app read {r.read:,} bytes of a 200 MB body"
    assert r.status == 400
    assert r.detail == message


# --- Uploads at the limit behave exactly as today ----------------------------

AT_LIMIT = [
    ("/api/upload", "r1.txt", b"hostname r1\n", None),
    # A policy and a business context must also be VALID to be accepted, so
    # these are `{}` and `[]` padded with JSON whitespace to the exact size.
    ("/api/policy", "p.json", None, (b"{", b"}")),
    ("/api/business-context", "b.json", None, (b"[", b"]")),
]


def at_size(filename: str, size: int, fill: Optional[bytes], brackets) -> Iterator[bytes]:
    if fill is not None:
        yield from one_file_body(filename, size, fill)
        return
    yield part_head(filename) + brackets[0]
    yield from file_bytes(size - 2, b" ")
    yield brackets[1] + CLOSING


@pytest.mark.parametrize("path, filename, fill, brackets", AT_LIMIT)
@pytest.mark.parametrize("size", [LIMIT - 1, LIMIT])
@pytest.mark.parametrize("chunked", [False, True])
def test_an_upload_at_or_just_under_the_limit_is_still_accepted(path, filename, fill, brackets, size, chunked):
    length = None if chunked else length_of(filename, size)
    r = post(path, at_size(filename, size, fill, brackets), content_length=length)

    assert r.status == 200, r.body[:300]
    assert json.loads(r.body)["size_bytes"] == size
    assert r.read == length_of(filename, size)


@pytest.mark.parametrize("path, filename, message", ENDPOINTS)
def test_an_upload_one_byte_over_the_limit_is_refused_with_the_same_message(path, filename, message):
    size = LIMIT + 1
    r = post(path, one_file_body(filename, size), content_length=length_of(filename, size))

    assert r.status == 400
    assert r.detail == message


# --- A cut must never become a 500, or a shortened file accepted -------------


def test_a_cut_at_any_offset_near_the_part_headers_is_a_refusal_not_a_500(monkeypatch):
    """With the limit forced to 0, the cut falls at `allowance` bytes in.
    Walking the allowance across the opening boundary, the header lines, the
    blank line and the first data bytes puts the cut inside each of them."""
    body = b"".join(one_file_body("r1.txt", 200))
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 0)

    outcomes = {}
    for offset in range(0, len(part_head("r1.txt")) + 8):
        monkeypatch.setattr(main, "UPLOAD_ALLOWANCE_BYTES", offset, raising=False)
        for piece in (1, 7, CHUNK):
            r = post("/api/upload", rechunk(iter([body]), piece), content_length=len(body))
            outcomes[(offset, piece)] = r.status

    assert all(status in (400, 422) for status in outcomes.values()), {
        k: v for k, v in outcomes.items() if v not in (400, 422)
    }


def test_a_cut_inside_a_second_part_never_stages_a_shortened_file():
    """A decoy file part first, then the real `file` part: the cut lands in
    the second. Closing the multipart there would hand the endpoint a file
    under the limit, missing its end, and it would be accepted. If anything
    is accepted, it must be the whole file."""
    def body() -> Iterator[bytes]:
        yield part_head("decoy.bin", name="other")
        yield from file_bytes(1_500_000)
        yield CRLF + part_head("r1.txt")
        yield from file_bytes(1 * MB)
        yield CLOSING

    r = post("/api/upload", body(), content_length=sum(len(p) for p in body()))

    if r.status == 200:
        assert json.loads(r.body)["size_bytes"] == 1 * MB
    else:
        assert r.status in (400, 422), r.body[:300]


def test_part_headers_longer_than_the_allowance_never_stage_a_shortened_file():
    """One part whose headers alone are over 64 KB: the file data reaching the
    cut would be under the limit, so a clean close would accept it shortened.
    If anything is accepted, it must be the whole file."""
    data_size = LIMIT - 10_000
    pad = b"X-Pad: " + b"a" * (70 * 1024) + CRLF

    def body() -> Iterator[bytes]:
        yield part_head("r1.txt", extra_header=pad)
        yield from file_bytes(data_size)
        yield CLOSING

    r = post("/api/upload", body(), content_length=sum(len(p) for p in body()))

    if r.status == 200:
        assert json.loads(r.body)["size_bytes"] == data_size
    else:
        assert r.status in (400, 422), r.body[:300]


# --- What the endpoint decides first still decides ---------------------------

WRONG_EXTENSION = [
    (
        "/api/upload",
        "big.exe",
        "'big.exe' is not a config file we can read. Netwise accepts",
    ),
    ("/api/policy", "big.txt", "'big.txt' is not a policy file Netwise can read."),
    ("/api/business-context", "big.txt", "'big.txt' is not a business context Netwise can read."),
]


@pytest.mark.parametrize("path, filename, starts", WRONG_EXTENSION)
def test_a_200_mb_file_with_the_wrong_extension_still_gets_the_extension_message(path, filename, starts):
    r = post(path, one_file_body(filename, BIG), content_length=length_of(filename, BIG))

    assert r.status == 400
    assert r.detail.startswith(starts), r.detail
    assert "larger than" not in r.detail
    assert r.read <= MOST_THE_APP_MAY_READ


def test_a_first_request_cut_at_the_limit_still_gets_its_session_cookie():
    r = post("/api/upload", one_file_body("big.txt", BIG), content_length=length_of("big.txt", BIG))

    cookies = r.header(b"set-cookie")
    assert any(c.startswith(b"netwise_session=") for c in cookies), cookies


# --- Everything else is untouched --------------------------------------------


def test_a_large_body_to_another_post_endpoint_is_read_in_full():
    """`/api/ask` takes a JSON body. It is not an upload, so it is not cut:
    every byte the client sends reaches the app, as today."""
    payload = json.dumps({"question": "x" * (3 * MB)}).encode()
    r = post(
        "/api/ask",
        rechunk(iter([payload]), CHUNK),
        content_length=len(payload),
        content_type=b"application/json",
    )

    assert r.read == len(payload)
    assert r.status != 500


@pytest.mark.parametrize(
    "scope_type, method, path",
    [
        ("http", "GET", "/api/upload"),
        ("http", "POST", "/api/findings"),
        ("http", "POST", "/api/ask"),
        ("http", "PUT", "/api/policy"),
        ("http", "POST", "/api/upload/extra"),
        ("websocket", "GET", "/api/upload"),
        ("lifespan", None, None),
    ],
)
def test_the_limit_hands_every_other_request_through_unchanged(scope_type, method, path):
    """The middleware must pass the server's own `receive` and `send` on,
    untouched, to anything that is not a POST to one of the three uploads."""
    seen = {}

    async def inner(scope, receive, send):
        seen["receive"], seen["send"] = receive, send

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        pass

    scope = {"type": scope_type}
    if method:
        scope.update(method=method, path=path, headers=[])
    asyncio.run(main.UploadBodyLimit(inner)(scope, receive, send))

    assert seen["receive"] is receive
    assert seen["send"] is send
