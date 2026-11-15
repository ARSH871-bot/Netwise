"""A refused policy or business-context upload never shows the server's
temp file path.

WHAT THIS PINS
    /api/policy and /api/business-context save the upload to a temp file and
    hand that path to the loader (analysis/policy.py, analysis/
    business_context.py), whose refusals for an unreadable file start with
    the path: "C:\\Users\\<name>\\AppData\\Local\\Temp\\tmpab12cd.json is not
    valid JSON: ...". The endpoint returned that text as the 400 detail, so
    the user saw a server folder, including the Windows user name, instead
    of the name of the file they chose. Measured on main for four kinds of
    bad file on both endpoints: invalid JSON, an integer of 5,000 digits,
    nesting 100,000 deep, and bytes that are not UTF-8.

    The refusal must name the file the user uploaded and keep the loader's
    reason, word for word, without the path.

HOW THE PATH IS MADE RECOGNISABLE
    tempfile.tempdir is pointed at a folder whose name is a canary and
    contains a backslash, so the path is distinctive on every OS and its
    repr() spelling (backslashes doubled) differs from its plain one, on
    CI's Linux as well as on Windows.

NO BATFISH, NO OLLAMA -- the loaders refuse before anything is staged.
"""

import re
import tempfile

import pytest
from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)

CANARY = "netwise-temp-canary"


@pytest.fixture(autouse=True)
def canary_tempdir(tmp_path, monkeypatch):
    """Every temp file the endpoints make lands under a canary folder."""
    folder = tmp_path / (CANARY + "\\x")
    folder.mkdir(parents=True)
    monkeypatch.setattr(tempfile, "tempdir", str(folder))
    return folder


def _assert_no_server_path(detail: str, folder) -> None:
    for spelling in (str(folder), str(folder).replace("\\", "\\\\"), CANARY):
        assert spelling not in detail, f"the server's temp folder is in the refusal: {detail!r}"
    assert "AppData" not in detail, f"a Windows profile folder is in the refusal: {detail!r}"
    assert "Users" not in detail, f"a user folder is in the refusal: {detail!r}"
    assert not re.search(r"\b[A-Za-z]:[\\/]", detail), f"a drive-letter path is in the refusal: {detail!r}"


DEEP = b"[" * 100000 + b"]" * 100000

BAD_FILES = [
    ("/api/policy", "my-policy.json", b'{"policy_compliance": [ }', "is not valid JSON: line 1, column 25"),
    ("/api/policy", "my-policy.json", b'{"policy_compliance": [{"number": ' + b"9" * 5000 + b"}]}",
     "holds a value that cannot be read: Exceeds the limit (4300 digits)"),
    ("/api/policy", "my-policy.json", DEEP, "is nested too deeply to be a policy"),
    ("/api/policy", "my-policy.json", b'{"policy_compliance": [\xff]}', "is not UTF-8 text: byte 23"),
    ("/api/business-context", "assets.json", b'[{"device": }', "is not valid JSON: line 1, column 13"),
    ("/api/business-context", "assets.json", b'[{"device": "r", "tier": "critical", "n": ' + b"9" * 5000 + b"}]",
     "holds a value that cannot be read: Exceeds the limit (4300 digits)"),
    ("/api/business-context", "assets.json", DEEP, "is nested too deeply to be a business context"),
    ("/api/business-context", "assets.json", b'[{"device": "\xff"}]', "is not UTF-8 text: byte 13"),
]


@pytest.mark.parametrize("url, name, body, reason", BAD_FILES,
                         ids=[f"{u.rsplit('/', 1)[1]}-{r.split(':')[0][:20]}" for u, _, _, r in BAD_FILES])
def test_a_refusal_names_the_uploaded_file_not_the_temp_path(canary_tempdir, url, name, body, reason):
    response = client.post(url, files={"file": (name, body, "application/json")})

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    _assert_no_server_path(detail, canary_tempdir)
    assert f"'{name}'" in detail, f"the refusal does not name the uploaded file: {detail!r}"
    assert reason in detail, f"the loader's reason was lost: {detail!r}"


@pytest.mark.parametrize("url, loader_name, error_name, name", [
    ("/api/policy", "load_policy_file", "PolicyError", "my-policy.json"),
    ("/api/business-context", "load_business_context_file", "BusinessContextError", "assets.json"),
])
def test_a_path_quoted_with_doubled_backslashes_is_hidden_too(canary_tempdir, monkeypatch, url, loader_name,
                                                              error_name, name):
    """An OSError formats its filename with repr(), which doubles every
    backslash (found by Arsh on #463 in change impact). A refusal quoting
    the path that way must be cleaned too, in both spellings at once."""
    error_type = getattr(main, error_name)

    def refuse(path):
        raise error_type(f"{path} could not be read: [Errno 13] Permission denied: {str(path)!r}")

    monkeypatch.setattr(main, loader_name, refuse)
    response = client.post(url, files={"file": (name, b"[]", "application/json")})

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    _assert_no_server_path(detail, canary_tempdir)
    assert detail.count(f"'{name}'") == 2, f"both quotes of the path should name the file: {detail!r}"
    assert "[Errno 13] Permission denied" in detail, detail


def test_a_path_named_twice_is_hidden_both_times(canary_tempdir, monkeypatch):
    """Every occurrence is replaced, not only the first: a refusal can name
    the file twice in the same spelling. Replacing only the first left the
    second path in place and passed every other test here."""
    def refuse(path):
        raise main.PolicyError(f"{path} is not valid JSON, so {path} was not loaded")

    monkeypatch.setattr(main, "load_policy_file", refuse)
    response = client.post("/api/policy", files={"file": ("my-policy.json", b"{}", "application/json")})

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    _assert_no_server_path(detail, canary_tempdir)
    assert detail == "'my-policy.json' is not valid JSON, so 'my-policy.json' was not loaded", detail


def test_a_refusal_that_never_named_a_path_is_unchanged():
    """The control: a refusal with no path in it keeps exactly its words."""
    body = b'{"policy_compliance": [], "policy_compliance": []}'
    response = client.post("/api/policy", files={"file": ("my-policy.json", body, "application/json")})

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "the key 'policy_compliance' appears twice in one object. JSON keeps only "
        "the last, so the first would be silently ignored"
    )


@pytest.mark.parametrize("url, name, body", [
    ("/api/policy", "my-policy.json", b"{}"),
    ("/api/business-context", "assets.json", b"[]"),
])
def test_a_good_upload_is_unchanged(url, name, body):
    response = client.post(url, files={"file": (name, body, "application/json")})

    assert response.status_code == 200, response.text
    assert response.json()["filename"] == name
