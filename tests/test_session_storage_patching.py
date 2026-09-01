"""A fixture must not redirect storage by setting a module attribute (#242).

WHY THIS GUARD EXISTS
    Before #242, `web/main.py` exposed the staged-file locations as module
    constants, and fixtures redirected them the obvious way:

        monkeypatch.setattr(main, "CONFIGS_DIR", tmp_path / "configs")

    Storage is per session now, so request handlers call `configs_dir()`,
    which resolves through a ContextVar. The old names survive only as a
    PEP 562 `__getattr__` compatibility shim for reading -- and a module
    `__getattr__` is NOT consulted when a real attribute exists. So
    `setattr` shadows the shim, the handler never looks at it, and the
    fixture redirects nothing while appearing to redirect everything.

    That is a fixture which isolates nothing and still passes, which is the
    false-pass shape this project keeps finding.

WHY A GUARD AND NOT JUST THE THREE FIXES
    #242 found and fixed two instances. A third arrived four days later in
    #271, written against `main` before #242 merged, and took `main` red:

        16 failed, 1059 passed

    Both branches were green. The combination was not, and nothing warned
    anybody -- the pattern still LOOKS correct, which is exactly why it
    keeps being written.

    Fixing instances is what #172 got wrong and `test_tools_invocation.py`
    later fixed properly by enforcing the property across the folder. This
    is that, for this property: the next fixture to reach for the old name
    fails on the day it lands, with a message saying what to write instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent

#: The names that became session-scoped in #242. Reading them still works,
#: via the shim; PATCHING them does not.
SHADOWED_NAMES = (
    "SNAPSHOT_DIR",
    "CONFIGS_DIR",
    "POLICY_PATH",
    "BUSINESS_CONTEXT_PATH",
)

#: The function to patch instead of each constant.
REPLACEMENTS = {
    "SNAPSHOT_DIR": "snapshot_dir",
    "CONFIGS_DIR": "configs_dir",
    "POLICY_PATH": "policy_path",
    "BUSINESS_CONTEXT_PATH": "business_context_path",
}

_PATTERN = re.compile(
    r"""setattr\(\s*(?:web_?)?main\s*,\s*["'](""" + "|".join(SHADOWED_NAMES) + r""")["']"""
)


def _test_files():
    return sorted(p for p in TESTS_DIR.glob("test_*.py") if p.name != Path(__file__).name)


@pytest.mark.parametrize("path", _test_files(), ids=lambda p: p.name)
def test_no_fixture_patches_a_session_scoped_module_attribute(path: Path):
    """Patching the old constant is silently ignored -- patch the function.

    This is a static check on purpose. The runtime symptom is a fixture that
    passes while isolating nothing, so there is no failure to observe until
    something else breaks, somewhere else, for a reason that looks unrelated.
    """
    source = path.read_text(encoding="utf-8")
    offenders = []
    for number, line in enumerate(source.splitlines(), start=1):
        match = _PATTERN.search(line)
        if match:
            name = match.group(1)
            offenders.append(
                f"{path.name}:{number} patches {name} -- "
                f"patch main.{REPLACEMENTS[name]} instead"
            )

    assert not offenders, (
        "these fixtures redirect storage by setting a module attribute, which "
        "web/main.py's PEP 562 __getattr__ shim does NOT intercept, so the "
        "redirect silently does nothing:\n  "
        + "\n  ".join(offenders)
        + "\n\nWrite it as, for example:\n"
        "    monkeypatch.setattr(\n"
        "        main, 'configs_dir', lambda session_id=None: tmp_path / 'configs'\n"
        "    )"
    )


def test_the_replacement_functions_actually_exist():
    """Otherwise the advice in the message above is wrong, and a reader
    following it would be sent somewhere that does not exist."""
    from web import main

    for constant, function in REPLACEMENTS.items():
        assert callable(getattr(main, function, None)), (
            f"main.{function} is gone -- this guard tells people to patch it "
            f"instead of {constant}, so the advice must stay true"
        )


def test_reading_the_old_names_still_works():
    """The shim is for READING, and that half is deliberately kept -- dozens
    of assertions across the suite use it. Only patching is the problem."""
    from web import main

    for name in SHADOWED_NAMES:
        assert isinstance(getattr(main, name), Path)
