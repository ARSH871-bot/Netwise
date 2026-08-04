"""Make the repository root importable when the tests run.

WHY THIS FILE EXISTS
    Without it, `pytest tests/` fails with:

        ModuleNotFoundError: No module named 'analysis'

    ...even though `python -m pytest tests/` passes. The difference is not in
    pytest: `python -m pytest` puts the current directory on `sys.path`, and
    the bare `pytest` command does not. So `from analysis import findings` can
    only be resolved by one of them.

    That bit us in a way worth recording. Every local run used
    `python -m pytest`, so the suite looked fine, while CONTRIBUTING.md and
    README.md both told people to run `pytest tests/ -v` -- the form that does
    not work. Anyone following the documentation would have hit an import
    error on their first attempt and reasonably concluded the repo was broken.

    It was caught by the very first CI run, because a fresh Ubuntu machine has
    no reason to have the root on its path. That is exactly the class of
    problem CI is for: not the code being wrong, but the code depending on
    something about our own machines that we never noticed we relied on.

WHAT IT DOES
    pytest imports the root conftest.py before collecting anything, so putting
    the repo root on sys.path here fixes every test module at once. Doing it
    explicitly, rather than relying on pytest's own rootdir insertion, means
    the behaviour is visible to a reader instead of being a side effect of how
    pytest happens to be invoked.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
