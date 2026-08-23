"""Shared pytest setup.

WHY THIS FILE EXISTS
    `web/main.py` grew a module-level explanation cache in #92. Module-level
    state survives a test, and the tests around `_attach_explanations()`
    build deliberately identical findings -- so without this fixture, a test
    can be served an explanation cached by an earlier one.

    Not a hypothetical. Measured by neutering the fixture and running the
    suite:

        with the fixture      407 passed
        fixture neutered      9 failed, 398 passed

    Four of the nine are in test_web_findings_explanation.py, which was
    written before the cache existed and tests the F-4-adjacent guarantees
    at this seam:

        test_a_failed_explanation_is_omitted_not_an_exception
        test_one_failed_explanation_does_not_affect_the_others
        test_the_finding_itself_is_unchanged_apart_from_the_new_keys
        test_a_fallback_explanation_reports_fallback_as_the_source

    That is the part worth reading twice. **The cache would have broken four
    existing safety tests belonging to a feature it was not touching**, and
    the failure would have looked like a bug in those tests rather than in
    the new code. An earlier draft of this docstring guessed at a different
    example entirely; the real list came from running it.

    A test that passes -- or fails -- because of another test is worse than
    one that simply fails. This clears the cache around every test so
    ordering cannot matter.
"""

import pytest


@pytest.fixture(autouse=True)
def _clear_web_caches():
    """Empty web.main's caches before and after every test.

    BOTH of them. #92b added a second module-level cache (the analysed
    findings list) and it has the same problem for the same reason -- a
    cached analysis surviving into another test would let one test's staged
    config answer another test's request.

    Resetting them is listed rather than discovered: a new cache added to
    web/main.py must be added here too, and the loop below fails loudly on
    a name that no longer exists rather than skipping it silently, so a
    rename cannot quietly stop clearing something.

    Imported lazily and guarded: `tests/` must stay runnable if the web
    layer is ever unimportable for an unrelated reason, rather than every
    test in the suite erroring at collection with a misleading message.

    Both sides, not just before: a test that leaves an entry behind should
    not be able to affect anything even if a later fixture fails to run.
    """
    try:
        from web import main as web_main
    except Exception:
        yield
        return

    resets = []
    for name in ("reset_explanation_cache", "reset_analysis_cache"):
        fn = getattr(web_main, name, None)
        assert fn is not None, (
            f"web.main.{name} is gone. If the cache was removed, delete it "
            f"from this list; if it was renamed, rename it here. Silently "
            f"skipping it would leave module state leaking between tests."
        )
        resets.append(fn)

    for reset in resets:
        reset()
    yield
    for reset in resets:
        reset()
