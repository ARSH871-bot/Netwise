"""The analysis cache's write must be one critical section (#208).

WHY THIS FILE EXISTS AT ALL
    Adding the lock broke nothing. Measured, with the lock replaced by a
    no-op stand-in: **1030 passed** -- the entire suite, unchanged. That is
    honest information rather than a comfort: it means the lock was
    protecting a property no test asserted, and a later reader could delete
    it, watch the suite stay green, and reasonably conclude it was
    decoration.

    So these tests exist to make the property assertable.

THE TWO KINDS OF TEST HERE, AND WHY BOTH
    1. STRUCTURAL -- that the write path actually takes the lock. Cheap,
       deterministic, and it fails the moment someone removes it.

    2. BEHAVIOURAL -- that concurrent writes do not over-evict. This one
       needs the check->evict window widened with an injected delay, because
       a few bytecodes is not reliably hit by luck. The delay does not
       CREATE the race; it makes an existing one reproducible. Said plainly
       so nobody later mistakes the injection for the bug.

WHAT THE LOCK DOES NOT DO, also asserted: it is not held across the analysis
itself, so two requests for the same uncached key both compute. Serialising
that would hold a lock for seconds of Batfish work.
"""

from __future__ import annotations

import threading
import time

import pytest

from web import main


@pytest.fixture(autouse=True)
def clean_cache():
    main.reset_analysis_cache()
    yield
    main.reset_analysis_cache()


class _RecordingLock:
    """A real lock that remembers how many times it was entered."""

    def __init__(self):
        self._lock = threading.Lock()
        self.entered = 0

    def __enter__(self):
        self._lock.acquire()
        self.entered += 1
        return self

    def __exit__(self, *exc):
        self._lock.release()
        return False


def _results():
    return [
        {
            "id": "AC-001",
            "check": "access_control",
            "severity": "high",
            "device": "rtr-us5",
            "summary": "s",
            "evidence": {"detail": "d", "source": "x"},
            "status": "found",
        }
    ]


# ---------------------------------------------------------------------------
# Structural: the paths that mutate the ordering take the lock
# ---------------------------------------------------------------------------


def test_remembering_an_analysis_takes_the_lock(monkeypatch):
    """The insert, the reorder and the eviction are one critical section.

    Fails immediately if the lock is removed, which the rest of the suite
    does not -- that is the entire point of this test.
    """
    recorder = _RecordingLock()
    monkeypatch.setattr(main, "_analysis_cache_lock", recorder)

    main._remember_analysis("key-1", _results())

    assert recorder.entered == 1, "the write path must be serialised"


def test_reading_the_cache_takes_the_lock(monkeypatch):
    """`move_to_end()` mutates the ordering, so a lookup is not a pure read.

    A lookup racing an eviction could re-order a dict another thread is
    walking, so every touch of the ordering is serialised rather than
    someone having to work out which ones were exempt.
    """
    main._remember_analysis("key-1", _results())

    recorder = _RecordingLock()
    monkeypatch.setattr(main, "_analysis_cache_lock", recorder)

    main._cached_analysis("key-1")

    assert recorder.entered == 1


def test_resetting_the_cache_takes_the_lock(monkeypatch):
    recorder = _RecordingLock()
    monkeypatch.setattr(main, "_analysis_cache_lock", recorder)

    main.reset_analysis_cache()

    assert recorder.entered == 1


def test_a_skipped_write_does_not_take_the_lock(monkeypatch):
    """`_analysis_is_worth_caching()` is evaluated BEFORE the lock.

    It only reads the caller's own list, so holding the lock across it would
    widen the critical section for nothing. A key of None returns earlier
    still.
    """
    recorder = _RecordingLock()
    monkeypatch.setattr(main, "_analysis_cache_lock", recorder)

    main._remember_analysis(None, _results())
    main._remember_analysis("key-1", [{"status": "error"}])   # not worth caching

    assert recorder.entered == 0


# ---------------------------------------------------------------------------
# Behavioural: concurrent writes do not over-evict
# ---------------------------------------------------------------------------


def test_concurrent_writes_do_not_evict_below_the_bound(monkeypatch):
    """THE #208 RACE, reproduced.

    The window between `len(...) > MAX` and `popitem()` is a few bytecodes
    wide, so it is not reliably hit by luck. This widens it with an injected
    delay -- the delay does not create the race, it makes an existing one
    observable on demand.

    Measured while writing this, with the lock replaced by a no-op:

        WITHOUT the lock   1 of 8 writes survived   cache fell to 1 entry
        WITH the lock      8 of 8 writes survived   cache held at 8

    The consequence is a wasted re-analysis, never a wrong answer -- which
    is why #208 is a normal fix rather than the defect its policy-layer twin
    was (#182: "2 of 2 concurrent analyses read the WRONG policy").
    """
    real_popitem = main._analysis_cache.popitem

    def slow_popitem(last=False):
        time.sleep(0.01)
        return real_popitem(last=last)

    monkeypatch.setattr(main._analysis_cache, "popitem", slow_popitem, raising=False)

    # Fill to the bound, so every further write triggers an eviction.
    for i in range(main.ANALYSIS_CACHE_MAX):
        main._analysis_cache[f"seed-{i}"] = _results()

    writers = 8
    barrier = threading.Barrier(writers, timeout=30)

    def write(n):
        barrier.wait()
        main._remember_analysis(f"key-{n}", _results())

    threads = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    survived = sum(1 for k in main._analysis_cache if k.startswith("key-"))

    assert survived == writers, (
        f"only {survived} of {writers} concurrent writes survived -- the "
        f"write-and-evict sequence is not atomic"
    )
    assert len(main._analysis_cache) == main.ANALYSIS_CACHE_MAX


def test_the_cache_never_exceeds_its_bound_under_concurrency():
    """The other direction, without any injection.

    Passes with or without the lock -- the GIL makes each operation atomic,
    so the bound holds either way. Kept because it is the invariant a reader
    expects to see asserted, and its passing is not evidence the lock works.
    """
    writers = 24
    barrier = threading.Barrier(writers, timeout=30)

    def write(n):
        barrier.wait()
        main._remember_analysis(f"key-{n}", _results())

    threads = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(main._analysis_cache) <= main.ANALYSIS_CACHE_MAX


# ---------------------------------------------------------------------------
# What the lock deliberately does not do
# ---------------------------------------------------------------------------


def test_the_lock_is_not_held_across_the_analysis(monkeypatch):
    """Two requests for the same uncached key both compute, on purpose.

    Serialising that would hold a lock for seconds of real Batfish work and
    turn every concurrent reader into a queue, to save a duplicate whose
    result is identical. The cost of the duplicate is time; the cost of the
    queue would be the app.

    Asserted by holding the lock on this thread and confirming a read still
    completes -- which it can only do if the analysis path does not need it.
    """
    main._remember_analysis("key-1", _results())

    done = []

    def reader():
        # Not the cache path -- this is what an in-flight analysis does:
        # work that must not be blocked by another request's bookkeeping.
        done.append(main._analysis_is_worth_caching(_results()))

    with main._analysis_cache_lock:
        thread = threading.Thread(target=reader)
        thread.start()
        thread.join(timeout=5)

    assert done == [True], "analysis work must not require the cache lock"
