"""Netwise -- per-session identity, so two users cannot see each other's scan.

WHY THIS EXISTS (#242)
    Every piece of upload state in `web/main.py` was one module-level value:
    one staged config directory, one `_uploaded` flag, one analysis cache.
    That is only defensible for a single-user local tool, and `main.py`'s own
    comment said so:

        "Module-level state is only defensible because this is a single-user
         local tool. Two people uploading at once would overwrite each
         other's snapshot."

    This gives each browser its own identity, so that sentence stops being a
    caveat and starts being false.

WHY ContextVar AND NOT threading.local()
    Decided on #243 before either half was built, rather than discovered
    halfway through.

    `threading.local()` isolates a THREAD. That is enough for the policy
    loader (#181), because `/api/findings` is a sync endpoint and therefore
    runs in the threadpool. It is not enough here:

      - `upload_config`, `upload_policy` and `upload_business_context` are
        all `async def`, so they run on the event loop. Many requests share
        one thread there, and `threading.local()` would hand them all the
        same slot -- the exact bug this module exists to prevent, in the
        three endpoints that write the state.

      - A session outlives a single thread by definition. Keying identity to
        a thread would make the identity wrong as soon as anything moved
        between them.

    `ContextVar` is correct for both: asyncio gives each task its own
    context, and Starlette's threadpool copies the context into the worker
    thread, so a sync endpoint sees the value its middleware set.

WHAT A SESSION IS, AND WHAT IT IS NOT
    A random id in a cookie. It is NOT authentication, and nothing here
    claims otherwise -- anyone who copies the cookie gets the session. It
    separates concurrent users from each other; it does not defend one
    against another who is trying. Netwise runs offline and locally, so
    that is the honest scope, and widening it would need a real login story
    rather than a longer token.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar

#: The cookie the browser carries. Named rather than generic so it is
#: obvious in devtools which tool set it.
SESSION_COOKIE = "netwise_session"

#: How long a browser keeps it. A working day: long enough that refreshing
#: the page or coming back after lunch keeps your scan, short enough that a
#: shared machine does not carry one person's session into the next week.
SESSION_MAX_AGE = 8 * 60 * 60

#: Used when there is NO request in flight -- the CLI entry points, a direct
#: import, and any test that calls a helper without going through the app.
#: Those callers are genuinely single-session, and giving them a stable name
#: keeps their behaviour byte-for-byte what it was before this module.
DEFAULT_SESSION = "default"

#: The current request's session. A ContextVar, so asyncio tasks and
#: threadpool workers each see their own value -- see the module docstring.
_current_session: ContextVar[str] = ContextVar(
    "netwise_session_id", default=DEFAULT_SESSION
)


def new_session_id() -> str:
    """A fresh, unguessable session id.

    `token_urlsafe` rather than a counter or a uuid4 hex: it is
    cryptographically random, and it is safe in both a cookie value and a
    directory name without escaping, which is the second place it is about
    to be used.
    """
    return secrets.token_urlsafe(16)


def current_session_id() -> str:
    """The session this request belongs to, or DEFAULT_SESSION outside one."""
    return _current_session.get()


def set_current_session(session_id: str):
    """Install the session for this context. Returns the reset token."""
    return _current_session.set(session_id)


def reset_current_session(token) -> None:
    """Undo `set_current_session`, restoring whatever was there before.

    Paired with the token rather than setting DEFAULT_SESSION back, so
    nesting cannot silently lose an outer value.
    """
    _current_session.reset(token)


def is_valid_session_id(candidate: object) -> bool:
    """Is this something we issued, shaped like it at least?

    THIS IS A PATH-SAFETY CHECK, NOT AN AUTHENTICATION CHECK.
        The session id becomes a DIRECTORY NAME. A cookie is client-supplied
        text, so a browser -- or anything pretending to be one -- can send
        `../../etc` and would otherwise get it joined onto a path we own.

        So the rule is a whitelist, not a blacklist: url-safe base64
        characters only, bounded length. `..` fails it because `.` is not in
        the set, and every separator fails it for the same reason. Anything
        that does not match is not repaired or escaped -- it is discarded
        and a fresh id is issued, because a malformed cookie is not
        something to negotiate with.
    """
    if not isinstance(candidate, str):
        return False
    if not 16 <= len(candidate) <= 64:
        return False
    return all(c.isalnum() or c in "-_" for c in candidate)
