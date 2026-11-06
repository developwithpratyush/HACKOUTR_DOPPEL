"""The network circuit breaker (P14): if the internet drops mid-demo, Doppel keeps working from its caches.

Every outside call (CT logs, the vision model, the narration model) asks ``offline()`` first. It's true when
``DOPPEL_OFFLINE=1`` (the ``serve --offline`` switch), or for ``DOWN_FOR_S`` seconds after any call failed with a
*network* error (no DNS, refused, timed out). While it's true, every caller goes straight to its cache or its offline
fallback, so one dropped connection costs one failed call, not a 25-second stall per lookup. After the window
the next call tries the network again by itself: when the internet comes back, so does live lookup.

HTTP errors (401, 429, 503) are *not* network errors: the internet is fine, that one service isn't.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import urllib.error

DOWN_FOR_S = 90.0
log = logging.getLogger("doppel.net")
_lock = threading.Lock()
_until = 0.0
_why: str | None = None


def forced() -> bool:
    return os.environ.get("DOPPEL_OFFLINE", "0") not in ("", "0", "false", "False")


def down() -> bool:
    return time.time() < _until


def offline() -> bool:
    """Cache only right now: the offline switch, or the network failed in the last ``DOWN_FOR_S`` seconds."""
    return forced() or down()


def is_network_error(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):          # the server answered: the network is up
        return False
    if isinstance(exc, (OSError, TimeoutError, ConnectionError)):
        return True
    name = type(exc).__name__
    return any(k in name for k in ("Connect", "Timeout", "NetworkError")) and "Status" not in name


def mark_down(why: str) -> None:
    global _until, _why
    with _lock:
        first = not down()
        _until, _why = time.time() + DOWN_FOR_S, why[:200]
    if first:
        log.warning("network unreachable (%s): cache-only for %.0f s", why[:120], DOWN_FOR_S)


def mark_up() -> None:
    global _until, _why
    with _lock:
        _until, _why = 0.0, None


def state() -> dict:
    return {"forced_offline": forced(), "down": down(), "retry_in_s": max(0.0, round(_until - time.time(), 1)),
            "why": _why if down() else None}
