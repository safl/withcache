"""A tiny client for consuming a withcache cache-host from other tools.

Lets a consumer (e.g. bty) point downloads at withcache without re-implementing
the ``/b/`` URL scheme. Stdlib only, so importing it pulls in no third-party
dependencies.

    from withcache import client

    # "use the cache when it's warm, the origin otherwise"
    url = client.serve_url("http://cache:3000", origin) or origin

The ``/b/<urlsafe-b64(origin)>/<basename>`` encoding is shared with the shims
and the server (one definition in :mod:`withcache._shim`), so consumers stay in
lockstep with the cache-host automatically.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from . import _shim

__all__ = ["PROBE_TIMEOUT", "blob_url", "cache_base", "is_cached", "serve_url"]

PROBE_TIMEOUT = 3.0  # seconds; never block the caller on a slow/unreachable cache

#: Normalize a server value: accepts 'host', 'host:3000', or 'http://host:3000'.
cache_base = _shim.cache_base


def blob_url(server: str, origin: str) -> str:
    """The cache-host serve URL for ``origin``:
    ``<server>/b/<urlsafe-b64(origin), unpadded>/<basename>``. The trailing
    basename is cosmetic (so any downloader names the saved file after the
    artifact); the cache keys on the decoded origin URL."""
    return _shim.blob_url(_shim.cache_base(server), origin)


def is_cached(server: str, origin: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """True if the cache-host already holds ``origin`` (a ``HEAD`` on ``/b/``
    returns 200). A miss (404), an unreachable host, a timeout, or any error
    returns False, so a caller can safely fall back to the origin. The HEAD
    also *warms* an auto-fetch cache-host: the miss is recorded and the
    background fill enqueued, so a later probe flips to cached."""
    req = urllib.request.Request(blob_url(server, origin), method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return bool(resp.status == 200)
    except urllib.error.HTTPError:
        return False  # 404 miss (now recorded + enqueued by the cache-host)
    except (urllib.error.URLError, OSError):
        return False  # unreachable / timeout -> caller serves the origin itself


def serve_url(server: str, origin: str, timeout: float = PROBE_TIMEOUT) -> str | None:
    """The cache-host serve URL for ``origin`` if the cache holds it, else
    ``None`` -- the convenience form of "use the cache when warm":

        url = client.serve_url(cache, origin) or origin
    """
    return blob_url(server, origin) if is_cached(server, origin, timeout) else None
