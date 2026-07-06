"""A tiny client for consuming a withcache cache-host from other tools.

Lets a consumer (e.g. bty) point downloads at withcache without re-implementing
the ``/b/`` URL scheme, and also lets bty consume withcache's catalog as the
single source of truth for what images are flashable. Stdlib only, so
importing it pulls in no third-party dependencies.

    from withcache import client

    # Byte-serving: "use the cache when it's warm, the origin otherwise"
    url = client.serve_url("http://cache:8081", origin) or origin

    # Catalog: list what's flashable, add a new entry
    entries = client.list_catalog("http://cache:8081")
    client.add_catalog_entry(
        "http://cache:8081",
        {"name": "debian", "src": "https://.../debian.img.gz"},
    )

The ``/b/<urlsafe-b64(origin)>/<basename>`` encoding is shared with the shims
and the server (one definition in :mod:`withcache._shim`), so consumers stay in
lockstep with the cache-host automatically. Catalog reads are open (LAN-only
trust model); writes gate on ``$WITHCACHE_ADMIN_PASSWORD`` -- the client picks
it up from the env var by default so cross-container callers work out of the
box on the bty deploy (which sets the password on both ends).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import _shim

__all__ = [
    "CATALOG_TIMEOUT",
    "PROBE_TIMEOUT",
    "WithcacheError",
    "add_catalog_entry",
    "blob_url",
    "cache_base",
    "delete_catalog_entry",
    "is_cached",
    "list_catalog",
    "serve_url",
]

PROBE_TIMEOUT = 3.0  # seconds; never block the caller on a slow/unreachable cache
CATALOG_TIMEOUT = 5.0  # seconds; catalog reads/writes are small, keep short


class WithcacheError(Exception):
    """Raised on a catalog-plane failure: network, HTTP error, parse error.

    Inherits from :class:`Exception` (not :class:`OSError`) so callers can
    opt-in to surfacing withcache failures distinctly from generic network
    errors."""


#: Normalize a server value: accepts 'host', 'host:8081', or 'http://host:8081'.
cache_base = _shim.cache_base


def blob_url(server: str, origin: str) -> str:
    """The cache-host serve URL for ``origin``:
    ``<server>/b/<urlsafe-b64(origin), unpadded>/<basename>``. The trailing
    basename is cosmetic (so any downloader names the saved file after the
    artifact); the cache keys on the decoded origin URL."""
    return _shim.blob_url(_shim.cache_base(server), origin)


def is_cached(
    server: str,
    origin: str,
    timeout: float = PROBE_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> bool:
    """True if the cache-host already holds ``origin`` (a ``HEAD`` on ``/b/``
    returns 200). A miss (404), an unreachable host, a timeout, or any error
    returns False, so a caller can safely fall back to the origin. The HEAD
    also *warms* an auto-fetch cache-host: the miss is recorded and the
    background fill enqueued, so a later probe flips to cached.

    ``headers`` (optional) attaches request headers to the HEAD. The
    cache-host forwards a client-supplied ``Authorization`` into its
    background-fetch worker, so a consumer that has just minted an OCI
    bearer (the typical use case: bty resolving an ``oras://`` catalog
    entry to a ``ghcr.io`` blob URL at import time) can warm the cache
    against that token-gated origin in one probe. Other entries in
    ``headers`` round-trip the same way; only ``Authorization`` is
    forwarded into the fetch on the server side.
    """
    req = urllib.request.Request(blob_url(server, origin), method="HEAD")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return bool(resp.status == 200)
    except urllib.error.HTTPError:
        return False  # 404 miss (now recorded + enqueued by the cache-host)
    except (urllib.error.URLError, OSError):
        return False  # unreachable / timeout -> caller serves the origin itself


def serve_url(
    server: str,
    origin: str,
    timeout: float = PROBE_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> str | None:
    """The cache-host serve URL for ``origin`` if the cache holds it, else
    ``None`` -- the convenience form of "use the cache when warm":

        url = client.serve_url(cache, origin) or origin

    ``headers`` is passed through to :func:`is_cached` for the HEAD probe;
    the returned serve URL never carries auth (cached bytes are served
    without revisiting the origin).
    """
    return blob_url(server, origin) if is_cached(server, origin, timeout, headers=headers) else None


def _resolve_password(password: str | None) -> str | None:
    """``password`` if given, else ``$WITHCACHE_ADMIN_PASSWORD``, else ``None``.
    Empty / whitespace values are treated as unset."""
    if password:
        return password
    env = (os.environ.get("WITHCACHE_ADMIN_PASSWORD") or "").strip()
    return env or None


def _catalog_request(
    method: str,
    server: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: float = CATALOG_TIMEOUT,
    password: str | None = None,
) -> Any:
    """Shared request wiring for the catalog JSON endpoints.

    ``password`` -> ``Authorization: Bearer <pw>`` on writes. Reads
    are open on the server side so ``password`` is a no-op there;
    always sending it is fine (server ignores the header on reads).
    """
    url = f"{cache_base(server)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    resolved_pw = _resolve_password(password)
    if resolved_pw is not None:
        req.add_header("Authorization", f"Bearer {resolved_pw}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 204:
                return None
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
            detail = payload.get("detail") if isinstance(payload, dict) else None
        except (json.JSONDecodeError, ValueError):
            detail = None
        raise WithcacheError(f"{method} {path} -> HTTP {exc.code}: {detail or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WithcacheError(f"{method} {path} -> {exc}") from exc
    except json.JSONDecodeError as exc:
        raise WithcacheError(f"{method} {path} -> invalid JSON: {exc}") from exc


def list_catalog(
    server: str,
    timeout: float = CATALOG_TIMEOUT,
) -> dict[str, Any]:
    """Return the catalog snapshot as ``{url, env_url, fetched_at,
    last_error, entries: [...]}``. Open route: no password needed.

    Raises :class:`WithcacheError` on any failure (network, HTTP,
    parse). Callers typically want the ``entries`` field only:

        entries = client.list_catalog(server)["entries"]
    """
    return _catalog_request("GET", server, "/catalog", timeout=timeout)


def add_catalog_entry(
    server: str,
    entry: dict[str, Any],
    *,
    timeout: float = CATALOG_TIMEOUT,
    password: str | None = None,
) -> dict[str, Any]:
    """POST one entry into the catalog.

    ``entry`` must carry at least ``name`` + ``src``. Optional
    fields: ``format``, ``arch``, ``sha256``, ``size_bytes``,
    ``resolved_src``, ``description``.

    Raises :class:`WithcacheError` on any HTTP failure (409 if the
    entry name already exists; 401 if auth is enabled and no valid
    password reached the server).
    """
    return _catalog_request(
        "POST", server, "/catalog/entries", body=entry, timeout=timeout, password=password
    )


def delete_catalog_entry(
    server: str,
    name: str,
    *,
    timeout: float = CATALOG_TIMEOUT,
    password: str | None = None,
) -> None:
    """DELETE the catalog entry with ``name=<name>``. 404 (no such
    entry) is treated as success so the call is idempotent for the
    operator's "make sure this is gone" intent, mirroring
    :func:`nbdmux.client.remove_export`.

    Raises :class:`WithcacheError` on transport failure but NOT on
    404."""
    path = f"/catalog/entries?name={urllib.parse.quote(name, safe='')}"
    try:
        _catalog_request("DELETE", server, path, timeout=timeout, password=password)
    except WithcacheError as exc:
        if "HTTP 404" in str(exc):
            return
        raise
