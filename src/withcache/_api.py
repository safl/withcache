"""Byte-serving routes for the withcache FastAPI app.

Ports ``GET /blob?url=<origin>`` and ``GET /b/<b64>/<name>`` (+
their HEAD counterparts) from the stdlib ``server.py`` handler.
This is the bty-critical surface: bty at
``bty.web._withcache.blob_url`` builds these URLs and the live
env hands them to a ``wget|dd`` chain, so the wire contract must
stay byte-identical:

- URL shape: ``/b/<urlsafe_b64(src_url)>/<name>``. Name segment is
  decorative; the b64 token is the source of truth.
- Cache hit -> 200 + ``Content-Type`` + ``Content-Length`` +
  ``X-Withcache-Sha256`` + streamed body (64 KiB chunks).
- Cache miss -> 404 with a message pointing at ``/ui/catalog``'s
  Download button, plus a side-effect ``record_miss`` write so the
  ``/ui/misses`` page shows the operator what clients tried to
  fetch that isn't in the catalog yet.

Since v0.10.0 there is no auto-fetch on miss: the operator
explicitly Downloads. The Miss page's Fetch button (retargeted in
v0.11.0) promotes a missed URL to a catalog entry + enqueues the
Download in one click.

Streaming shape: FastAPI ``StreamingResponse`` with a generator
that reads chunks from the on-disk blob at 64 KiB reads;
:class:`StreamRegistry` ticks progress per chunk so the operator
Downloads page shows in-flight transfers as they run.
"""

from __future__ import annotations

import base64
import contextlib
import urllib.parse
from collections.abc import Iterator
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from .server import CHUNK, CatalogState, _oras_tag_moved, _serialise_catalog


def _decode_blob_origin(path: str, query: str) -> str:
    """Extract the source URL from either shape.

    ``/blob?url=<origin>``: read ``url`` query param.
    ``/b/<b64>/<name>``: base64-decode the first path segment. The
    trailing ``<name>`` is decorative -- a client that derives
    format from URL filename (e.g. bty's flash chain) gets the
    right extension without the b64 token having to include it.
    """
    if path.startswith("/b/"):
        token = path[len("/b/") :].split("/", 1)[0]
        try:
            return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ""
    return (urllib.parse.parse_qs(query).get("url") or [""])[0]


def _serve_blob(
    request: Request,
    url: str,
    head_only: bool,
) -> Response:
    """Shared implementation for GET and HEAD blob requests.

    Returns 400 when the origin URL couldn't be decoded, 404 on
    cache miss (with a hint pointing at ``POST /catalog/entries/
    {name}/download``), or 200 + a StreamingResponse on hit.

    Since v0.10.0 there is no auto-fetch on miss: the operator
    picks explicitly what to download on withcache's /ui/catalog
    page. A miss here is either "not downloaded yet" (operator
    action needed) or "hit an unlisted URL" (bug in the caller).
    """
    if not url:
        return PlainTextResponse("missing url\n", status_code=400)

    store = request.app.state.store

    row = store.get_blob(url)
    if row is not None and _oras_tag_moved(url, row["sha256"]):
        # Tag re-pushed since we cached it: drop the stale bytes.
        # The miss branch below turns this into a 404 the operator
        # resolves by hitting Download / Redownload on /ui/catalog.
        store.delete_blob(row["key"])
        row = None

    if row is None:
        fresh = store.record_miss(url)
        if fresh:
            # First miss for this URL: emit an audit event so the
            # operator sees it on /ui/events. Subsequent misses for
            # the same URL bump the counter without re-emitting.
            from . import _events_log

            with contextlib.suppress(Exception):
                with store.conn() as ev_conn:
                    _events_log.record(
                        ev_conn,
                        kind="blob.miss.recorded",
                        summary=f"First cache miss for {url}",
                        subject_kind="blob",
                        subject_id=url,
                        actor="client",
                        source_ip=_events_log.normalize_ip(
                            request.client.host if request.client else None
                        ),
                    )
                    ev_conn.commit()
        return PlainTextResponse(
            "cache miss: this URL hasn't been downloaded yet. "
            "Pick the matching catalog entry on /ui/catalog and hit Download.\n",
            status_code=404,
        )

    path = store.blob_path(row["key"])
    headers = {
        "Content-Length": str(row["size"]),
        "X-Withcache-Sha256": row["sha256"],
    }
    media_type = row["content_type"] or "application/octet-stream"

    if head_only:
        # No body; the shim's HEAD probe doesn't count as a served
        # download so record_hit is skipped.
        return Response(status_code=200, media_type=media_type, headers=headers)

    store.record_hit(row["key"])

    def _chunks() -> Iterator[bytes]:
        """Read the blob in 64 KiB chunks. StreamingResponse iterates
        this + writes each chunk to the client."""
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(_chunks(), media_type=media_type, headers=headers)


def register_api_routes(app: FastAPI) -> None:
    """Attach the byte-serving routes to ``app``.

    Runtime objects (``store``, ``mgr``, ``streams``) are read from
    ``app.state`` at request time so tests + the lifespan hook can
    inject fresh instances without rebuilding the app.
    """

    @app.get("/blob", response_class=Response)
    def blob_get_legacy(request: Request) -> Response:
        """Legacy ``?url=<origin>`` shape. Kept for downstream
        consumers that pinned this before the ``/b/<b64>/<name>``
        canonical URL landed."""
        url = _decode_blob_origin("/blob", request.url.query)
        return _serve_blob(request, url, head_only=False)

    @app.head("/blob")
    def blob_head_legacy(request: Request) -> Response:
        url = _decode_blob_origin("/blob", request.url.query)
        return _serve_blob(request, url, head_only=True)

    @app.get("/b/{token}/{name:path}", response_class=Response)
    def blob_get_b64(token: str, name: str, request: Request) -> Response:
        """Canonical ``/b/<b64>/<name>`` shape. bty's flash chain
        builds these URLs; the ``<name>`` segment is decorative so
        the client derives extension for downstream format probes."""
        del name  # decorative segment; source of truth is the b64 token
        url = _decode_blob_origin(f"/b/{token}/x", "")
        return _serve_blob(request, url, head_only=False)

    @app.head("/b/{token}/{name:path}")
    def blob_head_b64(token: str, name: str, request: Request) -> Response:
        del name
        url = _decode_blob_origin(f"/b/{token}/x", "")
        return _serve_blob(request, url, head_only=True)

    # ---------- Catalog JSON API -----------------------------------------
    #
    # Bty consumes the catalog through these endpoints: withcache is the
    # single source of truth for what images exist. Read is open (mirrors
    # /blob's LAN-only trust model); writes gate on the same Bearer
    # pattern nbdmux uses -- an ``Authorization: Bearer <pw>`` header
    # whose value matches ``$WITHCACHE_ADMIN_PASSWORD``, or a session
    # cookie for browser-based operators.

    def _bearer_or_session_authed(request: Request) -> None:
        """Auth dependency for catalog writes.

        - No password configured -> open (single-tenant LAN deploy).
        - Session cookie present -> OK (browser path).
        - Matching Bearer token -> OK (service-to-service path;
          bty reads ``$WITHCACHE_ADMIN_PASSWORD`` and posts it).
        - Otherwise -> 401.
        """
        auth = request.app.state.auth
        if not auth.enabled:
            return
        # Session cookie check -- Starlette's SessionMiddleware
        # stores the flag under ``withcache_authed`` in
        # ``request.session``. Mirrors the flag ``_app.py`` sets.
        if request.session.get("withcache_authed"):
            return
        header = request.headers.get("Authorization") or ""
        if header.startswith("Bearer ") and auth.check_bearer(header[len("Bearer ") :]):
            return
        raise HTTPException(status_code=401, detail="auth required")

    @app.get("/catalog")
    def list_catalog(request: Request) -> JSONResponse:
        """Return the current catalog as JSON.

        Open route: bty polls this from a sibling container without a
        session (mirrors the ``/blob`` byte-serving surface's trust
        model -- LAN-only, no auth on reads). Returns only entries
        whose bytes are on disk in withcache's cache. Since v0.11.0
        "presence in this list" IS the readiness signal: staged
        entries (added but not yet Downloaded) are invisible to trio
        consumers so bty + nbdmux can trust every entry they see is
        flashable / exportable. Operators see the staged view on
        withcache's own ``/ui/catalog``.

        No pagination -- the catalog is small (dozens of entries at
        most).
        """
        cs: CatalogState = request.app.state.catalog
        store = request.app.state.store
        entries_out: list[dict[str, Any]] = []
        for e in cs.entries:
            fetch_url = e.get("resolved_src") or e.get("src") or ""
            if not fetch_url or store.get_blob(fetch_url) is None:
                continue
            entries_out.append(dict(e))
        return JSONResponse(
            {
                "url": cs.url,
                "env_url": cs.env_url,
                "fetched_at": cs.fetched_at,
                "last_error": cs.last_error,
                "entries": entries_out,
            }
        )

    @app.post("/catalog/entries", status_code=201)
    def add_catalog_entry(
        body: dict[str, Any],
        request: Request,
        _auth: None = Depends(_bearer_or_session_authed),
    ) -> JSONResponse:
        """Insert one catalog entry.

        Body: ``{"name": "...", "src": "...", "format?", "arch?",
        "sha256?", "size_bytes?", "resolved_src?", "description?"}``.
        Only ``src`` is required; every other field is optional and
        gets persisted through the ``catalog.toml`` round-trip.

        409 when an entry with the same ``name`` already exists;
        rejecting on duplicate name (not src) because the display
        surface keys on name and two rows with the same name would
        collide on the /ui/catalog table.

        Rejects any unknown top-level key -- the emitter allowlists
        keys anyway, but failing loud at the API boundary saves the
        operator from wondering why their ``notes`` field vanished.
        """
        allowed = {
            "name",
            "src",
            "resolved_src",
            "format",
            "arch",
            "sha256",
            "size_bytes",
            "description",
        }
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        unknown = set(body.keys()) - allowed
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"unknown key(s) {sorted(unknown)}; allowed: {sorted(allowed)}",
            )
        name = body.get("name")
        src = body.get("src")
        if not isinstance(name, str) or not name.strip():
            raise HTTPException(status_code=400, detail="name: non-empty string required")
        if not isinstance(src, str) or not src.strip():
            raise HTTPException(status_code=400, detail="src: non-empty string required")

        cs: CatalogState = request.app.state.catalog
        if any(e.get("name") == name for e in cs.entries):
            raise HTTPException(
                status_code=409,
                detail=f"catalog entry with name={name!r} already exists",
            )
        entry = {k: v for k, v in body.items() if v is not None and v != ""}
        cs.entries.append(entry)
        _persist_catalog(cs)
        return JSONResponse(entry, status_code=201)

    @app.post("/catalog/entries/{name}/download", status_code=202)
    def download_catalog_entry(
        name: str,
        request: Request,
        _auth: None = Depends(_bearer_or_session_authed),
    ) -> JSONResponse:
        """Fetch the entry's bytes into the local cache.

        Since v0.10.0 auto-fetch on cache miss is gone: the operator
        picks explicitly what to download. Nbdmux + bty's flash
        chain both refuse to hand out /b/<url> URLs for entries
        that haven't been downloaded, so this is the one-place
        control for "make it servable."

        Idempotent: enqueuing an entry that already has a live
        download returns the existing job. Force-refetch is
        ``POST /catalog/entries/{name}/download?force=1``.
        """
        cs: CatalogState = request.app.state.catalog
        mgr = request.app.state.mgr
        store = request.app.state.store

        entry = next((e for e in cs.entries if e.get("name") == name), None)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"no catalog entry with name={name!r}")
        fetch_url = entry.get("resolved_src") or entry.get("src") or ""
        if not fetch_url:
            raise HTTPException(
                status_code=400,
                detail=f"catalog entry {name!r} has no ``src`` / ``resolved_src`` to fetch",
            )
        force = request.query_params.get("force") in ("1", "true", "yes")
        if force:
            existing = store.get_blob(fetch_url)
            if existing is not None:
                store.delete_blob(existing["key"])
        job = mgr.enqueue(fetch_url)
        return JSONResponse(
            {
                "name": name,
                "src": fetch_url,
                "job_id": job.id,
                "status": job.status,
            },
            status_code=202,
        )

    @app.delete("/catalog/entries", status_code=204)
    def delete_catalog_entry(
        request: Request,
        name: str | None = None,
        _auth: None = Depends(_bearer_or_session_authed),
    ) -> Response:
        """Delete via ``?name=<name>`` query param (URL-safe;
        avoids path-encoding TOML entry names).

        204 on success. 404 when no entry with that name exists.
        """
        if not name or not name.strip():
            raise HTTPException(status_code=400, detail="name: query param required")
        cs: CatalogState = request.app.state.catalog
        original = list(cs.entries)
        cs.entries = [e for e in cs.entries if e.get("name") != name]
        if len(cs.entries) == len(original):
            raise HTTPException(
                status_code=404,
                detail=f"no catalog entry with name={name!r}",
            )
        _persist_catalog(cs)
        return Response(status_code=204)


def _persist_catalog(cs: CatalogState) -> None:
    """Write the current in-memory catalog back to
    ``<data_dir>/catalog.toml`` (when ``persist_path`` is set).

    Silent no-op when ``persist_path`` is ``None`` -- tests inject
    a stub CatalogState without disk backing and still exercise
    the in-memory mutation."""
    if cs.persist_path is None:
        return
    from pathlib import Path

    Path(cs.persist_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cs.persist_path).write_bytes(_serialise_catalog(cs.entries))
