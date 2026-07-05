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
- Cache miss -> 404 with ``cache miss (recorded)`` body,
  side-effect of enqueueing a background fetch when
  ``auto_fetch`` is on and the store has capacity.
- HEAD support: same headers, no body (probes from
  bty.web._withcache.is_cached use HEAD).
- ``Authorization`` request header forwarded onto the background
  fetch worker so a token-gated origin (typical use case: an OCI
  bearer minted by bty at catalog import time) can be pulled by
  the worker with the same credential.

Streaming shape: FastAPI ``StreamingResponse`` with a generator
that reads chunks from the on-disk blob. The pre-port stdlib
handler chunked via ``self.wfile.write`` in a loop; the port
preserves the same 64 KiB read size + the
:class:`StreamRegistry` progress ticks so the operator dashboard
shows the same numbers.
"""

from __future__ import annotations

import base64
import urllib.parse
from collections.abc import Iterator

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response, StreamingResponse

from .server import CHUNK, StreamRegistry, _oras_tag_moved


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

    Returns 400 when the origin URL couldn't be decoded, 404 (with
    miss recording + optional fetch enqueue) on cache miss, or 200
    + a StreamingResponse on hit. Same status codes and body shapes
    the pre-port stdlib handler emitted.
    """
    if not url:
        return PlainTextResponse("missing url\n", status_code=400)

    store = request.app.state.store
    mgr = request.app.state.mgr
    auto_fetch: bool = request.app.state.auto_fetch
    streams: StreamRegistry = request.app.state.streams

    row = store.get_blob(url)
    if row is not None and _oras_tag_moved(url, row["sha256"]):
        # Tag re-pushed since we cached it: drop the stale bytes so
        # the miss branch below re-fetches the current content.
        # Same shape as the pre-port handler.
        store.delete_blob(row["key"])
        row = None

    if row is None:
        store.record_miss(url)
        if auto_fetch and store.has_capacity():
            # Forward the client's Authorization header onto the
            # worker so a token-gated origin (fresh OCI bearer from
            # bty at catalog import time) can be fetched. Narrow
            # allowlist: Authorization only; /admin/fetch carries
            # its own ``headers=`` payload for the curated path.
            fwd_headers: dict[str, str] | None = None
            auth_header = request.headers.get("Authorization")
            if auth_header:
                fwd_headers = {"Authorization": auth_header}
            mgr.enqueue(url, headers=fwd_headers)
        return PlainTextResponse("cache miss (recorded)\n", status_code=404)

    path = store.blob_path(row["key"])
    headers = {
        "Content-Length": str(row["size"]),
        "X-Withcache-Sha256": row["sha256"],
    }
    media_type = row["content_type"] or "application/octet-stream"

    if head_only:
        # No body; the shim's HEAD probe doesn't count as a served
        # download so record_hit + stream registration are skipped.
        return Response(status_code=200, media_type=media_type, headers=headers)

    store.record_hit(row["key"])
    client = f"{request.client.host}:{request.client.port}" if request.client else "unknown"
    stream = streams.start(url=url, client=client, total=row["size"])

    def _chunks() -> Iterator[bytes]:
        """Read the blob in 64 KiB chunks. StreamingResponse iterates
        this + writes each chunk to the client. Progress ticks fire
        every :data:`StreamRegistry.PROGRESS_STRIDE` chunks so the
        dashboard's 1 Hz refresh sees updates without lock-contention
        on a busy box."""
        sent = 0
        ticks = 0
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    yield chunk
                    sent += len(chunk)
                    ticks += 1
                    if ticks % StreamRegistry.PROGRESS_STRIDE == 0:
                        streams.bump(stream.id, sent)
                streams.bump(stream.id, sent)
        finally:
            streams.finish(stream.id)

    return StreamingResponse(_chunks(), media_type=media_type, headers=headers)


def register_api_routes(app: FastAPI) -> None:
    """Attach the byte-serving routes to ``app``.

    Runtime objects (``store``, ``mgr``, ``streams``, ``auto_fetch``)
    are read from ``app.state`` at request time so tests + the
    lifespan hook can inject fresh instances without rebuilding
    the app.
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
