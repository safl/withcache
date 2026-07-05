"""FastAPI app factory for withcache (v0.9.0 port).

Replaces the stdlib ``http.server``-based ``server.py`` request
handler with a FastAPI application. Mirrors ``nbdmux._app`` in
shape so the trio's three consoles share one testing + auth +
chrome pattern; the eventual ``trio-common`` extraction rolls
these into one library.

The port is staged: this module currently hosts scaffolding only
(Jinja + static + session middleware + healthz + login) so a
TestClient-backed test can prove the pattern. The byte-serving
routes (``/blob``, ``/b/<b64>/<name>``), the operator pages
(Cached / Downloads / Misses / Catalog / Settings), and the
DownloadManager thread lifespan wiring migrate in follow-up
commits.

The stdlib ``server.py`` remains the runtime daemon during the
port; ``main()`` there is unchanged. That keeps the existing 148
tests green while this file lands and gets iterated.
"""

from __future__ import annotations

import contextlib
import os
import sys
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from ._api import register_api_routes
from .server import (
    DEFAULT_CATALOG_URL,
    Auth,
    CatalogState,
    DownloadManager,
    Store,
    StreamRegistry,
    resolve_secret,
)

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATES_DIR = Path(__file__).parent / "_templates"

# Starlette's SessionMiddleware stores the flag under a namespaced
# key inside ``request.session``. Same pattern as bty + nbdmux.
SESSION_AUTHED_KEY = "withcache_authed"


class NotAuthenticated(Exception):
    """Raised by :func:`require_ui_auth` when the request lacks an
    authed session. The exception handler redirects to /ui/login."""


def _build_jinja(templates_dir: Path) -> Environment:
    """Configure the Jinja environment. Autoescape on for all
    templates so operator-supplied strings can't inject markup.
    Same shape as nbdmux + bty."""
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def create_app(
    *,
    data_dir: str | os.PathLike[str],
    secret_key: bytes | None = None,
    store: Store | None = None,
    mgr: DownloadManager | None = None,
    streams: StreamRegistry | None = None,
    catalog: CatalogState | None = None,
    auto_fetch: bool = True,
    keep_query: bool = False,
    max_bytes: int = 0,
    run_lifecycle: bool = False,
) -> FastAPI:
    """Build the FastAPI application for the withcache control plane.

    ``data_dir`` is the persistent state directory (where the
    stdlib server writes ``session-secret`` etc.). We borrow
    ``resolve_secret`` from the legacy module so a running daemon
    and the ported UI share one signing key across the migration.

    ``secret_key`` overrides the persisted secret; tests pass a
    stable bytes value so cookies stay valid across the fixture's
    lifetime without touching the disk.

    ``store`` / ``mgr`` / ``streams`` / ``auto_fetch`` let tests
    inject stubs / capture doubles without spawning the real
    :class:`DownloadManager` worker thread. The daemon path
    (``server.main`` post-cut-over) passes real instances via a
    lifespan hook.
    """
    data_dir_str = str(data_dir)
    Path(data_dir_str).mkdir(parents=True, exist_ok=True)
    secret = secret_key or resolve_secret(data_dir_str)
    admin_password = os.environ.get("WITHCACHE_ADMIN_PASSWORD") or None
    auth = Auth(secret=secret, password=admin_password)

    jinja = _build_jinja(_TEMPLATES_DIR)

    @contextlib.asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Start-of-request-cycle wiring for the daemon path.

        Fires only when ``run_lifecycle=True`` (``server.main`` boots
        uvicorn with this). TestClient callers omit the flag so no
        background thread or fetch fires from the fixture -- the mgr
        thread pool still starts at Store construction but that's
        ``daemon=True`` so process exit reaps it.
        """
        if run_lifecycle:
            # Kick the startup catalog fetch when the on-disk
            # persisted catalog is empty. Same shape the pre-port
            # ``server.main`` had; daemon=True so a slow / broken
            # upstream doesn't block ``uvicorn.run``'s serve loop.
            if not _app.state.catalog.entries:
                threading.Thread(
                    target=_app.state.catalog.fetch_now,
                    name="withcache-catalog-init",
                    daemon=True,
                ).start()
        try:
            yield
        finally:
            if run_lifecycle:
                # Drain DownloadManager workers so sqlite finalizer
                # warnings from leaked threads don't fire on shutdown.
                with contextlib.suppress(Exception):
                    _app.state.mgr.close()
                print("withcache: shut down", file=sys.stderr, flush=True)

    app = FastAPI(
        title="withcache",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        lifespan=_lifespan,
    )

    # SessionMiddleware signs a cookie with the same shape (name +
    # HttpOnly + SameSite=Lax + Max-Age) the pre-port stdlib server
    # emitted, so a rolling deploy doesn't invalidate existing
    # browser sessions.
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret.decode("utf-8", errors="replace"),
        session_cookie=Auth.COOKIE,
        max_age=Auth.MAX_AGE,
        same_site="lax",
        https_only=False,
    )

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Runtime objects the byte-serving handlers reach via
    # ``request.app.state``. Store writes a real cache.db under
    # data_dir so tests exercise the SQLite path unchanged. mgr +
    # streams default to real instances (they don't spawn threads
    # at construction time; the mgr thread only starts on demand).
    app.state.store = (
        store
        if store is not None
        else Store(data_dir_str, keep_query=keep_query, max_bytes=max_bytes)
    )
    app.state.mgr = mgr if mgr is not None else DownloadManager(app.state.store)
    app.state.streams = streams if streams is not None else StreamRegistry()
    app.state.auto_fetch = auto_fetch
    # CatalogState mirrors the pre-port ``server.main`` setup: env pin
    # wins over on-disk override, on-disk override wins over the shipping
    # default (nosi's rolling catalog manifest). ``load_persisted`` seeds
    # entries from the last successful fetch so a restart doesn't wipe
    # the cache. Tests pass a stub via ``catalog=`` to skip disk IO.
    if catalog is not None:
        app.state.catalog = catalog
    else:
        env_catalog_url = (os.environ.get("WITHCACHE_CATALOG_URL") or "").strip()
        catalog_url = env_catalog_url or DEFAULT_CATALOG_URL
        cs = CatalogState(
            url=catalog_url,
            persist_path=str(Path(data_dir_str) / "catalog.toml"),
            env_url=env_catalog_url,
            url_override_path=str(Path(data_dir_str) / "catalog_url"),
        )
        cs.load_persisted()
        app.state.catalog = cs

    register_api_routes(app)

    def render(name: str, request: Request, **ctx: Any) -> HTMLResponse:
        """Render a Jinja template + always-injected context.
        Same pattern as :func:`nbdmux._app.render`."""
        ctx.setdefault("version", __version__)
        # ``logged_in`` gates the nav-btns + user-bar in the layout.
        # Auth-disabled deploys treat every request as authed so the
        # nav isn't hidden under an unauth veil.
        ctx.setdefault(
            "logged_in",
            (not auth.enabled) or bool(request.session.get(SESSION_AUTHED_KEY)),
        )
        path_parts = request.url.path.strip("/").split("/")
        nav_active = path_parts[1] if len(path_parts) > 1 and path_parts[0] == "ui" else None
        ctx.setdefault("nav_active", nav_active)
        template = jinja.get_template(name)
        return HTMLResponse(template.render(**ctx))

    def require_ui_auth(request: Request) -> None:
        """Auth dependency for UI routes. Raises NotAuthenticated,
        which the exception handler turns into a 303 to /ui/login."""
        if not auth.enabled:
            return
        if not request.session.get(SESSION_AUTHED_KEY):
            raise NotAuthenticated()

    @app.exception_handler(NotAuthenticated)
    async def _not_authed_handler(_request: Request, _exc: NotAuthenticated) -> RedirectResponse:
        return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- Health --------------------------------------------------

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Liveness probe. JSON body naming service + version; same
        shape bty's Settings > Bytes reachability pill polls."""
        return JSONResponse({"status": "ok", "service": "withcache", "version": __version__})

    # ---------- Login / logout ------------------------------------------

    @app.get("/ui/login", response_class=HTMLResponse)
    def ui_login_form(request: Request, error: str | None = None) -> HTMLResponse:
        if request.session.get(SESSION_AUTHED_KEY):
            return RedirectResponse(  # type: ignore[return-value]
                url="/ui/cached", status_code=status.HTTP_303_SEE_OTHER
            )
        return render("ui/login.html", request, error=error)

    @app.post("/ui/login")
    def ui_login_submit(request: Request, password: str = Form(...)) -> Any:
        if not auth.check_password(password):
            return render("ui/login.html", request, error="Invalid password.")
        request.session[SESSION_AUTHED_KEY] = True
        return RedirectResponse(url="/ui/cached", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/ui/logout")
    def ui_logout(request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- Root redirect + placeholder pages -----------------------

    @app.get("/")
    def _root() -> RedirectResponse:
        return RedirectResponse(url="/ui/cached", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/ui/cached", response_class=HTMLResponse)
    def ui_cached(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Cached blobs view: one row per cached artifact with URL,
        size, sha short, hit count, and last-fetch timestamp. Reads
        ``app.state.store.list_blobs`` (sorted newest-first)."""
        rows = app.state.store.list_blobs()
        total_bytes = app.state.store.total_size()
        return render(
            "ui/cached.html",
            request,
            nav_active="cached",
            rows=rows,
            total_bytes=total_bytes,
            row_count=len(rows),
        )

    @app.get("/ui/downloads", response_class=HTMLResponse)
    def ui_downloads(
        request: Request, _auth_check: None = Depends(require_ui_auth)
    ) -> HTMLResponse:
        """DownloadManager jobs view: queued / running / completed /
        failed / cancelled, with a progress bar for jobs that report
        Content-Length. Reads ``app.state.mgr.list``."""
        jobs = app.state.mgr.list() if hasattr(app.state.mgr, "list") else []
        return render("ui/downloads.html", request, nav_active="downloads", jobs=jobs)

    @app.get("/ui/misses", response_class=HTMLResponse)
    def ui_misses(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Recorded cache misses: URL, count, first-seen, last-seen.
        Reads ``app.state.store.list_misses`` (sorted by last-seen)."""
        rows = app.state.store.list_misses()
        return render("ui/misses.html", request, nav_active="misses", rows=rows)

    @app.get("/ui/catalog", response_class=HTMLResponse)
    def ui_catalog(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Catalog view: current URL + env pin + on-disk override
        provenance, plus the entries table. Read-only for this pass;
        Refresh + Set URL + Add oras + Delete land in the admin-forms
        follow-up PR."""
        cs: CatalogState = app.state.catalog
        return render(
            "ui/catalog.html",
            request,
            nav_active="catalog",
            catalog_url=cs.url,
            catalog_env_url=cs.env_url,
            catalog_entries=cs.entries,
            catalog_fetched_at=cs.fetched_at,
            catalog_last_error=cs.last_error,
            catalog_last_info=cs.last_info,
        )

    @app.get("/ui/settings", response_class=HTMLResponse)
    def ui_settings(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Read-only Settings view for this pass. Persistent overrides
        land in the follow-up settings-store PR mirroring nbdmux's
        Override / Effective / Default pattern."""
        session_secret_from_env = bool((os.environ.get("WITHCACHE_SESSION_SECRET") or "").strip())
        return render(
            "ui/settings.html",
            request,
            nav_active="settings",
            data_dir=data_dir_str,
            catalog_url=app.state.catalog.url,
            catalog_env_url=app.state.catalog.env_url,
            max_bytes=max_bytes,
            auth_enabled=auth.enabled,
            session_secret_from_env=session_secret_from_env,
        )

    # ---------- Admin form endpoints ------------------------------------
    #
    # Form-encoded siblings of the operator actions the pre-port
    # ``server.Handler`` dispatched on ``self.ADMIN_POST``. Each 303s
    # to a sensible /ui/* target so the browser flips to GET and the
    # dashboard reflects the mutation. Auth-gated -- the JSON /blob
    # + /b/ byte-serving routes stay open (bty polls from a sibling
    # container) but writes gate on the session cookie.

    @app.post("/admin/fetch")
    def ui_admin_fetch(
        url: str = Form(""),
        header: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Enqueue a background fetch. Optional ``header`` field
        carries a curated authorization payload -- format matches
        the pre-port ``parse_headers`` helper."""
        from .server import parse_headers

        u = (url or "").strip()
        if u:
            app.state.mgr.enqueue(u, headers=parse_headers(header or ""))
        return RedirectResponse(url="/ui/downloads", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/dismiss")
    def ui_admin_dismiss(
        key: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        k = (key or "").strip()
        if k:
            app.state.store.dismiss(k)
        return RedirectResponse(url="/ui/misses", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/delete")
    def ui_admin_delete_blob(
        key: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        k = (key or "").strip()
        if k:
            app.state.store.delete_blob(k)
        return RedirectResponse(url="/ui/cached", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/cancel")
    def ui_admin_cancel(
        id: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        jid = (id or "").strip()
        if jid.isdigit():
            app.state.mgr.cancel(int(jid))
        return RedirectResponse(url="/ui/downloads", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/clear")
    def ui_admin_clear(
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        app.state.mgr.clear_finished()
        return RedirectResponse(url="/ui/downloads", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_refresh")
    def ui_admin_catalog_refresh(
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        app.state.catalog.fetch_now()
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_set_url")
    def ui_admin_catalog_set_url(
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Persist an operator override for the catalog URL. Success
        triggers an immediate fetch so the entries table reflects the
        new source without a second click. Failure records the reason
        on ``catalog.last_error`` and the Catalog page surfaces it."""
        ok, msg = app.state.catalog.set_url_override(url or "")
        if ok:
            app.state.catalog.fetch_now()
        else:
            app.state.catalog.last_error = msg
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_add_oras")
    def ui_admin_catalog_add_oras(
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        app.state.catalog.add_oras_entry(url or "")
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_delete_entry")
    def ui_admin_catalog_delete_entry(
        name: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        ok, msg = app.state.catalog.delete_entry(name or "")
        if not ok:
            app.state.catalog.last_error = msg
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    return app
