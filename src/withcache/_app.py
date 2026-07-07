"""FastAPI app factory for withcache.

Mirrors :mod:`nbdmux._app` in shape so the trio's three consoles
share one testing + auth + chrome pattern; the eventual
``trio-common`` extraction rolls these into one library.

Hosts the operator UI (Cached / Downloads / Misses / Catalog /
Settings), the byte-serving routes registered via
:func:`._api.register_api_routes`, the admin form endpoints the
UI action buttons post to, and the persistent-override Settings
form for the Warming card's log level. :func:`withcache.server.main`
constructs the runtime objects and launches uvicorn against this
factory.
"""

from __future__ import annotations

import contextlib
import hashlib
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

from . import __version__, _settings_store, _table_state
from ._api import _persist_catalog, register_api_routes
from .server import (
    DEFAULT_CATALOG_URL,
    Auth,
    CatalogState,
    DownloadManager,
    Store,
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
    ``build_query_string`` + ``per_page_choices`` are exposed as
    globals so ``ui/_table_macros.html`` renders without threading
    them through every ``render()`` call. Same shape as nbdmux +
    bty."""
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["build_query_string"] = _table_state.build_query_string
    env.globals["per_page_choices"] = list(_table_state.PER_PAGE_CHOICES)
    return env


def create_app(
    *,
    data_dir: str | os.PathLike[str],
    secret_key: bytes | None = None,
    store: Store | None = None,
    mgr: DownloadManager | None = None,
    catalog: CatalogState | None = None,
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

    ``store`` / ``mgr`` let tests inject stubs / capture doubles
    without spawning the real :class:`DownloadManager` worker
    thread. :func:`server.main` passes real instances at daemon
    start.
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
            # persisted catalog is empty. daemon=True so a slow /
            # broken upstream doesn't block ``uvicorn.run``'s serve
            # loop.
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
    # HttpOnly + SameSite=Lax + Max-Age) as bty + nbdmux so a
    # rolling deploy across the trio doesn't invalidate existing
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
    # data_dir so tests exercise the SQLite path unchanged. The mgr
    # default is a real DownloadManager; its worker thread starts on
    # demand (first enqueue).
    app.state.store = (
        store
        if store is not None
        else Store(data_dir_str, keep_query=keep_query, max_bytes=max_bytes)
    )
    app.state.mgr = mgr if mgr is not None else DownloadManager(app.state.store)
    # Auth object exposed on app.state so :func:`register_api_routes`
    # (which owns the JSON catalog write endpoints) can gate them on
    # ``Authorization: Bearer <pw>``. The UI form + login flow read
    # ``auth`` from this closure directly, but the register-routes
    # pattern doesn't have the closure, so app.state is the bridge.
    app.state.auth = auth
    # CatalogState resolution: env pin wins over on-disk override,
    # on-disk override wins over the shipping default (nosi's rolling
    # catalog manifest). ``load_persisted`` seeds entries from the
    # last successful fetch so a restart doesn't wipe the cache.
    # Tests pass a stub via ``catalog=`` to skip disk IO.
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
    # Ensure the settings table exists so the Settings render + save
    # handlers don't crash on a fresh cache.db.
    with app.state.store.conn() as _c:
        _settings_store.init(_c)

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
                url="/ui/dashboard", status_code=status.HTTP_303_SEE_OTHER
            )
        return render("ui/login.html", request, error=error)

    @app.post("/ui/login")
    def ui_login_submit(request: Request, password: str = Form(...)) -> Any:
        if not auth.check_password(password):
            return render("ui/login.html", request, error="Invalid password.")
        request.session[SESSION_AUTHED_KEY] = True
        return RedirectResponse(url="/ui/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/ui/logout")
    def ui_logout(request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- Root redirect + operator UI pages -----------------------

    @app.get("/")
    def _root() -> RedirectResponse:
        return RedirectResponse(url="/ui/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/ui/dashboard", response_class=HTMLResponse)
    def ui_dashboard(
        request: Request, _auth_check: None = Depends(require_ui_auth)
    ) -> HTMLResponse:
        """Withcache landing page: catalog + cache + activity summary
        at a glance. Same shape as bty's dashboard (jump-link subnav,
        cards for counts, health check pills, recent misses)."""
        cs: CatalogState = app.state.catalog
        store = app.state.store
        mgr = app.state.mgr
        entries_total = len(cs.entries)
        # A cache row lives only when the blob file is present; the
        # store's ``get_blob`` already gates on existence.
        entries_cached = 0
        for entry in cs.entries:
            fetch_url = entry.get("resolved_src") or entry.get("src") or ""
            if fetch_url and store.get_blob(fetch_url) is not None:
                entries_cached += 1
        blob_count, miss_count = store.counts()
        cached_bytes = store.total_size()
        jobs = mgr.list() if hasattr(mgr, "list") else []
        active_jobs = sum(1 for j in jobs if j.status in ("queued", "running"))
        failed_jobs = sum(1 for j in jobs if j.status == "failed")
        recent_misses = list(store.list_misses())[:5]

        sanity: list[dict[str, Any]] = []
        env_url = (os.environ.get("WITHCACHE_CATALOG_URL") or "").strip()
        sanity.append(
            {
                "label": "Catalog source",
                "ok": bool(cs.url),
                "info": False,
                "detail": (cs.url or "(unset)") + (" (env pin)" if env_url else ""),
                "href": "/ui/settings#catalog",
            }
        )
        sanity.append(
            {
                "label": "Catalog fetch",
                "ok": not cs.last_error,
                "info": False,
                "detail": cs.last_error or (cs.fetched_at or "not fetched yet"),
                "href": "/ui/settings#catalog",
                "fix_href": "/ui/settings#catalog",
            }
        )
        sanity.append(
            {
                "label": "Downloads",
                "ok": failed_jobs == 0,
                "info": False,
                "detail": (
                    f"{active_jobs} in flight, {failed_jobs} failed"
                    if (active_jobs or failed_jobs)
                    else "idle"
                ),
                "href": "/ui/catalog",
                "fix_href": "/ui/catalog",
            }
        )
        sanity.append(
            {
                "label": "Recorded misses",
                "info": True,
                "ok": True,
                "detail": (
                    f"{miss_count} URL{'s' if miss_count != 1 else ''} not in the catalog"
                    if miss_count
                    else "no misses recorded"
                ),
                "href": "/ui/misses",
            }
        )

        return render(
            "ui/dashboard.html",
            request,
            nav_active="dashboard",
            entries_total=entries_total,
            entries_cached=entries_cached,
            blob_count=blob_count,
            cached_bytes=cached_bytes,
            miss_count=miss_count,
            active_jobs=active_jobs,
            failed_jobs=failed_jobs,
            recent_misses=recent_misses,
            sanity=sanity,
            catalog_url=cs.url,
        )

    def _latest_job_by_url(mgr_jobs: list[Any]) -> dict[str, Any]:
        """Reduce ``mgr.list()`` to the newest job per URL. Used by the
        Catalog page to surface the last download's status + progress
        against the matching entry (queued / running / failed /
        cancelled). Completed jobs are folded into the ``downloaded_at``
        pill via the store row and don't need a separate entry."""
        latest: dict[str, Any] = {}
        for job in mgr_jobs:
            prev = latest.get(job.url)
            # The DownloadManager doesn't stamp jobs with a monotonic
            # id we can trust across restarts; but iteration order is
            # append-order so the last write wins, matching "latest".
            latest[job.url] = job if prev is None else job
        return latest

    @app.get("/ui/misses", response_class=HTMLResponse)
    def ui_misses(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Recorded cache misses (URL, count, first-seen, last-seen),
        with client-side filter + per-page selector matching the bty
        table pattern. Server-side sort/pagination lives on the URL
        so the view is bookmarkable."""
        params = dict(request.query_params)
        allowed_sort = {
            "url": "url",
            "count": "count",
            "first_seen": "first_seen",
            "last_seen": "last_seen",
        }
        sort = _table_state.parse_sort(
            params,
            allowed=allowed_sort,
            default_column="last_seen",
            default_direction="desc",
        )
        q = (params.get("q") or "").strip().lower()
        all_rows = list(app.state.store.list_misses())
        if q:
            all_rows = [r for r in all_rows if q in (r["url"] or "").lower()]
        reverse = sort.direction == "desc"
        all_rows.sort(key=lambda r: r[sort.column] or "", reverse=reverse)
        page = _table_state.parse_pagination(params, total=len(all_rows))
        rows = all_rows[page.offset : page.offset + page.per_page]
        preserved = {
            "q": q or None,
            "sort": sort.column,
            "dir": sort.direction,
            "per_page": str(page.per_page)
            if page.per_page != _table_state.DEFAULT_PER_PAGE
            else None,
        }
        return render(
            "ui/misses.html",
            request,
            nav_active="misses",
            rows=rows,
            q=q,
            sort=sort,
            page=page,
            preserved=preserved,
        )

    @app.get("/ui/catalog", response_class=HTMLResponse)
    def ui_catalog(request: Request, _auth_check: None = Depends(require_ui_auth)) -> HTMLResponse:
        """Catalog view: entries table with per-row cache + download
        state folded in. The retired Cached + Downloads tabs surface
        their signal here now:

        - ``hits`` (from ``store.get_blob`` blob row): how many times
          bty / clients pulled these bytes since the entry cached.
        - ``downloaded_at`` + ``downloaded_size``: presence of a
          store row is the "cached" signal.
        - ``active_job_status`` + ``active_job_progress``: newest
          DownloadManager job for this entry's URL so a running
          fetch renders a live progress pill without a separate tab.

        Client-side filter + per-page selector matching bty. The
        catalog source URL editor moved to ``/ui/settings#catalog``
        in v0.12.0.
        """
        params = dict(request.query_params)
        cs: CatalogState = app.state.catalog
        store = app.state.store
        mgr = app.state.mgr

        jobs_by_url = _latest_job_by_url(mgr.list() if hasattr(mgr, "list") else [])
        enriched: list[dict[str, Any]] = []
        for entry in cs.entries:
            row = {**entry}
            fetch_url = entry.get("resolved_src") or entry.get("src") or ""
            blob = store.get_blob(fetch_url) if fetch_url else None
            row["downloaded_at"] = blob["fetched_at"] if blob else None
            row["downloaded_size"] = int(blob["size"]) if blob else None
            row["hits"] = int(blob["hits"]) if blob else 0
            job = jobs_by_url.get(fetch_url)
            row["active_job_status"] = job.status if job else None
            row["active_job_error"] = getattr(job, "error", None) if job else None
            row["active_job_bytes_done"] = getattr(job, "bytes_done", 0) if job else 0
            row["active_job_bytes_total"] = getattr(job, "bytes_total", 0) if job else 0
            row["_src_lower"] = (row.get("src") or row.get("url") or "").lower()
            row["_name_lower"] = (row.get("name") or "").lower()
            row["_format_lower"] = (row.get("format") or "").lower()
            enriched.append(row)

        q = (params.get("q") or "").strip().lower()
        if q:
            enriched = [
                r
                for r in enriched
                if q in r["_name_lower"] or q in r["_src_lower"] or q in r["_format_lower"]
            ]
        allowed_sort = {
            "name": "name",
            "src": "_src_lower",
            "format": "_format_lower",
            "downloaded_at": "downloaded_at",
        }
        sort = _table_state.parse_sort(
            params,
            allowed=allowed_sort,
            default_column="name",
            default_direction="asc",
        )
        reverse = sort.direction == "desc"
        sort_key = allowed_sort[sort.column]
        enriched.sort(key=lambda r: r.get(sort_key) or "", reverse=reverse)
        page = _table_state.parse_pagination(params, total=len(enriched))
        entries = enriched[page.offset : page.offset + page.per_page]
        preserved = {
            "q": q or None,
            "sort": sort.column,
            "dir": sort.direction,
            "per_page": str(page.per_page)
            if page.per_page != _table_state.DEFAULT_PER_PAGE
            else None,
        }
        return render(
            "ui/catalog.html",
            request,
            nav_active="catalog",
            catalog_entries=entries,
            catalog_fetched_at=cs.fetched_at,
            catalog_last_error=cs.last_error,
            catalog_last_info=cs.last_info,
            q=q,
            sort=sort,
            page=page,
            preserved=preserved,
        )

    @app.get("/ui/settings", response_class=HTMLResponse)
    def ui_settings(
        request: Request,
        saved: str | None = None,
        error: str | None = None,
        _auth_check: None = Depends(require_ui_auth),
    ) -> HTMLResponse:
        """Effective-configuration view with a form-editable Warming
        card. Mirrors bty + nbdmux's Override / Effective / Default
        pattern for the log level. Catalog URL persistence still
        routes through ``CatalogState.set_url_override`` (via the
        Catalog page's /admin/catalog_set_url form) so the on-disk
        override file the daemon reads at startup stays the single
        source of truth."""
        session_secret_from_env = bool((os.environ.get("WITHCACHE_SESSION_SECRET") or "").strip())
        with app.state.store.conn() as conn:
            log_level_override = _settings_store.get(conn, _settings_store.KEY_LOG_LEVEL)
            try:
                log_level_effective = _settings_store.resolve_log_level(conn)
                log_level_error: str | None = None
            except _settings_store.SettingValueError as exc:
                log_level_effective = log_level_override or ""
                log_level_error = str(exc)
        log_level_env = (os.environ.get(_settings_store.ENV_LOG_LEVEL) or "").strip()
        flash_map = {"logging": "Logging settings saved."}
        flash = error if error else flash_map.get(saved or "")
        flash_kind = "danger" if error else ("success" if flash else None)
        cs: CatalogState = app.state.catalog
        return render(
            "ui/settings.html",
            request,
            nav_active="settings",
            data_dir=data_dir_str,
            catalog_url=cs.url,
            catalog_env_url=cs.env_url,
            catalog_fetched_at=cs.fetched_at,
            catalog_last_error=cs.last_error,
            catalog_last_info=cs.last_info,
            max_bytes=max_bytes,
            auth_enabled=auth.enabled,
            session_secret_from_env=session_secret_from_env,
            log_level_override=log_level_override,
            log_level_effective=log_level_effective,
            log_level_env=log_level_env,
            log_level_error=log_level_error,
            log_level_default=_settings_store.DEFAULT_LOG_LEVEL,
            log_levels=list(_settings_store.LOG_LEVELS),
            flash=flash,
            flash_kind=flash_kind,
        )

    @app.post("/admin/settings/logging")
    def ui_admin_settings_logging(
        log_level: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Persist the Logging card's log-level override. Empty
        submits clear the row so the resolver falls through to env /
        default. Invalid values 303 back with ``?error=<msg>`` and
        DO NOT persist -- rejecting at write time keeps the failure
        loud rather than deferring it to the next resolve.

        Syncs ``os.environ[WITHCACHE_LOG_LEVEL]`` at save time so
        code that reads the env var picks up the change without a
        restart; a cleared override restores whatever env value was
        present at process start (captured on first save)."""
        import urllib.parse

        ll = (log_level or "").strip().lower()
        if ll and ll not in _settings_store.LOG_LEVELS:
            msg = f"log level {ll!r} not in {list(_settings_store.LOG_LEVELS)}"
            return RedirectResponse(
                url="/ui/settings?error=" + urllib.parse.quote(msg, safe=""),
                status_code=status.HTTP_303_SEE_OTHER,
            )
        with app.state.store.conn() as conn:
            if ll:
                _settings_store.set_value(conn, _settings_store.KEY_LOG_LEVEL, ll)
                os.environ[_settings_store.ENV_LOG_LEVEL] = ll
            else:
                _settings_store.clear(conn, _settings_store.KEY_LOG_LEVEL)
        return RedirectResponse(
            url="/ui/settings?saved=logging#logging",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # ---------- Admin form endpoints ------------------------------------
    #
    # Form-encoded operator actions the UI action buttons post to.
    # Each 303s to a sensible /ui/* target so the browser flips to
    # GET and the dashboard reflects the mutation. Auth-gated -- the
    # JSON /blob + /b/ byte-serving routes stay open (bty polls from
    # a sibling container) but writes gate on the session cookie.

    def _promote_url_to_catalog(u: str) -> dict[str, Any] | None:
        """Common promote-a-URL-into-a-catalog-entry helper shared by
        ``/admin/fetch`` (Misses page) and ``/admin/catalog_add_entry``
        (Catalog subnav). Returns the newly-created entry or ``None``
        if one already exists for this URL.

        The name is derived from the URL basename with a
        ``misses-<sha12>`` fallback when the path is empty (bare host
        + slash); collisions add a numeric suffix. ``format`` is
        inferred from a known compressor suffix when present; other
        catalog fields stay unset until the operator hits Download
        (sha256, size arrive from the store row on subsequent
        renders)."""
        import urllib.parse as _urlparse

        cs: CatalogState = app.state.catalog
        already = next(
            (e for e in cs.entries if (e.get("resolved_src") or e.get("src")) == u),
            None,
        )
        if already is not None:
            return None
        parsed = _urlparse.urlsplit(u)
        basename = _urlparse.unquote(parsed.path.rsplit("/", 1)[-1] or "")
        if not basename:
            basename = f"misses-{hashlib.sha256(u.encode('utf-8')).hexdigest()[:12]}"
        candidate = basename
        existing_names = {e.get("name") for e in cs.entries}
        suffix = 2
        while candidate in existing_names:
            candidate = f"{basename}-{suffix}"
            suffix += 1
        entry: dict[str, Any] = {"name": candidate, "src": u, "resolved_src": u}
        for _ext in (".img.zst", ".img.gz", ".img.xz", ".iso.gz", ".iso.xz", ".img", ".iso"):
            if basename.endswith(_ext):
                entry["format"] = _ext.lstrip(".")
                break
        cs.entries.append(entry)
        _persist_catalog(cs)
        return entry

    @app.post("/admin/fetch")
    def ui_admin_fetch(
        url: str = Form(""),
        header: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Promote a URL to a first-class catalog entry AND enqueue
        its download in one click. Bound to the ``Fetch`` button on
        the ``/ui/misses`` page: the operator sees a URL clients
        keep asking for, hits Fetch, and the URL becomes a normal
        catalog entry that trio consumers (bty, nbdmux) can see as
        soon as its bytes land.

        Optional ``header`` carries a curated authorization payload
        parsed by :func:`withcache.server.parse_headers` so a
        token-gated origin can be fetched. No-op with a redirect
        when the URL is blank."""
        from .server import parse_headers

        u = (url or "").strip()
        if not u:
            return RedirectResponse(url="/ui/misses", status_code=status.HTTP_303_SEE_OTHER)
        _promote_url_to_catalog(u)
        app.state.mgr.enqueue(u, headers=parse_headers(header or ""))
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/dismiss")
    def ui_admin_dismiss(
        key: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        k = (key or "").strip()
        if k:
            app.state.store.dismiss(k)
        return RedirectResponse(url="/ui/misses", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/cancel_entry")
    def ui_admin_cancel_entry(
        name: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Cancel the newest in-flight DownloadManager job for the
        named catalog entry. No-op when the entry is unknown or
        nothing is queued/running for its URL."""
        cs: CatalogState = app.state.catalog
        entry = next((e for e in cs.entries if e.get("name") == (name or "").strip()), None)
        if entry is not None:
            fetch_url = entry.get("resolved_src") or entry.get("src") or ""
            for job in app.state.mgr.list():
                if job.url == fetch_url and job.status in ("queued", "running"):
                    app.state.mgr.cancel(job.id)
                    break
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_refresh")
    def ui_admin_catalog_refresh(
        next: str = Form("catalog"),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Re-fetch the currently-configured catalog source and
        re-parse entries. Callers pass ``next=catalog|settings`` so
        the 303 lands the operator back where they clicked."""
        app.state.catalog.fetch_now()
        target = "/ui/settings" if (next or "").strip() == "settings" else "/ui/catalog"
        return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_set_url")
    def ui_admin_catalog_set_url(
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Persist an operator override for the catalog URL. Success
        triggers an immediate fetch so the entries table reflects the
        new source without a second click. Failure records the reason
        on ``catalog.last_error`` and the Settings page surfaces it.
        The form lives on ``/ui/settings`` since v0.12.0."""
        ok, msg = app.state.catalog.set_url_override(url or "")
        if ok:
            app.state.catalog.fetch_now()
        else:
            app.state.catalog.last_error = msg
        return RedirectResponse(url="/ui/settings", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_add_oras")
    def ui_admin_catalog_add_oras(
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        app.state.catalog.add_oras_entry(url or "")
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_add_entry")
    def ui_admin_catalog_add_entry(
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """URL-only add-entry form for the Catalog subnav. Derives the
        catalog name from the URL basename (with a numeric collision
        suffix) and the ``format`` from a known compressor suffix
        when present. Empty submits are refused with a
        ``catalog.last_error`` note; other fields (sha256, arch,
        size, description) stay unset until the operator hits
        Download and the store row supplies size / hash. Same
        promote-a-URL helper the Misses page's Fetch button uses,
        minus the auto-download step.

        For ``oras://`` sources use ``/admin/catalog_add_oras``
        instead; the registry walk fills ``format`` + ``size``
        from the manifest."""
        cs: CatalogState = app.state.catalog
        u = (url or "").strip()
        if not u:
            cs.last_error = "url is required"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        if u.startswith("oras://"):
            cs.last_error = "use Add ORAS for oras:// sources"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        if not (u.startswith("http://") or u.startswith("https://")):
            cs.last_error = "expected http(s):// URL"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        added = _promote_url_to_catalog(u)
        if added is None:
            cs.last_error = f"catalog already has an entry for {u}"
        else:
            cs.last_error = ""
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

    @app.post("/admin/catalog_download_entry")
    def ui_admin_catalog_download_entry(
        name: str = Form(""),
        force: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Form-encoded sibling of ``POST /catalog/entries/{name}/download``.

        Adds an enqueue for the named entry; a truthy ``force`` field
        drops any existing cached bytes first so the redownload
        replaces stale content instead of hitting the dedup-on-active
        branch in :class:`DownloadManager`.
        """
        cs: CatalogState = app.state.catalog
        entry = next((e for e in cs.entries if e.get("name") == (name or "").strip()), None)
        if entry is None:
            cs.last_error = f"no catalog entry with name={name!r}"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        fetch_url = entry.get("resolved_src") or entry.get("src") or ""
        if not fetch_url:
            cs.last_error = f"catalog entry {name!r} has no ``src`` / ``resolved_src`` to fetch"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        if force.strip().lower() in ("1", "true", "on", "yes"):
            existing = app.state.store.get_blob(fetch_url)
            if existing is not None:
                app.state.store.delete_blob(existing["key"])
        app.state.mgr.enqueue(fetch_url)
        cs.last_error = ""
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    return app
