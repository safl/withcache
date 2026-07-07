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
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, _events_log, _settings_store, _table_state
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
    async def _lifespan(_app: FastAPI) -> AsyncGenerator[None]:
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
    # Ensure the settings + events tables exist so the Settings render
    # + operator actions don't crash on a fresh cache.db.
    with app.state.store.conn() as _c:
        _settings_store.init(_c)
        _events_log.init(_c)

    register_api_routes(app)

    def _emit(
        *,
        kind: str,
        summary: str,
        request: Request | None = None,
        subject_kind: str | None = None,
        subject_id: str | None = None,
        actor: str | None = "operator",
        details: dict[str, Any] | None = None,
    ) -> None:
        """One-shot events emitter used by the UI action handlers.
        Opens its own connection, records the event, commits, closes.
        Never raises: any error is swallowed so a bad emit can't
        break the request that produced it."""
        try:
            client_host = None
            if request is not None and request.client is not None:
                client_host = _events_log.normalize_ip(request.client.host)
            with app.state.store.conn() as conn:
                _events_log.record(
                    conn,
                    kind=kind,
                    summary=summary,
                    subject_kind=subject_kind,
                    subject_id=subject_id,
                    actor=actor,
                    source_ip=client_host,
                    details=details,
                )
                conn.commit()
        except Exception:  # noqa: BLE001 -- emit is best-effort
            pass

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
            _emit(
                kind="auth.login.failed",
                summary="Login attempt with wrong password",
                request=request,
                subject_kind="auth",
                actor="operator",
            )
            return render("ui/login.html", request, error="Invalid password.")
        request.session[SESSION_AUTHED_KEY] = True
        _emit(
            kind="auth.login.succeeded",
            summary="Operator logged in",
            request=request,
            subject_kind="auth",
            actor="operator",
        )
        return RedirectResponse(url="/ui/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/ui/logout")
    def ui_logout(request: Request) -> RedirectResponse:
        request.session.clear()
        _emit(
            kind="auth.logout",
            summary="Operator logged out",
            request=request,
            subject_kind="auth",
            actor="operator",
        )
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

        with store.conn() as _c:
            recent_events = _events_log.list_recent(_c)
            unack_failures = _events_log.count_unacknowledged_failures(_c)
        if unack_failures:
            sanity.append(
                {
                    "label": "Unacknowledged failures",
                    "ok": False,
                    "info": False,
                    "detail": (
                        f"{unack_failures} failure event"
                        f"{'s' if unack_failures != 1 else ''} not yet acknowledged"
                    ),
                    "href": "/ui/events?q=failed",
                    "fix_href": "/ui/events?q=failed",
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
            recent_events=recent_events,
            recent_events_limit=_events_log.RECENT_EVENTS_LIMIT,
            sanity=sanity,
            catalog_url=cs.url,
        )

    @app.get("/ui/events", response_class=HTMLResponse)
    def ui_events(
        request: Request,
        q: str = "",
        page: int = 1,
        per_page: int = 25,
        _auth_check: None = Depends(require_ui_auth),
    ) -> HTMLResponse:
        """Slim audit log view: newest-first, free-text filter,
        per-page pagination. Same shape as bty's /ui/events."""
        needle = (q or "").strip()
        clamped_per_page = (
            per_page if per_page in _table_state.PER_PAGE_CHOICES else _table_state.DEFAULT_PER_PAGE
        )
        clamped_page = max(1, page)
        with app.state.store.conn() as conn:
            total = _events_log.count_events(conn, q=needle)
            page_state = _table_state.parse_pagination(
                {"page": str(clamped_page), "per_page": str(clamped_per_page)},
                total=total,
            )
            events = _events_log.search_events(
                conn,
                q=needle,
                offset=page_state.offset,
                limit=page_state.per_page,
            )
        preserved = {
            "q": needle or None,
            "per_page": (
                str(page_state.per_page)
                if page_state.per_page != _table_state.DEFAULT_PER_PAGE
                else None
            ),
        }
        return render(
            "ui/events.html",
            request,
            nav_active="events",
            events=events,
            q=needle,
            page=page_state,
            preserved=preserved,
        )

    @app.post("/admin/events/{event_id}/ack")
    def ui_admin_ack_event(
        event_id: int,
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Mark one event acknowledged. Clears it from the
        dashboard's unacknowledged-failures tripwire without
        deleting the row."""
        with app.state.store.conn() as conn:
            _events_log.set_acknowledged(conn, event_id, True)
            conn.commit()
        return RedirectResponse(url="/ui/events", status_code=status.HTTP_303_SEE_OTHER)

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
        request: Request,
        log_level: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Persist the Logging card's log-level override."""
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
        _emit(
            kind="settings.logging.updated",
            summary=f"Log level set to {ll or '(cleared)'}",
            request=request,
            subject_kind="settings",
            subject_id="logging",
            details={"log_level": ll or None},
        )
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
        request: Request,
        url: str = Form(""),
        header: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Promote a URL to a first-class catalog entry AND enqueue
        its download in one click. Bound to the ``Fetch`` button on
        the ``/ui/misses`` page."""
        from .server import parse_headers

        u = (url or "").strip()
        if not u:
            return RedirectResponse(url="/ui/misses", status_code=status.HTTP_303_SEE_OTHER)
        added = _promote_url_to_catalog(u)
        app.state.mgr.enqueue(u, headers=parse_headers(header or ""))
        if added is not None:
            _emit(
                kind="catalog.entry.added",
                summary=f"Promoted miss {u} to catalog entry {added['name']}",
                request=request,
                subject_kind="catalog",
                subject_id=added.get("name"),
                details={"src": u, "via": "misses.fetch"},
            )
        _emit(
            kind="catalog.entry.download.requested",
            summary=f"Download requested for {u}",
            request=request,
            subject_kind="catalog",
            subject_id=(added or {}).get("name") or u,
            details={"src": u},
        )
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/dismiss")
    def ui_admin_dismiss(
        request: Request,
        key: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        k = (key or "").strip()
        if k:
            app.state.store.dismiss(k)
            _emit(
                kind="blob.miss.dismissed",
                summary="Dismissed recorded miss",
                request=request,
                subject_kind="blob",
                subject_id=k,
            )
        return RedirectResponse(url="/ui/misses", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/cancel_entry")
    def ui_admin_cancel_entry(
        request: Request,
        name: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Cancel the newest in-flight DownloadManager job for the
        named catalog entry."""
        cs: CatalogState = app.state.catalog
        entry_name = (name or "").strip()
        entry = next((e for e in cs.entries if e.get("name") == entry_name), None)
        if entry is not None:
            fetch_url = entry.get("resolved_src") or entry.get("src") or ""
            for job in app.state.mgr.list():
                if job.url == fetch_url and job.status in ("queued", "running"):
                    app.state.mgr.cancel(job.id)
                    _emit(
                        kind="catalog.entry.download.cancelled",
                        summary=f"Cancelled download of {entry_name}",
                        request=request,
                        subject_kind="catalog",
                        subject_id=entry_name,
                        details={"src": fetch_url, "job_id": job.id},
                    )
                    break
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_refresh")
    def ui_admin_catalog_refresh(
        request: Request,
        next: str = Form("catalog"),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Re-fetch the currently-configured catalog source and
        re-parse entries."""
        cs: CatalogState = app.state.catalog
        cs.fetch_now()
        if cs.last_error:
            _emit(
                kind="catalog.refresh.failed",
                summary=f"Catalog refresh failed: {cs.last_error}",
                request=request,
                subject_kind="catalog",
                details={"url": cs.url, "error": cs.last_error},
            )
        else:
            _emit(
                kind="catalog.refreshed",
                summary=f"Catalog refreshed from {cs.url}",
                request=request,
                subject_kind="catalog",
                details={"url": cs.url, "entries": len(cs.entries)},
            )
        target = "/ui/settings" if (next or "").strip() == "settings" else "/ui/catalog"
        return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_set_url")
    def ui_admin_catalog_set_url(
        request: Request,
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Persist an operator override for the catalog URL."""
        ok, msg = app.state.catalog.set_url_override(url or "")
        if ok:
            app.state.catalog.fetch_now()
            _emit(
                kind="catalog.source.updated",
                summary=f"Catalog source URL set to {(url or '').strip() or '(cleared)'}",
                request=request,
                subject_kind="settings",
                subject_id="catalog",
                details={"url": (url or "").strip()},
            )
        else:
            app.state.catalog.last_error = msg
        return RedirectResponse(url="/ui/settings", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_add_oras")
    def ui_admin_catalog_add_oras(
        request: Request,
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        candidate = (url or "").strip()
        ok, _msg = app.state.catalog.add_oras_entry(candidate)
        if ok:
            _emit(
                kind="catalog.entry.added",
                summary=f"Added ORAS entry {candidate}",
                request=request,
                subject_kind="catalog",
                subject_id=candidate,
                details={"src": candidate, "via": "catalog.add_oras"},
            )
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_add_entry")
    def ui_admin_catalog_add_entry(
        request: Request,
        url: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """URL-only add-entry form for the Catalog subnav."""
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
            _emit(
                kind="catalog.entry.added",
                summary=f"Added HTTPS entry {added['name']}",
                request=request,
                subject_kind="catalog",
                subject_id=added["name"],
                details={"src": u, "via": "catalog.add_entry"},
            )
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_delete_entry")
    def ui_admin_catalog_delete_entry(
        request: Request,
        name: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        target = (name or "").strip()
        ok, msg = app.state.catalog.delete_entry(target)
        if not ok:
            app.state.catalog.last_error = msg
        else:
            _emit(
                kind="catalog.entry.deleted",
                summary=f"Deleted catalog entry {target}",
                request=request,
                subject_kind="catalog",
                subject_id=target,
            )
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/catalog_download_entry")
    def ui_admin_catalog_download_entry(
        request: Request,
        name: str = Form(""),
        force: str = Form(""),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """Form-encoded sibling of ``POST /catalog/entries/{name}/download``."""
        cs: CatalogState = app.state.catalog
        target = (name or "").strip()
        entry = next((e for e in cs.entries if e.get("name") == target), None)
        if entry is None:
            cs.last_error = f"no catalog entry with name={name!r}"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        fetch_url = entry.get("resolved_src") or entry.get("src") or ""
        if not fetch_url:
            cs.last_error = f"catalog entry {name!r} has no ``src`` / ``resolved_src`` to fetch"
            return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)
        forced = force.strip().lower() in ("1", "true", "on", "yes")
        if forced:
            existing = app.state.store.get_blob(fetch_url)
            if existing is not None:
                app.state.store.delete_blob(existing["key"])
        app.state.mgr.enqueue(fetch_url)
        cs.last_error = ""
        _emit(
            kind="catalog.entry.download.requested",
            summary=(
                f"Redownload requested for {target}"
                if forced
                else f"Download requested for {target}"
            ),
            request=request,
            subject_kind="catalog",
            subject_id=target,
            details={"src": fetch_url, "force": forced},
        )
        return RedirectResponse(url="/ui/catalog", status_code=status.HTTP_303_SEE_OTHER)

    return app
