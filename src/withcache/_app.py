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

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from ._api import register_api_routes
from .server import Auth, DownloadManager, Store, StreamRegistry, resolve_secret

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
    auto_fetch: bool = True,
    keep_query: bool = False,
    max_bytes: int = 0,
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
    app = FastAPI(
        title="withcache",
        version=__version__,
        docs_url=None,
        redoc_url=None,
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
        """Placeholder for the Cached view; renders the shared
        chrome so the auth gate + layout work end-to-end. Real
        content lands in a follow-up commit."""
        return render("ui/_layout.html", request, nav_active="cached")

    return app
