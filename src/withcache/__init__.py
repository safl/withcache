"""withcache, operator-curated URL-keyed artifact cache for a small lab.

- ``withcache-server`` (withcache.server:main): the cache-host.
- ``curlwithcache`` / ``wgetwithcache``: transparent curl/wget shims, shipped
  as a native binary or a Python launcher (see hatch_build.py).
- ``withcache.client``: a tiny, stdlib-only library for other tools to consume
  a cache-host (build serve URLs, probe what's cached) without re-implementing
  the ``/b/`` URL scheme.
- ``withcache.oras``: OCI registry adapter. Parses ``oras://...`` references
  and resolves them to a plain HTTPS blob URL + bearer headers. The cache-host
  uses it on a cold miss; library consumers (e.g. ``bty``) import it to
  validate catalog entries and pre-resolve content digests.

Since v0.9.0 the daemon runs on FastAPI + Jinja + Bootstrap 5 + htmx
(matching bty-web + nbdmux, the eventual ``trio-common`` extraction
target); ``withcache.client``, ``withcache.oras``, and the shim
launchers stay stdlib-only so downstream consumers (bty) don't
inherit the framework floor.
"""

from . import oras
from .client import blob_url, cache_base, is_cached, serve_url

__version__ = "0.9.1"

__all__ = ["__version__", "blob_url", "cache_base", "is_cached", "oras", "serve_url"]
