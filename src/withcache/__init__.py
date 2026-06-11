"""withcache — operator-curated, URL-keyed artifact cache for a small lab.

- ``withcache-server`` (withcache.server:main): the cache-host.
- ``curlwithcache`` / ``wgetwithcache``: transparent curl/wget shims, shipped
  as a native binary or a Python launcher (see hatch_build.py).
- ``withcache.client``: a tiny, stdlib-only library for other tools to consume
  a cache-host (build serve URLs, probe what's cached) without re-implementing
  the ``/b/`` URL scheme.

All modules are stdlib-only and self-contained.
"""

from .client import blob_url, cache_base, is_cached, serve_url

__version__ = "0.4.0"

__all__ = ["__version__", "blob_url", "cache_base", "is_cached", "serve_url"]
