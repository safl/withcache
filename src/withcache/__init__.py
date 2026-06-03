"""withcache — operator-curated, URL-keyed artifact cache for a small lab.

Two console entry points (see pyproject.toml):
  withcache         -> withcache.client:main   (the cache-aware downloader)
  withcache-server  -> withcache.server:main   (the cache-host)

Both modules are stdlib-only and self-contained, so either file can also be
copied and run on its own with a plain ``python3``.
"""

__version__ = "0.1.0"
