#!/usr/bin/env python3
"""Pull an ``oras://`` artifact, through the cache when one is configured.

This is the pattern a provisioner wants: combine the two withcache library
modules so a big, token-gated registry blob comes off a local cache-host on the
re-pull instead of the registry.

- ``withcache.oras`` resolves an ``oras://`` reference to a concrete registry
  blob URL plus a short-lived anonymous bearer.
- ``withcache.client`` re-points the download at a cache-host when
  ``WITHCACHE_SERVER`` is set and the blob is cached. A cache hit is served
  bearer-free; a miss, timeout, or unset server falls back to the registry
  with the bearer. Since v0.10.0 a miss is recorded on the cache-host's
  ``/ui/misses`` page (no background fetch) so an operator can turn a
  recurring miss into a first-class catalog entry with one Fetch click.

Both modules are stdlib-only, so this example has no third-party dependencies.

Usage::

    WITHCACHE_SERVER=http://cache:8081 \\
        python pull_oras_blob.py oras://ghcr.io/<owner>/<repo>@sha256:<digest> out.bin

Omit ``WITHCACHE_SERVER`` to pull straight from the registry.
"""

import os
import sys
import urllib.request

from withcache import client, oras


def pull(ref: str, dst: str) -> None:
    # 1. Resolve the oras reference to a blob URL + bearer header.
    resolved = oras.resolve_ref(ref)
    url, headers = resolved.blob_url, dict(resolved.headers)

    # 2. Prefer the cache-host when one is configured and holds the blob.
    server = os.environ.get("WITHCACHE_SERVER")
    if server:
        served = client.serve_url(server, url, headers=headers)
        if served:
            url, headers = served, {}

    # 3. Stream it down.
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp, open(dst, "wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <oras://ref> <dst>", file=sys.stderr)
        return 2
    pull(sys.argv[1], sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
