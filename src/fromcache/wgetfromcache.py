#!/usr/bin/env python3
"""wgetfromcache — a transparent caching shim for ``wget`` (part of fromcache).

The wget sibling of curlfromcache. Drop it on $PATH ahead of the real wget
(typically as a ``wget`` symlink). If FROMCACHE_SERVER points at a fromcache
cache-host and the artifact is cached there, the download is served from the
cache; otherwise your wget runs exactly as written.

    export FROMCACHE_SERVER=http://fromcache-server:3000
    wget https://the/origin/cuda.tar.gz            # cache hit -> local, named cuda.tar.gz

Because the cache URL is path-encoded with the real basename, a bare ``wget
URL`` still saves the file under the artifact's name (not the cache URL). Set
$REAL_WGET to pin the wrapped binary; WGETFROMCACHE_SERVER overrides
FROMCACHE_SERVER for wget only.

Stdlib only.
"""

import os
import subprocess
import sys

try:
    from fromcache import _shim
except ImportError:  # running the source file directly, uninstalled
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    from fromcache import _shim


def probe(real_wget: str, url: str):
    """Probe the cache with the same wget we'll exec, via --spider (HEAD).
    0 -> hit, 8 (server error response, i.e. our 404 miss) -> miss, else None."""
    try:
        r = subprocess.run(
            [real_wget, "--spider", "-q", "-T", str(_shim.PROBE_TIMEOUT), "-t", "1", url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    return True if r.returncode == 0 else False if r.returncode == 8 else None


def main(argv=None):
    _shim.run("wget", probe, argv)


if __name__ == "__main__":
    main()
