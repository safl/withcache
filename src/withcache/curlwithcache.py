#!/usr/bin/env python3
"""curlwithcache — a transparent caching shim for ``curl`` (part of withcache).

Think "ccache for HTTP artifacts, without a proxy". Drop it on $PATH ahead of
the real curl (typically as a ``curl`` symlink). If WITHCACHE_SERVER points at a
withcache cache-host and the artifact is cached there, the download is served
from the cache; otherwise — server unset, not cached, or unreachable — your curl
runs exactly as written. Existing scripts need no changes.

    export WITHCACHE_SERVER=http://withcache-server:3000
    curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz   # cache hit -> local

It wraps the system curl, so all curl flags keep working; on a miss it hands
your original arguments straight to the real curl. Set $REAL_CURL to pin the
wrapped binary; CURLWITHCACHE_SERVER overrides WITHCACHE_SERVER for curl only.

Stdlib only.
"""

import os
import subprocess
import sys

try:
    from withcache import _shim
except ImportError:  # running the source file directly, uninstalled
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    from withcache import _shim


def probe(real_curl: str, url: str):
    """Probe the cache with the same curl we'll exec. 0 -> hit, 22 (curl -f on
    HTTP >=400) -> miss, anything else -> unreachable."""
    try:
        r = subprocess.run(
            [real_curl, "-fsS", "-I", "-m", str(_shim.PROBE_TIMEOUT), "-o", os.devnull, url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    return True if r.returncode == 0 else False if r.returncode == 22 else None


def main(argv=None):
    _shim.run("curl", probe, argv)


if __name__ == "__main__":
    main()
