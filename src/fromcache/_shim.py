"""Shared core for the fromcache download-tool shims (curlfromcache, wgetfromcache).

Every shim does the same three things — find the URL in the wrapped tool's
arguments, ask the cache-host whether it has that artifact, and on a hit
re-point just the URL at the cache before exec'ing the real tool — so that
logic lives here. A shim only supplies (a) the tool's name and (b) how to
probe the cache with that tool.

The cache fetch URL is path-encoded as ``<server>/b/<base64(origin)>/<basename>``
so that ANY downloader names the saved file after the real artifact (``-O`` /
bare ``wget`` derive the name from the URL's last path segment), with no query
string to pollute the name and no per-tool output-flag parsing.
"""

import base64
import os
import re
import sys
import urllib.parse

PROBE_TIMEOUT = 5  # seconds; a slow/unreachable cache must never block the user

# A real URL argument begins with a scheme; this excludes header/data values
# like "Referer: https://…" or "u=https://…" that merely contain "://".
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def cache_base(server: str) -> str:
    """Accept 'host', 'host:3000', or 'http://fromcache-server:3000'."""
    server = server.strip().rstrip("/")
    if "://" not in server:
        server = "http://" + server
    return server


def env_server(tool: str) -> str | None:
    """Per-tool override (e.g. CURLFROMCACHE_SERVER) wins, else FROMCACHE_SERVER."""
    return os.environ.get(tool.upper() + "FROMCACHE_SERVER") or os.environ.get("FROMCACHE_SERVER")


def find_real(name: str) -> str | None:
    """The next executable ``name`` on PATH that isn't this shim. $REAL_<NAME>
    (e.g. $REAL_CURL) overrides."""
    override = os.environ.get("REAL_" + name.upper())
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    me = os.path.realpath(sys.argv[0]) if sys.argv and sys.argv[0] else None
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            if me and os.path.realpath(cand) == me:
                continue  # that's us — keep looking for the real one
            return cand
    return None


def find_url(argv: list):
    """Return (index, origin_url, kind) where kind is 'bare' or 'urleq', or None.

    'bare'  -> argv[index] is the URL (replace the whole token).
    'urleq' -> argv[index] is '--url=URL' (replace, keeping the prefix).
    """
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == "--":  # everything after is an operand
            for k in range(i + 1, len(argv)):
                if _SCHEME.match(argv[k]):
                    return (k, argv[k], "bare")
            return None
        if t == "--url" and i + 1 < len(argv):
            return (i + 1, argv[i + 1], "bare")
        if t.startswith("--url="):
            return (i, t[len("--url=") :], "urleq")
        if _SCHEME.match(t):
            return (i, t, "bare")
        i += 1
    return None


def _basename(origin: str) -> str:
    name = os.path.basename(urllib.parse.urlsplit(origin).path)
    return name or "download"


def blob_url(base: str, origin: str) -> str:
    """<base>/b/<urlsafe-base64(origin), unpadded>/<basename> — path-encoded so
    every downloader derives the correct output filename."""
    token = base64.urlsafe_b64encode(origin.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{base}/b/{token}/{urllib.parse.quote(_basename(origin))}"


def rewrite(argv: list, idx: int, kind: str, new_url: str) -> list:
    argv = list(argv)
    argv[idx] = ("--url=" + new_url) if kind == "urleq" else new_url
    return argv


def plan(tool: str, probe, argv: list):
    """Resolve (real_tool_path, final_argv) WITHOUT exec'ing — the testable core
    of run(). ``probe(real_tool, url)`` returns True (hit) / False (miss) / None
    (unreachable). On a hit the URL token is re-pointed at the cache; otherwise
    argv is returned exactly as the user wrote it. real is None if no real tool
    is found."""
    real = find_real(tool)
    if real is None:
        return None, argv
    server = env_server(tool)
    found = find_url(argv) if server else None
    if server and found is not None:
        idx, origin, kind = found
        url = blob_url(cache_base(server), origin)
        if probe(real, url) is True:
            argv = rewrite(argv, idx, kind, url)
    return real, argv


def run(tool: str, probe, argv=None):
    """The shim entry point. ``probe(real_tool, url)`` returns True (hit),
    False (miss), or None (cache unreachable)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    real, final = plan(tool, probe, argv)
    if real is None:
        sys.stderr.write(
            f"{tool}fromcache: no real {tool} found on PATH (set $REAL_{tool.upper()})\n"
        )
        sys.exit(127)
    try:
        os.execv(real, [real, *final])  # become the tool: exit code, signals, I/O
    except OSError as e:
        sys.stderr.write(f"{tool}fromcache: cannot exec {real}: {e}\n")
        sys.exit(127)
