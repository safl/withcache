#!/usr/bin/env python3
"""fromcache — cache-aware downloader (client for a fromcache cache-host).

Ask a fromcache cache-host for an artifact by its origin URL. On a hit, stream
it from the cache; on a miss (which the cache-host records for an operator to
review) fall back to the origin so you're never blocked. Optionally verify the
result against a known SHA-256.

Stdlib only — copy this single file onto any box with python3, chmod +x, done.

  fromcache https://the/origin/cuda.tar.gz --cache http://fromcache-server:3000
  fromcache https://the/origin/cuda.tar.gz -o ./cuda.tar.gz --sha256 <hex>

The cache may also be supplied via the FROMCACHE_CACHE environment variable.

curl-compatible flags
---------------------
fromcache understands the most common curl download flags so you can rewrite a
script by swapping `curl` for `fromcache --cache http://fromcache-server:3000`:

  -o, --output FILE        write here ("-" = stdout); default: remote filename
  -O, --remote-name        save as the URL's basename (fromcache's default too)
  -H, --header 'K: V'      add a request header to the ORIGIN (repeatable)
  -A, --user-agent UA      set User-Agent
  -u, --user USER[:PASS]   HTTP Basic auth to the origin
  -k, --insecure           skip TLS verification
  -L, --location           follow redirects (always on; accepted for compat)
  -f, --fail               fail on HTTP errors (always on; accepted for compat)
  -s, --silent             no progress output
  -S, --show-error         show errors even with -s (errors always go to stderr)
      --retry N            retry transient (network / 5xx) failures N times
      --max-time S         overall timeout in seconds (alias: --connect-timeout)

Note: unlike curl, `-c` is NOT cache (curl uses it for the cookie jar); use the
long `--cache`. Credentials from -H/-u/-A are sent to the ORIGIN only, never to
the cache, so a cache-host never sees your vendor tokens.
"""

import argparse
import base64
import hashlib
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CHUNK = 64 * 1024
USER_AGENT = "fromcache/0.1"


def eprint(*a):
    print(*a, file=sys.stderr, flush=True)


def cache_base(cache: str) -> str:
    """Accept 'my-box', 'my-box:3000', or 'http://fromcache-server:3000'."""
    cache = cache.strip().rstrip("/")
    if "://" not in cache:
        cache = "http://" + cache
    return cache


def default_output(url: str) -> str:
    name = os.path.basename(urllib.parse.urlsplit(url).path)
    return name or "download"


def make_opener(insecure: bool) -> urllib.request.OpenerDirector:
    handlers = []
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)  # build_opener adds redirects


def request(url: str, headers: dict) -> urllib.request.Request:
    req = urllib.request.Request(url)
    for k, v in headers.items():
        req.add_header(k, v)
    return req


def urlopen_retry(opener, req, timeout: int, retries: int):
    for attempt in range(retries + 1):
        try:
            return opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 or attempt == retries:
                raise  # client errors (incl. 404 cache miss) are not retried
        except (urllib.error.URLError, OSError):
            if attempt == retries:
                raise
        time.sleep(min(2 ** attempt, 10))


def stream(resp, out: str) -> str:
    """Stream the response body to `out` ('-' = stdout); return sha256 hex."""
    sha = hashlib.sha256()
    if out == "-":
        w = sys.stdout.buffer
        while (chunk := resp.read(CHUNK)):
            w.write(chunk)
            sha.update(chunk)
        w.flush()
        return sha.hexdigest()
    tmp = out + ".part"
    with open(tmp, "wb") as f:
        while (chunk := resp.read(CHUNK)):
            f.write(chunk)
            sha.update(chunk)
    os.replace(tmp, out)
    return sha.hexdigest()


def verify(out: str, got: str, expected: str | None):
    if expected and got.lower() != expected.lower():
        if out != "-" and os.path.exists(out):
            os.remove(out)
        eprint(f"error: sha256 mismatch\n  expected {expected}\n  got      {got}")
        sys.exit(3)


def from_cache(base, url, out, expected, opener, ua, timeout, retries) -> bool:
    """Try the cache (sending only a User-Agent — never origin creds).
    Returns True on hit, False on a recorded miss."""
    q = base + "/blob?url=" + urllib.parse.quote(url, safe="")
    try:
        resp = urlopen_retry(opener, request(q, {"User-Agent": ua}), timeout, retries)
        with resp:
            got = stream(resp, out)
        verify(out, got, expected)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False  # cache miss — recorded server-side
        raise


def from_origin(url, out, expected, opener, headers, timeout, retries):
    resp = urlopen_retry(opener, request(url, headers), timeout, retries)
    with resp:
        got = stream(resp, out)
    verify(out, got, expected)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="fromcache", add_help=True,
                                 description="cache-aware, curl-compatible downloader")
    ap.add_argument("url", help="origin URL of the artifact")
    ap.add_argument("--cache", default=os.environ.get("FROMCACHE_CACHE"),
                    help="cache-host URL (host, host:port, or URL); or set FROMCACHE_CACHE")
    ap.add_argument("--sha256", help="expected SHA-256; verifies cache and origin downloads")
    ap.add_argument("--no-fallback", action="store_true",
                    help="on a cache miss, fail instead of downloading from origin")
    # curl-compatible flags
    ap.add_argument("-o", "--output", help='output path ("-" = stdout)')
    ap.add_argument("-O", "--remote-name", action="store_true",
                    help="save as the URL basename (the default anyway)")
    ap.add_argument("-H", "--header", action="append", metavar="LINE",
                    help="extra request header sent to the ORIGIN (repeatable)")
    ap.add_argument("-A", "--user-agent", metavar="UA")
    ap.add_argument("-u", "--user", metavar="USER[:PASS]", help="HTTP Basic auth to origin")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("-L", "--location", action="store_true", help="(accepted; always on)")
    ap.add_argument("-f", "--fail", action="store_true", help="(accepted; always on)")
    ap.add_argument("-s", "--silent", "-q", "--quiet", action="store_true", dest="silent")
    ap.add_argument("-S", "--show-error", action="store_true", help="(accepted; errors always shown)")
    ap.add_argument("--retry", type=int, default=0, metavar="N")
    ap.add_argument("--max-time", "--connect-timeout", type=int, default=120,
                    dest="max_time", metavar="S")
    return ap


def main():
    args = build_parser().parse_args()

    ua = args.user_agent or USER_AGENT
    origin_headers = {"User-Agent": ua}
    for line in args.header or []:
        if ":" in line:
            k, v = line.split(":", 1)
            origin_headers[k.strip()] = v.strip()
    if args.user:
        origin_headers["Authorization"] = "Basic " + base64.b64encode(
            args.user.encode("utf-8")).decode("ascii")

    out = args.output or default_output(args.url)
    opener = make_opener(args.insecure)
    timeout, retries = args.max_time, args.retry

    def say(*a):
        if not args.silent:
            eprint(*a)

    # 1. Try the cache, if one was configured.
    if args.cache:
        base = cache_base(args.cache)
        try:
            if from_cache(base, args.url, out, args.sha256, opener, ua, timeout, retries):
                say(f"HIT  {args.url}  ->  {out}")
                return
            say(f"MISS {args.url}  (recorded on {base})")
        except (urllib.error.URLError, OSError) as e:
            say(f"warn: cache unreachable ({e}); using origin")
    else:
        say("no --cache set; using origin")

    if args.no_fallback:
        eprint("error: cache miss and --no-fallback set")
        sys.exit(2)

    # 2. Fall back to origin so the caller is never blocked.
    say(f"GET  {args.url}  (origin)  ->  {out}")
    try:
        from_origin(args.url, out, args.sha256, opener, origin_headers, timeout, retries)
    except urllib.error.HTTPError as e:
        eprint(f"error: origin returned HTTP {e.code} {e.reason}")
        sys.exit(22)  # curl's CURLE_HTTP_RETURNED_ERROR
    except (urllib.error.URLError, OSError) as e:
        eprint(f"error: {e}")
        sys.exit(7)  # curl's CURLE_COULDNT_CONNECT
    say("done")


if __name__ == "__main__":
    main()
