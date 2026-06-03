# fromcache

A tiny, **operator-curated** artifact cache for a small lab — for the big
vendor downloads you re-pull constantly: CUDA, ROCm, DOCA, firmware, drivers.

The trick: artifacts are cached **by their origin URL as a key**, and a client
tool (`fromcache`) opts in explicitly. No transparent proxy, no TLS
interception, no client CA to distribute — the URL is a lookup key, not a
connection target.

```
fromcache https://the/origin/cuda.tar.gz --cache http://fromcache-server:3000
        │
        ├─ HIT  → stream from the cache (fast, local)
        └─ MISS → the cache records the URL for an operator;
                  fromcache falls back to origin so you're never blocked
```

Misses are **not** fetched automatically. An operator reviews the miss list in
a small web UI and presses **Download**, and only then does the cache-host pull
the artifact from origin and store it. You can also pre-seed via an
"add from URI" form. So the cache-host is the only box that needs internet
egress (and any vendor credentials), and clients never write to it.

Everything is **stdlib-only Python** — no `pip`, no framework, nothing to manage.

## Why not just curl + a caching proxy?

For `https://` (i.e. every vendor download), a forward proxy can't cache without
**SSL-bump / MITM** — curl tunnels TLS end-to-end via `CONNECT`, so the proxy
only sees ciphertext. fromcache sidesteps that by making the URL an explicit
**lookup key** instead of a connection target. And no proxy offers the
**operator-curated** model (a miss queue a human approves). The cache-host is
the real product; the client is deliberately thin — if you don't want to install
it, this one-liner is equivalent:

```sh
URL=https://the/origin/cuda.tar.gz
curl -sf "http://fromcache-server:3000/blob?url=$URL" -o out || curl -L "$URL" -o out
```

## Components

| Path                          | What it is                                               |
|-------------------------------|----------------------------------------------------------|
| `src/fromcache/server.py`     | The cache-host: blob store + miss table + admin UI       |
| `src/fromcache/client.py`     | The CLI; stdlib-only, also runnable as a single file     |
| `deploy/Containerfile`        | `python:slim` + `pip install .`                          |
| `deploy/compose.yml`          | One service, one volume — single Podman/Docker host      |
| `pyproject.toml`              | Packaging: `fromcache` + `fromcache-server` commands     |

## Install

```sh
pip install fromcache          # provides `fromcache` and `fromcache-server`
```

Either tool is also a self-contained stdlib script — for the client you can skip
install entirely and just copy one file:

```sh
scp src/fromcache/client.py lab-node:/usr/local/bin/fromcache   # one file, no deps
```

## Deploy the cache-host

```sh
export FROMCACHE_ADMIN_PASSWORD=change-me    # protects the operator UI
podman compose -f deploy/compose.yml up -d   # or: docker compose -f ...
# admin UI:  http://fromcache-server:3000/
```

Or without containers (installed, or straight from the source file):

```sh
FROMCACHE_ADMIN_PASSWORD=change-me fromcache-server --data-dir ./data --port 3000
# or: python3 src/fromcache/server.py --data-dir ./data --port 3000
```

Data (blobs + `cache.db` + `session-secret`) lives in the `/data` volume (or
`--data-dir`). Artifacts are immutable per version, so there is no cache
invalidation.

## Use the client

```sh
export FROMCACHE_CACHE=http://fromcache-server:3000
fromcache https://the/origin/cuda.tar.gz
fromcache https://the/origin/cuda.tar.gz -o ./cuda.tar.gz --sha256 <hex>
```

### curl-compatible flags

Swap `curl` for `fromcache --cache http://fromcache-server:3000` in a script and
the common flags keep working:

| flag | meaning |
|------|---------|
| `-o, --output FILE`    | write here (`-` = stdout); default is the remote filename |
| `-O, --remote-name`    | save as the URL basename (fromcache's default anyway) |
| `-H, --header 'K: V'`  | add a request header to the **origin** (repeatable) |
| `-A, --user-agent UA`  | set User-Agent |
| `-u, --user U[:P]`     | HTTP Basic auth to the origin |
| `-k, --insecure`       | skip TLS verification |
| `-L, --location`       | follow redirects (always on; accepted) |
| `-f, --fail`           | fail on HTTP errors (always on; accepted) |
| `-s, --silent`         | no progress output |
| `-S, --show-error`     | accepted; errors always go to stderr |
| `--retry N`            | retry transient (network / 5xx) failures |
| `--max-time S`         | overall timeout (alias `--connect-timeout`) |

Notes: unlike curl, `-c` is **not** `--cache` (curl uses `-c` for the cookie
jar) — use the long `--cache`. Credentials from `-H/-u/-A` go to the **origin
only**, never to the cache, so the cache-host never sees your vendor tokens.
Also: `--sha256 <hex>` verifies both the cache and origin paths; `--no-fallback`
fails on a miss instead of hitting origin. Exit codes follow curl where it makes
sense (`22` HTTP error, `7` connect failure, `3` sha256 mismatch, `2` miss with
`--no-fallback`).

## Typical loop

1. A node runs `fromcache <url>` for a CUDA/ROCm/DOCA artifact → **miss**, served
   from origin, URL recorded on the cache-host.
2. Operator opens the admin UI, logs in, sees the miss, clicks **Download**.
3. Every later `fromcache <url>` for that artifact is a local **hit**.

Pre-seeding known-large artifacts via *Add from URI* skips step 1 entirely.

## Auth

Single-tenant session-cookie auth (modelled on [bty]'s approach, with an env
password instead of PAM):

- The **read path** (`/blob`, `/healthz`) is **open** — clients never log in.
- The **operator surface** (`/` and `/admin/*`) is gated behind a server-signed
  session cookie. Log in at `/ui/login` with `FROMCACHE_ADMIN_PASSWORD`.
- The cookie is HMAC-signed with a key from `FROMCACHE_SESSION_SECRET`, or a
  random key persisted to `<data-dir>/session-secret` (survives restarts).
- If `FROMCACHE_ADMIN_PASSWORD` is unset, the operator UI is left **open** and a
  warning is logged at startup — set it for any shared deployment.

| Env var                   | Purpose                                               |
|---------------------------|-------------------------------------------------------|
| `FROMCACHE_ADMIN_PASSWORD`| Operator login password (unset ⇒ UI open)             |
| `FROMCACHE_SESSION_SECRET`| Override the persisted cookie-signing key (optional)  |
| `FROMCACHE_CACHE`         | Default `--cache` for the `fromcache` client          |

[bty]: ../bty

## Cache keys & signed URLs

By default the key is `scheme://host/path` with the **query string dropped**, so
CDN/presigned URLs (whose tokens change every request) still match by path.
Pass `--keep-query` to the server if you need query-sensitive keys. Use
`fromcache --sha256 <hex>` to pin integrity on the un-signed raw blobs.

## Notes / not-yet

- Auth is a single shared operator password; there are no per-user accounts.
  Behind a trusted LAN that's usually enough; for anything exposed, also front
  it with your reverse proxy / WireGuard.
- Package-manager repos (`.deb`/`.rpm`) are GPG-signed and verified by the
  client regardless of transport, so caching them this way is safe.
