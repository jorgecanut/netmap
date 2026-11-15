# How NetMap works (maintainer guide)

Short version: **Python standard library only**, one SQLite file, plain HTML/JS with
no build step. To fix something, find the module in the table, read its docstring,
run the tests.

```
netmap.py                 launcher (windowless logging, crash hook) -> netmap_core.app.main
netmap_core/
  app.py        wires everything, background loops, startup/shutdown
  config.py     command-line flags + NETMAP_* environment variables
  store.py      SQLite: connection log + everything set in the UI; size cap
  tracker.py    THE CORE: open/classify/log/close connections, map + list views
  local.py      this machine's sockets (Linux /proc incl. Docker, Windows, macOS)
  router.py     OpenWrt over SSH: conntrack parsing, direction logic, reconnects
  geo.py        offline DB-IP database + ip-api.com fallback + cache
  threats.py    blocklists (SOURCES), categories/severities, fast prefix matching
  rules.py      user rules: safe expression interpreter + engine
  auth.py       admin password, sessions, setup code, lockout
  tailscale.py  tailnet peers (This machine tab)
  web.py        HTTP server, JSON API (ROUTES table), security headers
  util.py       logging Throttle, IP helpers, atomic writes
  static/       index.html, app.css, app.js  (the whole UI)
tests/          python -m unittest discover -s tests -t .
docs/           this file, ROUTER.md, RULES.md, DOCKER.md, router/netmap-feed.sh
```

## One connection's life

```
local.collect() every 2 s ─┐                       ┌─> geo.lookup()        location at the time
                           ├─> tracker.open() ─────┼─> threats.match()     blocklist flags (public IPs only)
router conntrack NEW ──────┘          │            ├─> verdict_for()       trusted / suspicious / ignore
                                      │            └─> engine.run()        your rules
                                      ▼
                         store.insert_conn()  ── row in `conns`, kept in tracker.live
                                      │
local: gone for 3 scans  ─┐           ▼
router conntrack DESTROY ─┴─> tracker.close() ─> bytes, duration, rules again (closed=True)
                                      │          store.close_conn()
                                      ▼
                         tracker.recent for 90 s (fades on the map), then only in the log
```

The page polls `GET /api/live?scope=local|network` every 2.5 s (from memory, cheap).
When you drag the timeline it calls `GET /api/at?t=` (from the database), and the
History tab pages through `GET /api/history`.

## Data

Everything lives in `NETMAP_DATA_DIR` (Docker: `/data`):

| File | What | Safe to delete? |
|---|---|---|
| `netmap.sqlite` (+`-wal`, `-shm`) | connection log, settings, subnets, devices, rules, verdicts, sessions, admin password hash, online geo cache | deletes **everything** |
| `geoip.sqlite` | offline DB-IP database, rebuilt monthly | yes, re-downloaded (~93 MB download, ~720 MB on disk, ~2 min) |
| `threat_lists/*.txt` | last good copy of each blocklist | yes, re-downloaded |
| `router_key`, `router_key.pub` | NetMap's SSH key for the router | yes, but then re-add the new public key on the router |
| `router_known_hosts` | the router's host key | yes (same as *Forget host key*) |

Inspect the database with `sqlite3 /data/netmap.sqlite` (`.schema`, or e.g.
`SELECT * FROM conns ORDER BY id DESC LIMIT 20;`). The schema is at the top of
`store.py`. Back it up with `sqlite3 /data/netmap.sqlite ".backup /data/backup.sqlite"`,
which is safe while NetMap runs.

**Size cap:** `NETMAP_MAX_DB_MB` (default 4096). Every 10 minutes `store.prune()`
deletes just enough of the oldest *closed* connections to get back to 90% of the cap.

## Debugging

- **Logs** go to stderr: `docker logs netmap`, or `netmap.log` next to the script when
  started windowless on Windows. `NETMAP_LOG_LEVEL=DEBUG` shows ignored router lines,
  HTTP requests and more.
- **Repeating failures** (router down, list download failing) are logged once, then at most
  every 10 minutes (5 for the router) with a running count, and once more when they recover
  (`util.Throttle`). A quiet log doesn't mean nothing is retrying. Check the header pills
  and Settings for current state.
- **Unexpected exceptions** in background loops are logged with a full traceback
  (`log.exception`) and the loop continues. API errors return
  `internal error: <Type>: <message> (details in the NetMap log)` and log the traceback.
- **Crashes** of the main thread or any thread go through the hook in `netmap.py`.
- Locked out? `python netmap.py --reset-password`
  (`docker exec netmap python netmap.py --reset-password`), then restart: the log
  prints a new setup code.

## Common changes

| I want to… | Edit |
|---|---|
| add a blocklist | append to `SOURCES` in `threats.py` (plain IP/CIDR list) |
| add a rule field or function | `FIELDS`/`FUNCTIONS` in `rules.py`, fill it in `context_for()`, document it in `RULES.md` (a test checks) |
| change what counts as router noise | `NOISE_PORTS` in `router.py` |
| allow another router command | `docs/router/netmap-feed.sh` **and** the call in `router.py` |
| add an API endpoint | a `h_*` function + one line in `ROUTES` in `web.py` (pick public/read/write) |
| change colours | tokens at the top of `static/app.css` |
| change the fade / close timings | `FADE`, `LOCAL_GRACE_POLLS` in `tracker.py` |

## Tests

```sh
python -m unittest discover -s tests -t .        # ~5 s, no network needed
```

| File | Covers |
|---|---|
| `test_router.py` | conntrack parsing, direction logic (out/in/internal/router/IPv6), leases, DNS log, error messages |
| `test_rules.py` | rule language, sandbox (no imports/attributes/etc.), engine isolation, every example in RULES.md |
| `test_threats.py` | list parsing, prefix index, severity ordering, last-good-copy on failure |
| `test_store_geo_auth.py` | log queries, paging, size cap, offline geo build + lookup order, passwords/sessions/lockout |
| `test_tracker.py` | whole pipeline with a real DB: geo, DNS, bytes, snapshot reconnects, verdicts, rules, regressions |
| `test_web.py` | the real server with a fake router (`fake_ssh.py`): login, CSRF, Host/Origin checks, every settings API |

`tests/samples.py` holds real-format router output. Add a line there when you meet one
the parser gets wrong, then fix `router.py` until the test passes.

## Security model (short)

- Login required (unless `--no-auth`, which is refused unless bound to 127.0.0.1).
- Session cookie: random, HttpOnly, SameSite=Strict, Secure behind HTTPS proxies. Only its SHA-256 is stored.
- Every state-changing API call needs the `X-NetMap-CSRF` header and a same-site `Origin`.
- `Host` must be in `NETMAP_ALLOWED_HOSTS` (blocks DNS rebinding).
- Strict Content-Security-Policy: scripts only from this server and cdnjs (Leaflet, with SRI hashes).
- Rules are interpreted, never `eval`ed (see RULES.md).
- The router key can only run `netmap-feed` (forced command in `authorized_keys`).
- Subprocesses are always called with argument lists, never a shell.
