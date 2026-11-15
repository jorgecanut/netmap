"""SQLite storage: the connection log plus everything managed in the web UI.

One file (netmap.sqlite in the data dir). Each thread gets its own connection;
WAL mode lets the web server read while the tracker writes. The log is capped
by size (--max-db-mb): when it is exceeded the oldest connections are deleted
and the space is returned to the OS.

To inspect it by hand:  sqlite3 /data/netmap.sqlite '.schema'
"""

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager

log = logging.getLogger("netmap.store")

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- One row per connection. scope: 'local' (this machine) or 'network' (router).
-- device: the LAN IP that made it, 'router', or 'local' for this machine.
-- severity: 0 none, 1 info, 2 low, 3 medium, 4 high (highest flag).
-- flags: JSON list of {src: list|rule|verdict, name, category, severity}.
-- Location columns record where the IP was *at the time*; IPs move.
CREATE TABLE IF NOT EXISTS conns (
    id          INTEGER PRIMARY KEY,
    scope       TEXT NOT NULL,
    direction   TEXT NOT NULL,          -- out | in | internal
    proto       TEXT NOT NULL,
    device      TEXT NOT NULL,
    proc        TEXT,
    pid         INTEGER,
    local_port  INTEGER,
    remote_ip   TEXT NOT NULL,
    remote_port INTEGER,
    domain      TEXT,
    start_ts    REAL NOT NULL,
    end_ts      REAL,
    bytes_out   INTEGER,
    bytes_in    INTEGER,
    cc TEXT, region TEXT, city TEXT, lat REAL, lon REAL, org TEXT,
    severity    INTEGER NOT NULL DEFAULT 0,
    flags       TEXT
);
CREATE INDEX IF NOT EXISTS conns_scope_start ON conns(scope, start_ts);
CREATE INDEX IF NOT EXISTS conns_scope_end   ON conns(scope, end_ts);
CREATE INDEX IF NOT EXISTS conns_remote      ON conns(remote_ip);
CREATE INDEX IF NOT EXISTS conns_dev_cc      ON conns(scope, device, cc);
CREATE INDEX IF NOT EXISTS conns_flagged     ON conns(scope, start_ts) WHERE severity > 0;

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subnets (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, cidr TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, expr TEXT NOT NULL,
    category TEXT NOT NULL, severity INTEGER NOT NULL, enabled INTEGER NOT NULL,
    updated REAL NOT NULL);
-- target: ip:<addr> | domain:<suffix> | device:<lan ip>
-- verdict: trusted | suspicious | ignore
CREATE TABLE IF NOT EXISTS verdicts (
    target TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL,
    created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY, cc TEXT, region TEXT, city TEXT, lat REAL, lon REAL,
    org TEXT, source TEXT, ts REAL NOT NULL);
"""

CONN_COLS = ("id", "scope", "direction", "proto", "device", "proc", "pid", "local_port",
             "remote_ip", "remote_port", "domain", "start_ts", "end_ts", "bytes_out",
             "bytes_in", "cc", "region", "city", "lat", "lon", "org", "severity", "flags")


def row_to_conn(row):
    d = dict(zip(CONN_COLS, row))
    d["flags"] = json.loads(d["flags"]) if d["flags"] else []
    return d


class Store:
    def __init__(self, path, max_mb=4096):
        self.path = path
        self.max_bytes = max(64, max_mb) * 1024 * 1024
        self._local = threading.local()
        self.write_lock = threading.RLock()    # one writer at a time, all threads
        db = self.db()
        # auto_vacuum only takes effect if set before the first table exists.
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        db.executescript(SCHEMA)
        db.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
        db.commit()

    # --- connections ----------------------------------------------------------

    def db(self):
        c = getattr(self._local, "db", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.db = c
        return c

    @contextmanager
    def tx(self):
        """Write transaction. Holds the process-wide write lock."""
        with self.write_lock:
            db = self.db()
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")

    def q(self, sql, args=()):
        return self.db().execute(sql, args).fetchall()

    # --- settings (JSON values) ----------------------------------------------

    def get(self, key, default=None):
        r = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r[0][0]) if r else default

    def set(self, key, value):
        with self.tx() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)",
                       (key, json.dumps(value)))

    # --- connection log -------------------------------------------------------

    def insert_conn(self, db, c):
        cur = db.execute(
            "INSERT INTO conns (scope, direction, proto, device, proc, pid, local_port,"
            " remote_ip, remote_port, domain, start_ts, end_ts, bytes_out, bytes_in,"
            " cc, region, city, lat, lon, org, severity, flags)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (c["scope"], c["direction"], c["proto"], c["device"], c.get("proc"),
             c.get("pid"), c.get("local_port"), c["remote_ip"], c.get("remote_port"),
             c.get("domain"), c["start_ts"], c.get("end_ts"), c.get("bytes_out"),
             c.get("bytes_in"), c.get("cc"), c.get("region"), c.get("city"),
             c.get("lat"), c.get("lon"), c.get("org"), c.get("severity", 0),
             json.dumps(c["flags"]) if c.get("flags") else None))
        return cur.lastrowid

    def close_conn(self, db, c):
        db.execute("UPDATE conns SET end_ts=?, bytes_out=?, bytes_in=?, severity=?,"
                   " flags=? WHERE id=?",
                   (c["end_ts"], c.get("bytes_out"), c.get("bytes_in"),
                    c.get("severity", 0),
                    json.dumps(c["flags"]) if c.get("flags") else None, c["id"]))

    def fill_geo(self, ip, g):
        """Back-fill location on rows logged before the lookup finished."""
        with self.tx() as db:
            db.execute("UPDATE conns SET cc=?, region=?, city=?, lat=?, lon=?, org=?"
                       " WHERE remote_ip=? AND cc IS NULL",
                       (g.get("cc"), g.get("region"), g.get("city"), g.get("lat"),
                        g.get("lon"), g.get("org"), ip))

    def close_dangling(self):
        """Rows left open by a crash or restart: close them at the last heartbeat."""
        hb = self.get("heartbeat", None)
        with self.tx() as db:
            n = db.execute("UPDATE conns SET end_ts=MAX(start_ts, ?) WHERE end_ts IS NULL",
                           (hb or time.time(),)).rowcount
        if n:
            log.info("closed %d connections left open by the previous run", n)

    def heartbeat(self):
        self.set("heartbeat", time.time())

    def conns_at(self, scope, t, limit=5000):
        """Connections that were open at time t."""
        rows = self.q("SELECT * FROM conns WHERE scope=? AND start_ts<=?"
                      " AND (end_ts>=? OR end_ts IS NULL)"
                      " ORDER BY start_ts DESC LIMIT ?", (scope, t, t, limit))
        return [row_to_conn(r) for r in rows]

    def history(self, scope, before_id=None, limit=200, min_severity=0, text=None,
                keep=None, scan_max=20000):
        """Newest-first page of the log. `text` is a substring match done in SQL;
        `keep(conn)` is an extra Python filter (used for subnets, which are
        computed from the device IP rather than stored)."""
        sql = "SELECT * FROM conns WHERE scope=?"
        args = [scope]
        if before_id:
            sql += " AND id<?"
            args.append(before_id)
        if min_severity:
            sql += " AND severity>=?"
            args.append(min_severity)
        if text:
            like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql += (" AND (device LIKE ? ESCAPE '\\' OR remote_ip LIKE ? ESCAPE '\\'"
                    " OR domain LIKE ? ESCAPE '\\' OR proc LIKE ? ESCAPE '\\'"
                    " OR cc LIKE ? ESCAPE '\\' OR city LIKE ? ESCAPE '\\'"
                    " OR org LIKE ? ESCAPE '\\' OR flags LIKE ? ESCAPE '\\')")
            args += [like] * 8
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(scan_max if keep else limit)
        out, last_id = [], None
        for r in self.db().execute(sql, args):
            c = row_to_conn(r)
            last_id = c["id"]
            if keep is None or keep(c):
                out.append(c)
                if len(out) >= limit:
                    break
        return out, last_id

    def time_range(self, scope):
        r = self.q("SELECT MIN(start_ts) FROM conns WHERE scope=?", (scope,))
        return r[0][0]

    def device_seen_country(self, scope, device, cc, before_ts):
        r = self.q("SELECT 1 FROM conns WHERE scope=? AND device=? AND cc=?"
                   " AND start_ts<? LIMIT 1", (scope, device, cc, before_ts))
        return bool(r)

    def device_seen_remote(self, scope, device, remote_ip, before_ts):
        r = self.q("SELECT 1 FROM conns WHERE remote_ip=? AND scope=? AND device=?"
                   " AND start_ts<? LIMIT 1", (remote_ip, scope, device, before_ts))
        return bool(r)

    # --- size cap ---------------------------------------------------------------

    def size_bytes(self):
        db = self.db()
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        free = db.execute("PRAGMA freelist_count").fetchone()[0]
        size = db.execute("PRAGMA page_size").fetchone()[0]
        return (pages - free) * size

    def prune(self):
        """Delete the oldest connections so the log fits in 90% of the cap.

        Pages are not freed in proportion to deleted rows (half-empty pages stay
        in use), so "delete a bit, measure, repeat" over-deletes. Instead the
        average size of a row is estimated once and just enough of the oldest
        rows are removed in one go. Returns the number of rows deleted."""
        size = self.size_bytes()
        if size <= self.max_bytes:
            return 0
        total = self.q("SELECT COUNT(*) FROM conns")[0][0]
        if not total:
            log.warning("database is %d MB with an empty connection log; the cap (%d MB) "
                        "is too small", size // 1048576, self.max_bytes // 1048576)
            return 0
        per_row = size / total
        want = int((size - self.max_bytes * 0.9) / per_row) + 1
        with self.tx() as db:
            deleted = db.execute(
                "DELETE FROM conns WHERE id IN (SELECT id FROM conns WHERE end_ts IS NOT"
                " NULL ORDER BY id LIMIT ?)", (want,)).rowcount
        if deleted:
            with self.write_lock:
                self.db().execute("PRAGMA incremental_vacuum")
            log.info("log over %d MB: deleted the %d oldest connections",
                     self.max_bytes // 1048576, deleted)
        return deleted

    # --- things managed in the UI ----------------------------------------------

    def subnets(self):
        return [dict(zip(("id", "name", "cidr", "color"), r))
                for r in self.q("SELECT id, name, cidr, color FROM subnets ORDER BY name")]

    def devices(self):
        return dict(self.q("SELECT ip, name FROM devices"))

    def rules(self, enabled_only=False):
        sql = "SELECT id, name, expr, category, severity, enabled, updated FROM rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        return [dict(zip(("id", "name", "expr", "category", "severity", "enabled",
                          "updated"), r)) for r in self.q(sql + " ORDER BY id")]

    def verdicts(self):
        return {r[0]: {"verdict": r[1], "note": r[2], "ts": r[3]}
                for r in self.q("SELECT target, verdict, note, ts FROM verdicts")}

    def geo_cached(self, ip):
        r = self.q("SELECT cc, region, city, lat, lon, org, source FROM geo_cache WHERE ip=?",
                   (ip,))
        return dict(zip(("cc", "region", "city", "lat", "lon", "org", "source"), r[0])) if r else None

    def geo_store(self, ip, g, source):
        with self.tx() as db:
            db.execute("INSERT OR REPLACE INTO geo_cache VALUES (?,?,?,?,?,?,?,?,?)",
                       (ip, g.get("cc"), g.get("region"), g.get("city"), g.get("lat"),
                        g.get("lon"), g.get("org"), source, time.time()))
