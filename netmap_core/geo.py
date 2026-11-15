"""IP geolocation: offline database first, online lookup as a fallback.

Lookup order for each remote IP:
  1. memory cache            (instant)
  2. geo_cache table         (results of earlier online lookups)
  3. offline DB-IP database  (geoip.sqlite, rebuilt monthly from DB-IP Lite)
  4. ip-api.com              (only if 1-3 have nothing; stored in geo_cache)

The offline database is DB-IP "IP to City Lite" + "IP to ASN Lite", licensed
CC BY 4.0, which requires the attribution shown on the map. It is downloaded
(~93 MB compressed, ~720 MB as SQLite, ~2 minutes) in the background; until that
finishes the online lookup covers everything.
"""

import csv
import gzip
import io
import json
import logging
import os
import queue
import sqlite3
import threading
import time
import urllib.error
import urllib.request

from .util import Throttle, ip_key, is_public

log = logging.getLogger("netmap.geo")
throttle = Throttle(log)

ATTRIBUTION = '<a href="https://db-ip.com">IP Geolocation by DB-IP</a>'
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.csv.gz"
IPAPI_BATCH = ("http://ip-api.com/batch?fields=status,message,countryCode,regionName,"
               "city,lat,lon,isp,org,query")
IPAPI_SELF = "http://ip-api.com/json/?fields=status,countryCode,regionName,city,lat,lon,query"
IPAPI_GAP = 4.5          # seconds between batch calls: free tier allows 15/minute
MEM_MAX = 50000


def _http(url, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "netmap", "Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=timeout)


class OfflineDB:
    """Read side of geoip.sqlite (built by `build`)."""

    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        self.generation = 0          # bumped on rebuild so threads reopen the file

    def _db(self):
        st = getattr(self._local, "st", None)
        if st is None or st[1] != self.generation:
            if not os.path.exists(self.path):
                return None
            db = sqlite3.connect("file:%s?mode=ro" % self.path, uri=True,
                                 check_same_thread=False)
            st = self._local.st = (db, self.generation)
        return st[0]

    def available(self):
        return os.path.exists(self.path)

    def built_month(self):
        db = self._db()
        if db is None:
            return None
        try:
            return db.execute("SELECT value FROM meta WHERE key='month'").fetchone()[0]
        except (sqlite3.Error, TypeError) as e:
            throttle.fail("offline-meta", "offline geo database %s looks damaged (%s); "
                          "delete it and it will be rebuilt", self.path, e)
            return None

    def lookup(self, ip):
        db = self._db()
        if db is None:
            return None
        k = ip_key(ip)
        try:
            r = db.execute("SELECT end, cc, region, city, lat, lon FROM city WHERE start<=?"
                           " ORDER BY start DESC LIMIT 1", (k,)).fetchone()
            if not r or r[0] < k or not r[1] or r[1] == "ZZ":
                return None
            g = {"cc": r[1], "region": r[2], "city": r[3], "lat": r[4], "lon": r[5],
                 "org": ""}
            a = db.execute("SELECT end, org FROM asn WHERE start<=? ORDER BY start DESC"
                           " LIMIT 1", (k,)).fetchone()
            if a and a[0] >= k:
                g["org"] = a[1]
            return g
        except sqlite3.Error as e:
            throttle.fail("offline-read", "offline geo database unreadable (%s): %s",
                          self.path, e)
            return None


def build(path, month, fetch=None):
    """Download DB-IP Lite for `month` (YYYY-MM) and build `path` atomically.
    `fetch(kind, month)` returns an iterable of CSV text lines (tests inject one)."""
    fetch = fetch or _fetch_dbip
    tmp = path + ".building"
    if os.path.exists(tmp):
        os.remove(tmp)
    db = sqlite3.connect(tmp)
    db.executescript("""
        PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE city (start BLOB PRIMARY KEY, end BLOB, cc TEXT, region TEXT,
                           city TEXT, lat REAL, lon REAL) WITHOUT ROWID;
        CREATE TABLE asn (start BLOB PRIMARY KEY, end BLOB, org TEXT) WITHOUT ROWID;
    """)
    t0 = time.time()
    n_city = _import(db, "city", fetch("city", month),
                     lambda r: (ip_key(r[0]), ip_key(r[1]), r[3], r[4], r[5],
                                float(r[6]), float(r[7])))
    n_asn = _import(db, "asn", fetch("asn", month),
                    lambda r: (ip_key(r[0]), ip_key(r[1]), r[3] if len(r) > 3 else ""))
    db.execute("INSERT INTO meta VALUES ('month', ?)", (month,))
    db.commit()
    db.close()
    os.replace(tmp, path)
    log.info("offline geo database %s built: %d city ranges, %d ASN ranges in %.0fs",
             month, n_city, n_asn, time.time() - t0)


def _import(db, table, lines, convert):
    n, batch, bad = 0, [], 0
    marks = ",".join("?" * (7 if table == "city" else 3))
    for row in csv.reader(lines):
        try:
            batch.append(convert(row))
        except (ValueError, IndexError):
            bad += 1                 # malformed line in the CSV; counted, then skipped
            continue
        if len(batch) >= 50000:
            db.executemany("INSERT OR REPLACE INTO %s VALUES (%s)" % (table, marks), batch)
            n += len(batch)
            batch = []
    if batch:
        db.executemany("INSERT OR REPLACE INTO %s VALUES (%s)" % (table, marks), batch)
        n += len(batch)
    if bad:
        log.warning("DB-IP %s: skipped %d malformed lines (format change?)", table, bad)
    return n


def _fetch_dbip(kind, month):
    url = DBIP_URL.format(kind=kind, month=month)
    log.info("downloading %s", url)
    resp = _http(url, timeout=120)
    return io.TextIOWrapper(gzip.GzipFile(fileobj=resp), encoding="utf-8")


def _months_to_try(now=None):
    t = time.gmtime(now or time.time())
    this = "%04d-%02d" % (t.tm_year, t.tm_mon)
    prev = "%04d-%02d" % ((t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12))
    return [this, prev]               # early in a month the new file may not exist yet


class Geo:
    def __init__(self, store, geo_db_path, download=True, online=True):
        self.store = store
        self.offline = OfflineDB(geo_db_path)
        self.download = download
        self.online = online
        self.mem = {}
        self.mem_lock = threading.Lock()
        self.pending = queue.Queue()
        self.queued = set()
        self.state = "waiting"        # waiting | ok | offline  (online lookups)
        self.offline_state = "missing"
        self.on_result = []           # callbacks(ip, geo) for back-filling
        self.home = None

    # --- public ------------------------------------------------------------------

    def lookup(self, ip):
        """Location dict or None (None = not known yet; an online lookup is queued)."""
        if not is_public(ip):
            return None
        with self.mem_lock:
            g = self.mem.get(ip)
        if g is not None:
            return g or None          # {} = known to be unlocatable
        g = self.store.geo_cached(ip) or self.offline.lookup(ip)
        if g:
            self._remember(ip, g)
            return g
        self._enqueue(ip)
        return None

    def start(self):
        if self.online:
            threading.Thread(target=self._online_worker, name="geo-online",
                             daemon=True).start()
        else:
            self.state = "off"
        if self.download:
            threading.Thread(target=self._offline_worker, name="geo-offline",
                             daemon=True).start()
        self.offline_state = "ok" if self.offline.available() else "missing"

    def locate_home(self):
        try:
            with _http(IPAPI_SELF, timeout=12) as r:
                d = json.loads(r.read().decode())
            if d.get("status") == "success":
                self.home = {"lat": d["lat"], "lon": d["lon"], "city": d.get("city", ""),
                             "cc": d.get("countryCode", "")}
                log.info("home location: %s, %s", self.home["city"], self.home["cc"])
                return True
            log.warning("ip-api could not locate this network: %s", d)
        except (OSError, ValueError) as e:
            throttle.fail("home", "home location lookup failed (ip-api.com): %s", e)
        return False

    # --- internals ---------------------------------------------------------------

    def _remember(self, ip, g):
        with self.mem_lock:
            if len(self.mem) >= MEM_MAX:
                self.mem.clear()
            self.mem[ip] = g

    def _enqueue(self, ip):
        if not self.online:
            return
        with self.mem_lock:
            if ip in self.queued:
                return
            self.queued.add(ip)
        self.pending.put(ip)

    def _online_worker(self):
        while True:
            if self.home is None:
                self.locate_home()
            batch = [self.pending.get()]
            while len(batch) < 100:
                try:
                    batch.append(self.pending.get_nowait())
                except queue.Empty:
                    break
            try:
                with _http(IPAPI_BATCH, data=json.dumps(batch).encode(), timeout=15) as r:
                    results = json.loads(r.read().decode())
                self.state = "ok"
                throttle.ok("ipapi", "ip-api.com reachable again")
            except (OSError, ValueError) as e:
                self.state = "offline"
                throttle.fail("ipapi", "online geolocation failed for %d IPs (ip-api.com): %s",
                              len(batch), e)
                with self.mem_lock:
                    self.queued.difference_update(batch)   # retry when seen again
                time.sleep(30)
                continue
            for r in results:
                ip = r.get("query")
                if not ip:
                    continue
                if r.get("status") == "success":
                    g = {"cc": r.get("countryCode", ""), "region": r.get("regionName", ""),
                         "city": r.get("city", ""), "lat": r.get("lat"), "lon": r.get("lon"),
                         "org": r.get("org") or r.get("isp") or ""}
                    try:
                        self.store.geo_store(ip, g, "ip-api")
                    except sqlite3.Error as e:
                        log.warning("could not cache location of %s: %s", ip, e)
                    self._remember(ip, g)
                    for cb in self.on_result:
                        try:
                            cb(ip, g)
                        except Exception:
                            log.exception("geo result callback failed for %s", ip)
                else:
                    log.debug("ip-api has no location for %s: %s", ip, r.get("message"))
                    self._remember(ip, {})
            with self.mem_lock:
                self.queued.difference_update(batch)
            time.sleep(IPAPI_GAP)

    def _offline_worker(self):
        while True:
            want = _months_to_try()
            have = self.offline.built_month()
            if have not in want or (have != want[0] and self._last_try_old()):
                for month in want:
                    if month == have:
                        break
                    try:
                        self.offline_state = "building"
                        build(self.offline.path, month)
                        self.offline.generation += 1
                        with self.mem_lock:
                            self.mem.clear()
                        self.offline_state = "ok"
                        break
                    except urllib.error.HTTPError as e:
                        if e.code == 404:
                            log.info("DB-IP %s not published yet; trying the month before",
                                     month)
                            continue
                        throttle.fail("dbip", "offline geo download failed (%s): %s", month, e)
                        break
                    except (OSError, EOFError, sqlite3.Error) as e:
                        throttle.fail("dbip", "offline geo database build failed (%s): %s",
                                      month, e)
                        break
                self.store.set("geo_last_try", time.time())
                self.offline_state = "ok" if self.offline.available() else "missing"
            time.sleep(6 * 3600)

    def _last_try_old(self):
        return time.time() - (self.store.get("geo_last_try", 0) or 0) > 86400
