"""The tracker: turns raw sockets / router events into logged, classified
connections, and builds the views the web page shows.

Data flow for every connection (both tabs):

    open()  -> location (geo) -> blocklists (threats) -> verdicts -> rules
            -> INSERT into the log -> kept in `live` while open
    close() -> bytes/duration -> rules again (closed=True) -> UPDATE the log
            -> kept in `recent` for FADE seconds so the map can fade it out
"""

import collections
import ipaddress
import logging
import threading
import time

from . import router as rtr
from .rules import context_for
from .threats import SEV
from .util import Throttle, is_private, is_public, parse_ip

log = logging.getLogger("netmap.tracker")
throttle = Throttle(log)

FADE = 90                 # seconds a closed connection stays (faded) on the live map
LOCAL_GRACE_POLLS = 3     # local: missing from this many scans -> closed
DNS_MAX = 100000
SCOPES = ("local", "network")


class Tracker:
    def __init__(self, store, geo, threats, engine, interval=2.0):
        self.store, self.geo, self.threats, self.engine = store, geo, threats, engine
        self.interval = interval
        self.lock = threading.RLock()
        self.live = {s: {} for s in SCOPES}
        self.recent = {s: {} for s in SCOPES}
        self.ignored = {s: set() for s in SCOPES}
        self.local_seen = {}
        self.wan_ips = set()
        self.leases = {}
        self.dns = collections.OrderedDict()
        self.subnets, self.devices, self.verdicts = [], {}, {}
        self.reload_config()
        geo.on_result.append(self._geo_result)

    # --- configuration managed in the UI -------------------------------------------

    def reload_config(self):
        subnets = []
        for s in self.store.subnets():
            try:
                subnets.append((ipaddress.ip_network(s["cidr"], strict=False), s))
            except ValueError:
                log.warning("subnet %r has an invalid range %r; ignored", s["name"], s["cidr"])
        subnets.sort(key=lambda x: -x[0].prefixlen)       # most specific first
        with self.lock:
            self.subnets = subnets
            self.devices = self.store.devices()
            self.verdicts = self.store.verdicts()

    def subnet_for(self, ip):
        a = parse_ip(ip)
        if a is None:
            return None
        for net, s in self.subnets:
            if a.version == net.version and a in net:
                return s
        return None

    def is_local(self, ip):
        return self.subnet_for(ip) is not None or is_private(ip)

    # --- rule environment ------------------------------------------------------------

    def device_name(self, conn):
        if conn["scope"] == "local":
            return conn.get("proc") or "this machine"
        d = conn["device"]
        if d == "router":
            return "router"
        return self.devices.get(d) or (self.leases.get(d) or {}).get("name") or d

    def subnet_name(self, ip):
        s = self.subnet_for(ip) if ip else None
        return s["name"] if s else ""

    def seen_country(self, conn):
        return self.store.device_seen_country(conn["scope"], conn["device"], conn["cc"],
                                              conn["start_ts"])

    def seen_remote(self, conn):
        return self.store.device_seen_remote(conn["scope"], conn["device"],
                                             conn["remote_ip"], conn["start_ts"])

    # --- classification ------------------------------------------------------------------

    def verdict_for(self, conn):
        v = self.verdicts
        if not v:
            return None
        for target in ("ip:" + conn["remote_ip"], "device:" + conn["device"]):
            if target in v:
                return v[target]["verdict"]
        dom = conn.get("domain")
        if dom:
            for target, info in v.items():
                if target.startswith("domain:"):
                    suf = target[7:]
                    if dom == suf or dom.endswith("." + suf):
                        return info["verdict"]
        return None

    def _classify(self, conn, closed=False):
        """Fill flags + severity. Returns False if a verdict says 'ignore'."""
        verdict = self.verdict_for(conn)
        if verdict == "ignore":
            return False
        if not closed:
            # Only public addresses: FireHOL lists private ranges as "bogons",
            # which would flag every connection between your own subnets.
            conn["list_flags"] = (self.threats.match(conn["remote_ip"])
                                  if is_public(conn["remote_ip"]) else [])
        flags = list(conn.get("list_flags", []))
        if verdict == "suspicious":
            flags.append({"src": "verdict", "name": "Marked suspicious",
                          "category": "user", "severity": SEV["medium"]})
        conn["flags"] = flags                     # rules see the list flags
        flags = flags + self.engine.run(context_for(conn, self))
        if verdict == "trusted":
            for f in flags:
                f["suppressed"] = True
        conn["flags"] = flags
        conn["severity"] = max([f["severity"] for f in flags if not f.get("suppressed")],
                               default=0)
        return True

    def _geo(self, conn):
        g = self.geo.lookup(conn["remote_ip"]) if is_public(conn["remote_ip"]) else None
        if g:
            for k in ("cc", "region", "city", "lat", "lon", "org"):
                conn[k] = g.get(k)

    # --- open / close ----------------------------------------------------------------------

    def open(self, scope, key, conn):
        with self.lock:
            if key in self.live[scope] or key in self.ignored[scope]:
                return
            conn["scope"] = scope
            conn.setdefault("start_ts", time.time())
            self._geo(conn)
            if not self._classify(conn):
                self.ignored[scope].add(key)
                return
            with self.store.tx() as db:
                conn["id"] = self.store.insert_conn(db, conn)
            self.live[scope][key] = conn
            self.recent[scope].pop(key, None)

    def close(self, scope, key, end_ts, bytes_out=None, bytes_in=None):
        with self.lock:
            conn = self.live[scope].pop(key, None)
            if conn is None:
                self.ignored[scope].discard(key)
                return
            conn["end_ts"] = max(end_ts, conn["start_ts"])
            if bytes_out is not None:
                conn["bytes_out"] = bytes_out
            if bytes_in is not None:
                conn["bytes_in"] = bytes_in
            self._classify(conn, closed=True)
            with self.store.tx() as db:
                self.store.close_conn(db, conn)
            self.recent[scope][key] = conn

    # --- this machine ------------------------------------------------------------------

    def poll_local(self, rows, now):
        grace = self.interval * LOCAL_GRACE_POLLS + 1
        with self.lock:
            for r in rows:
                if not is_public(r["ip"]):
                    continue
                key = "%s|%s|%s|%s" % (r["ip"], r["port"], r["proto"], r["pid"])
                self.local_seen[key] = now
                c = self.live["local"].get(key)
                if c is not None:
                    c["status"] = r["status"]
                    continue
                self.open("local", key, {
                    "direction": "out", "proto": r["proto"], "device": "local",
                    "proc": r["proc"], "pid": r["pid"], "local_port": r.get("local_port"),
                    "remote_ip": r["ip"], "remote_port": r["port"], "start_ts": now,
                    "status": r["status"]})
            for key in [k for k, t in self.local_seen.items() if now - t > grace]:
                last = self.local_seen.pop(key)
                self.close("local", key, last)

    # --- router (called by router.RouterFeed) ---------------------------------------------

    def _router_conn(self, ev):
        c = rtr.classify(ev, self.is_local, self.wan_ips)
        if c is None:
            return None, None
        a = parse_ip(c["remote_ip"])
        if a is None or a.is_multicast or a.is_unspecified or c["remote_ip"].endswith(".255"):
            return None, None
        key = "ct:" + ev["id"] if ev.get("id") else "ct:%s|%s|%s|%s|%s" % (
            ev["proto"], ev["o"]["src"], ev["o"].get("sport"), ev["o"]["dst"],
            ev["o"].get("dport"))
        c["proto"] = ev["proto"]
        return key, c

    def router_event(self, ev):
        key, c = self._router_conn(ev)
        if key is None:
            return
        # Events stream in real time, so our clock is as good as the router's -
        # and better while the router's clock is wrong (before NTP after a boot).
        now = time.time()
        ts = ev.get("ts")
        if ts is None or abs(ts - now) > 30:
            if ts is not None:
                throttle.fail("clock", "router clock is %.0f s off; using NetMap's clock",
                              ts - now)
            ts = now
        if ev["event"] == "NEW":
            c["domain"] = self.dns.get(c["remote_ip"])
            c["start_ts"] = ts
            for k in ("bytes_out", "bytes_in"):
                c.pop(k, None)
            self.open("network", key, c)
        elif ev["event"] == "DESTROY":
            if key not in self.live["network"] and key not in self.ignored["network"]:
                return             # opened before NetMap was watching; nothing logged
            self.close("network", key, ts, c.get("bytes_out"), c.get("bytes_in"))

    def router_snapshot(self, events):
        """Connections open right now. Open what we miss, close what is gone
        (a DESTROY lost while the SSH session was down)."""
        now, present = time.time(), set()
        with self.lock:
            for ev in events:
                key, c = self._router_conn(ev)
                if key is None:
                    continue
                present.add(key)
                if key not in self.live["network"]:
                    c["domain"] = self.dns.get(c["remote_ip"])
                    c["start_ts"] = now
                    c.pop("bytes_out", None), c.pop("bytes_in", None)
                    self.open("network", key, c)
            for key in [k for k in self.live["network"] if k not in present]:
                self.close("network", key, now)
            self.ignored["network"] &= present
        log.info("router snapshot: %d connections open", len(present))

    def router_leases(self, leases):
        with self.lock:
            self.leases = leases

    def router_dns(self, domain, ip):
        with self.lock:
            self.dns[ip] = domain
            self.dns.move_to_end(ip)
            if len(self.dns) > DNS_MAX:
                self.dns.popitem(last=False)

    def _geo_result(self, ip, g):
        with self.lock:
            for scope in SCOPES:
                for c in self.live[scope].values():
                    if c["remote_ip"] == ip and not c.get("cc"):
                        for k in ("cc", "region", "city", "lat", "lon", "org"):
                            c[k] = g.get(k)
        try:
            self.store.fill_geo(ip, g)
        except Exception:
            log.exception("could not back-fill the location of %s in the log", ip)

    # --- housekeeping ------------------------------------------------------------------------

    def expire_recent(self, now):
        with self.lock:
            for scope in SCOPES:
                r = self.recent[scope]
                for key in [k for k, c in r.items() if now - c["end_ts"] > FADE]:
                    del r[key]

    # --- views for the web page --------------------------------------------------------------

    def client_conn(self, c, now):
        """A connection as the browser sees it."""
        s = self.subnet_for(c["device"]) if c["scope"] == "network" else None
        open_ = c.get("end_ts") is None
        return {"id": c.get("id"), "dir": c["direction"], "proto": c["proto"],
                "device": c["device"], "name": self.device_name(c),
                "subnet": s["name"] if s else "", "color": s["color"] if s else "",
                "proc": c.get("proc"), "port": c.get("remote_port"),
                "local_port": c.get("local_port"), "remote_ip": c["remote_ip"],
                "domain": c.get("domain") or "", "start": c["start_ts"],
                "end": c.get("end_ts"), "active": open_,
                "age": 0 if open_ else round(now - c["end_ts"], 1),
                "bytes_out": c.get("bytes_out"), "bytes_in": c.get("bytes_in"),
                "geo": _geo_of(c), "severity": c.get("severity", 0),
                "flags": c.get("flags") or []}

    def live_view(self, scope, now=None):
        now = now or time.time()
        with self.lock:
            conns = list(self.live[scope].values()) + list(self.recent[scope].values())
            out = self._aggregate(scope, conns, now)
        return out

    def at_view(self, scope, t):
        conns = self.store.conns_at(scope, t)
        with self.lock:
            for c in conns:
                c["end_ts_real"] = c["end_ts"]
                c["end_ts"] = None                 # open at t, by definition
            return self._aggregate(scope, conns, t)

    def _aggregate(self, scope, conns, now):
        hosts = {}
        for c in conns:
            cc = self.client_conn(c, now)
            h = hosts.get(c["remote_ip"])
            if h is None:
                h = hosts[c["remote_ip"]] = {
                    "ip": c["remote_ip"], "geo": cc["geo"], "domain": cc["domain"],
                    "conns": [], "active": 0, "severity": 0, "flags": {},
                    "devices": {}, "dirs": set(), "age": cc["age"]}
            h["conns"].append(cc)
            h["active"] += cc["active"]
            h["age"] = min(h["age"], cc["age"])
            h["domain"] = h["domain"] or cc["domain"]
            h["geo"] = h["geo"] or cc["geo"]
            h["severity"] = max(h["severity"], cc["severity"])
            h["dirs"].add(cc["dir"])
            for f in cc["flags"]:
                h["flags"].setdefault(f["name"], f)
            if scope == "network":
                h["devices"].setdefault(c["device"], {
                    "ip": c["device"], "name": cc["name"], "subnet": cc["subnet"],
                    "color": cc["color"]})
            else:
                h["devices"].setdefault(cc["proc"], {"ip": "", "name": cc["proc"],
                                                     "subnet": "", "color": ""})
        out, countries, devices = [], set(), set()
        for h in hosts.values():
            h["conns"].sort(key=lambda x: (not x["active"], -x["start"]))
            h["count"] = len(h["conns"])
            h["conns"] = h["conns"][:40]
            h["flags"] = sorted(h["flags"].values(), key=lambda f: -f["severity"])
            h["devices"] = list(h["devices"].values())
            h["dirs"] = sorted(h["dirs"])
            if h["geo"]:
                countries.add(h["geo"]["cc"])
            devices.update(d["ip"] or d["name"] for d in h["devices"])
            out.append(h)
        out.sort(key=lambda h: (-h["severity"], -h["active"], h["age"], h["ip"]))
        return {"hosts": out, "stats": {
            "active": sum(h["active"] for h in out), "hosts": len(out),
            "flagged": sum(1 for h in out if h["severity"] > 0),
            "countries": len(countries), "devices": len(devices)}}

    def history(self, scope, before_id=None, limit=200, min_severity=0, text=None,
                subnets=None):
        keep = None
        if subnets:
            wanted = set(subnets)
            keep = lambda c: self.subnet_name(c["device"]) in wanted   # noqa: E731
        rows, last = self.store.history(scope, before_id, limit, min_severity, text, keep)
        now = time.time()
        with self.lock:
            return [self.client_conn(c, now) for c in rows], last

    def known_devices(self):
        """Devices seen on the network, for naming them in the UI."""
        with self.lock:
            ips = {c["device"] for c in self.live["network"].values()} | set(self.leases)
            out = []
            for ip in sorted(ips, key=_ip_sort):
                if ip == "router":
                    continue
                s = self.subnet_for(ip)
                out.append({"ip": ip, "name": self.devices.get(ip, ""),
                            "lease_name": (self.leases.get(ip) or {}).get("name", ""),
                            "mac": (self.leases.get(ip) or {}).get("mac", ""),
                            "subnet": s["name"] if s else ""})
            return out

    def suggested_subnets(self):
        """/24s (IPv4) with devices but no configured subnet."""
        with self.lock:
            ips = {c["device"] for c in self.live["network"].values()} | set(self.leases)
            counts = collections.Counter()
            for ip in ips:
                a = parse_ip(ip)
                if a and a.version == 4 and self.subnet_for(ip) is None:
                    counts[str(ipaddress.ip_network("%s/24" % ip, strict=False))] += 1
            return [{"cidr": k, "devices": n} for k, n in counts.most_common()]


def _geo_of(c):
    if c.get("lat") is None or c.get("lon") is None:
        return None
    return {"lat": c["lat"], "lon": c["lon"], "cc": c.get("cc") or "",
            "region": c.get("region") or "", "city": c.get("city") or "",
            "org": c.get("org") or ""}


def _ip_sort(ip):
    a = parse_ip(ip)
    return (a.version, int(a)) if a else (9, 0)
