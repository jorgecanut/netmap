"""Wires the parts together and runs the background loops.

    store    SQLite log + UI-managed settings            (store.py)
    geo      offline DB-IP + ip-api fallback              (geo.py)
    threats  blocklists with categories/severities        (threats.py)
    engine   your behaviour rules                         (rules.py)
    tracker  open/classify/log/close + map views          (tracker.py)
    feed     OpenWrt router over SSH (Network tab)        (router.py)
    local    this machine's sockets (This machine tab)    (local.py)
    web      HTTP server + JSON API                       (web.py)
"""

import logging
import signal
import sys
import threading
import time
import webbrowser

from . import VERSION, geo, local, tailscale
from .auth import Auth
from .router import RouterFeed
from .rules import Engine
from .store import Store
from .threats import Threats
from .tracker import Tracker
from .util import Throttle
from .web import make_server

log = logging.getLogger("netmap")
throttle = Throttle(log)


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.allowed_hosts = cfg.allowed_hosts
        self.store = Store(cfg.db_path, cfg.max_db_mb)
        self.auth = Auth(self.store, disabled=cfg.no_auth)
        self.geo = geo.Geo(self.store, cfg.geo_db_path, download=not cfg.no_geo_download,
                           online=not cfg.no_geo_online)
        if cfg.home:
            self.geo.home = {"lat": cfg.home[0], "lon": cfg.home[1], "city": "", "cc": ""}
        self.threats = Threats(cfg.data_dir)
        self.engine = Engine(self.store)
        self.tracker = Tracker(self.store, self.geo, self.threats, self.engine, cfg.interval)
        self.feed = RouterFeed(self.store, cfg.data_dir, self.tracker)
        self.tailscale = tailscale.Tailscale(self.geo)
        self.rates = local.Rates()
        self.scan_error = None
        self.server = None

    # --- data for the page header ----------------------------------------------

    def meta(self, scope):
        th = self.threats.status()
        m = {"version": VERSION, "home": self.geo.home, "geo_state": self.geo.state,
             "geo_offline": self.geo.offline_state, "attribution": geo.ATTRIBUTION,
             "threat": {"loaded": th["loaded"],
                        "errors": [s["key"] for s in th["sources"] if s["error"]]},
             "subnets": [{"name": s["name"], "cidr": s["cidr"], "color": s["color"]}
                         for s in self.store.subnets()]}
        if scope == "local":
            m.update(collector=local.collector_name(), scan_error=self.scan_error,
                     rates={"down": self.rates.down, "up": self.rates.up},
                     tailnet=self.tailscale.view())
        else:
            st = self.feed.status
            m["router"] = {"configured": bool(self.feed.config()["host"]),
                           "enabled": self.feed.config()["enabled"],
                           "state": st["state"], "error": st["error"], "dns": st["dns"]}
        return m

    # --- loops ---------------------------------------------------------------------

    def _local_loop(self):
        while True:
            now = time.time()
            try:
                rows = local.collect()
                self.scan_error = None
                throttle.ok("scan", "local socket scan works again")
            except RuntimeError as e:
                self.scan_error = str(e)
                throttle.fail("scan", "local socket scan failed: %s", e)
                rows = []
            try:
                self.tracker.poll_local(rows, now)
            except Exception:
                log.exception("could not record this machine's connections")
            self.rates.sample(now)
            time.sleep(self.cfg.interval)

    def _housekeeping(self):
        last_prune = 0
        while True:
            time.sleep(30)
            now = time.time()
            try:
                self.store.heartbeat()
                self.tracker.expire_recent(now)
                if now - last_prune > 600:
                    self.store.prune()
                    last_prune = now
            except Exception:
                log.exception("housekeeping failed (will retry in 30 s)")

    # --- one-time import of the previous version's history ---------------------------

    def import_old_history(self):
        """Versions up to 2026.11.15.3 kept a capped JSON history of this machine.
        Import it once so upgrading loses nothing; the file is then renamed."""
        import json
        import os
        path = os.path.join(self.cfg.data_dir, "netmap_history.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                entries = json.load(f)
            n = 0
            with self.store.tx() as db:
                for h in entries if isinstance(entries, list) else []:
                    if not isinstance(h, dict) or not h.get("ip"):
                        continue
                    port, _, proto = ((h.get("ports") or ["0/tcp"])[0]).partition("/")
                    g = h.get("geo") or {}
                    self.store.insert_conn(db, {
                        "scope": "local", "direction": "out", "proto": proto or "tcp",
                        "device": "local", "proc": (h.get("procs") or ["?"])[0],
                        "remote_ip": h["ip"], "remote_port": int(port or 0),
                        "start_ts": float(h.get("first_seen") or 0),
                        "end_ts": float(h.get("last_seen") or h.get("first_seen") or 0),
                        "cc": g.get("countryCode"), "city": g.get("city"),
                        "org": g.get("isp")})
                    n += 1
            os.replace(path, path + ".imported")
            log.info("imported %d addresses from the old %s", n, path)
        except (OSError, ValueError, TypeError) as e:
            log.warning("could not import old history %s (%s); left in place", path, e)

    # --- lifecycle -------------------------------------------------------------------

    def shutdown(self):
        log.info("stopping")
        try:
            now = time.time()
            for scope in ("local", "network"):
                for key in list(self.tracker.live[scope]):
                    self.tracker.close(scope, key, now)
        except Exception:
            log.exception("could not close open connections in the log on exit")
        if self.server:
            self.server.shutdown()

    def run(self):
        cfg = self.cfg
        log.info("NetMap v%s starting (data in %s)", VERSION, cfg.data_dir)
        log.info("reading this machine's sockets from %s", local.collector_name())
        self.store.close_dangling()
        self.import_old_history()
        self.auth.announce_setup()
        self.engine.reload()
        self.geo.start()
        self.threats.start()
        self.feed.start()
        self.tailscale.start()
        for target, name in ((self._local_loop, "local-scan"),
                             (self._housekeeping, "housekeeping")):
            threading.Thread(target=target, name=name, daemon=True).start()

        try:
            self.server = make_server(self, cfg.bind, cfg.port)
        except OSError as e:
            log.error("cannot listen on %s:%d (%s). If NetMap is already running that "
                      "is expected; otherwise another program holds the port - try "
                      "--port %d", cfg.bind, cfg.port, e, cfg.port + 1)
            if not cfg.no_browser:
                webbrowser.open("http://localhost:%d" % cfg.port)
            return 1
        if cfg.loopback_only:
            log.info("serving on http://localhost:%d", cfg.port)
        else:
            log.info("listening on %s:%d - reachable from your network", cfg.bind, cfg.port)
            log.info("browsers may use: %s", ", ".join(sorted(cfg.allowed_hosts)))
        if cfg.no_auth:
            log.warning("login disabled (--no-auth): anyone who can reach the port sees "
                        "everything")
        if hasattr(signal, "SIGTERM") and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, lambda *_: threading.Thread(
                target=self.shutdown, daemon=True).start())
        if not cfg.no_browser:
            threading.Timer(1.0, lambda: webbrowser.open(
                "http://localhost:%d" % cfg.port)).start()
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.shutdown()
        log.info("NetMap stopped")
        return 0


def main(argv=None):
    from . import config
    from .util import setup_logging
    setup_logging()
    cfg = config.parse(argv)
    if cfg.reset_password:
        Auth(Store(cfg.db_path, cfg.max_db_mb)).reset_password()
        print("admin password cleared; the next start prints a setup code")
        return 0
    return App(cfg).run()


if __name__ == "__main__":
    sys.exit(main())
