"""Tracker end-to-end with a real database and fake geo/threat sources."""

import os
import tempfile
import time
import unittest

from netmap_core import router, rules, threats
from netmap_core.store import Store
from netmap_core.tracker import Tracker
from tests import samples as S


class FakeGeo:
    def __init__(self):
        self.on_result = []
        self.places = {"93.184.216.34": {"cc": "US", "city": "Los Angeles", "lat": 34.0,
                                         "lon": -118.2, "region": "CA", "org": "Edgecast"},
                       "142.250.1.1": {"cc": "US", "city": "Mountain View", "lat": 37.4,
                                       "lon": -122.1, "region": "CA", "org": "Google"}}

    def lookup(self, ip):
        return self.places.get(ip)


class FakeThreats:
    def __init__(self, bad):
        self.bad = bad

    def match(self, ip):
        return threats.flags_for(self.bad.get(ip, set()))


def make(bad=None):
    store = Store(os.path.join(tempfile.mkdtemp(), "t.sqlite"))
    engine = rules.Engine(store)
    t = Tracker(store, FakeGeo(), FakeThreats(bad or {}), engine)
    with store.tx() as db:
        db.execute("INSERT INTO subnets (name, cidr, color) VALUES ('LAN','192.168.2.0/24','#3987e5')")
        db.execute("INSERT INTO subnets (name, cidr, color) VALUES ('IoT','192.168.3.0/24','#9085e9')")
    t.reload_config()
    t.wan_ips.add(S.WAN)
    return t, store, engine


def ev(line):
    return router.parse_conntrack(line)


class RouterFlow(unittest.TestCase):
    def test_open_close_logged_with_geo_dns_and_bytes(self):
        t, store, _ = make()
        t.router_dns("example.com", "93.184.216.34")
        t.router_event(ev(S.NEW_OUT))
        live = t.live_view("network")
        self.assertEqual(live["stats"]["active"], 1)
        h = live["hosts"][0]
        self.assertEqual((h["domain"], h["geo"]["city"]), ("example.com", "Los Angeles"))
        self.assertEqual(h["devices"][0]["subnet"], "LAN")
        t.router_event(ev(S.DESTROY_OUT))
        row = store.history("network")[0][0]
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (1200, 9000))
        self.assertAlmostEqual(row["end_ts"] - row["start_ts"], 12.5)
        self.assertEqual(row["city"], "Los Angeles")           # location at the time
        self.assertEqual(t.live_view("network")["hosts"][0]["active"], 0)   # fading

    def test_destroy_without_new_is_ignored(self):
        t, store, _ = make()
        t.router_event(ev(S.DESTROY_OUT))
        self.assertEqual(store.q("SELECT COUNT(*) FROM conns")[0][0], 0)

    def test_snapshot_opens_and_closes(self):
        t, store, _ = make()
        t.router_event(ev(S.NEW_OUT))                          # will be missing from snapshot
        t.router_snapshot([ev(l) for l in S.SNAPSHOT])
        live = {h["ip"] for h in t.live_view("network")["hosts"] if h["active"]}
        self.assertEqual(live, {"142.250.1.1", "162.159.200.1"})
        closed = store.q("SELECT COUNT(*) FROM conns WHERE end_ts IS NOT NULL")[0][0]
        self.assertEqual(closed, 1)
        t.router_snapshot([ev(l) for l in S.SNAPSHOT])         # reconnect: no duplicates
        self.assertEqual(store.q("SELECT COUNT(*) FROM conns")[0][0], 3)

    def test_device_names_from_leases_and_overrides(self):
        t, store, _ = make()
        t.router_leases(router.parse_leases(S.LEASES))
        t.router_event(ev(S.NEW_OUT))
        self.assertEqual(t.live_view("network")["hosts"][0]["devices"][0]["name"], "laptop")
        with store.tx() as db:
            db.execute("INSERT INTO devices VALUES ('192.168.2.10', 'Jorge laptop')")
        t.reload_config()
        self.assertEqual(t.live_view("network")["hosts"][0]["devices"][0]["name"], "Jorge laptop")

    def test_subnet_filter_in_history(self):
        t, _, _ = make()
        t.router_event(ev(S.NEW_OUT))          # LAN
        t.router_event(ev(S.NEW_INTERNAL))     # IoT
        rows, _ = t.history("network", subnets=["IoT"])
        self.assertEqual([r["device"] for r in rows], ["192.168.3.20"])
        self.assertEqual(rows[0]["dir"], "internal")


class Classification(unittest.TestCase):
    def test_blocklist_flag_and_severity(self):
        t, store, _ = make(bad={"93.184.216.34": {"feodo"}})
        t.router_event(ev(S.NEW_OUT))
        row = store.history("network")[0][0]
        self.assertEqual(row["severity"], threats.SEV["high"])
        self.assertEqual(row["flags"][0]["category"], "malware-c2")

    def test_rule_flag_and_rule_sees_lists(self):
        t, store, engine = make(bad={"93.184.216.34": {"tor"}})
        with store.tx() as db:
            db.execute("INSERT INTO rules (name, expr, category, severity, enabled, updated) "
                       "VALUES ('LAN to Tor', 'subnet == \"LAN\" and \"tor\" in lists', "
                       "'policy', 3, 1, 0)")
        engine.reload()
        t.router_event(ev(S.NEW_OUT))
        row = store.history("network")[0][0]
        self.assertEqual({f["name"] for f in row["flags"]}, {"Tor exit node", "LAN to Tor"})
        self.assertEqual(row["severity"], 3)

    def test_rule_on_close_uses_bytes(self):
        t, store, engine = make()
        with store.tx() as db:
            db.execute("INSERT INTO rules (name, expr, category, severity, enabled, updated) "
                       "VALUES ('big download', 'closed and bytes_in > 5000', 'volume', 2, 1, 0)")
        engine.reload()
        t.router_event(ev(S.NEW_OUT))
        self.assertEqual(store.history("network")[0][0]["severity"], 0)
        t.router_event(ev(S.DESTROY_OUT))
        self.assertEqual(store.history("network")[0][0]["flags"][0]["name"], "big download")

    def test_new_country_rule(self):
        t, store, engine = make()
        with store.tx() as db:
            db.execute("INSERT INTO rules (name, expr, category, severity, enabled, updated) "
                       "VALUES ('new country', 'new_country', 'anomaly', 2, 1, 0)")
        engine.reload()
        t.router_event(ev(S.NEW_OUT))
        t.router_event(ev(S.DESTROY_OUT))
        t.router_event(ev(S.shift(S.NEW_OUT.replace("id=3021434816", "id=5"), 20)))
        flags = [r["severity"] for r in store.history("network")[0]]
        self.assertEqual(flags, [0, 2])       # newest first: second visit is not new

    def test_verdicts(self):
        t, store, _ = make(bad={"93.184.216.34": {"feodo"}, "142.250.1.1": {"tor"}})
        t.router_dns("example.com", "93.184.216.34")
        with store.tx() as db:
            db.execute("INSERT INTO verdicts VALUES ('domain:example.com','trusted','',0)")
            db.execute("INSERT INTO verdicts VALUES ('ip:142.250.1.1','ignore','',0)")
        t.reload_config()
        t.router_event(ev(S.NEW_OUT))
        t.router_snapshot([ev(S.SNAPSHOT[0])])
        rows = store.history("network")[0]
        self.assertEqual(len(rows), 1)                         # ignored IP not logged
        self.assertEqual(rows[0]["severity"], 0)               # trusted: not counted
        self.assertTrue(rows[0]["flags"][0]["suppressed"])     # but still visible


class Regressions(unittest.TestCase):
    def test_private_addresses_never_blocklisted(self):
        # FireHOL level 1 contains 192.168.0.0/16 ("bogons"); internal traffic
        # must not be flagged because of it.
        t, store, _ = make(bad={"192.168.2.5": {"firehol"}})
        t.router_event(ev(S.NEW_INTERNAL))
        self.assertEqual(store.history("network")[0][0]["severity"], 0)

    def test_wrong_router_clock_uses_our_clock(self):
        t, store, _ = make()
        t.router_event(ev(S.shift(S.NEW_OUT, -400 * 86400)))      # router thinks it's last year
        start = store.history("network")[0][0]["start_ts"]
        self.assertLess(abs(start - time.time()), 5)


class LocalFlow(unittest.TestCase):
    def test_poll_open_then_close_after_grace(self):
        t, store, _ = make()
        row = {"ip": "93.184.216.34", "port": 443, "local_port": 5000, "proto": "tcp",
               "status": "ESTABLISHED", "pid": 42, "proc": "firefox"}
        t.poll_local([row, dict(row, ip="10.0.0.1")], now=1000)   # private ignored
        self.assertEqual(t.live_view("local", 1000)["stats"]["active"], 1)
        t.poll_local([row], now=1002)
        t.poll_local([], now=1010)                                  # gone > grace
        r = store.history("local")[0][0]
        self.assertEqual((r["proc"], r["end_ts"]), ("firefox", 1002))


if __name__ == "__main__":
    unittest.main()
