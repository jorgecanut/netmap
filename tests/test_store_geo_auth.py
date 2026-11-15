import os
import tempfile
import time
import unittest

from netmap_core import auth, geo
from netmap_core.store import Store


def tmp_store(max_mb=4096):
    return Store(os.path.join(tempfile.mkdtemp(), "t.sqlite"), max_mb)


def conn(**over):
    c = {"scope": "network", "direction": "out", "proto": "tcp", "device": "192.168.2.10",
         "remote_ip": "93.184.216.34", "remote_port": 443, "start_ts": 1000.0}
    c.update(over)
    return c


class StoreTests(unittest.TestCase):
    def test_insert_close_and_time_queries(self):
        s = tmp_store()
        with s.tx() as db:
            a = s.insert_conn(db, conn(start_ts=100))
            s.insert_conn(db, conn(start_ts=200, remote_ip="1.1.1.1"))
            s.close_conn(db, {"id": a, "end_ts": 150, "bytes_out": 5, "bytes_in": 6,
                              "severity": 3, "flags": [{"name": "x", "severity": 3}]})
        self.assertEqual({c["remote_ip"] for c in s.conns_at("network", 120)}, {"93.184.216.34"})
        self.assertEqual({c["remote_ip"] for c in s.conns_at("network", 250)}, {"1.1.1.1"})
        self.assertEqual(s.conns_at("local", 120), [])
        rows, _ = s.history("network", min_severity=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["flags"][0]["name"], "x")

    def test_history_text_filter_escapes_wildcards(self):
        s = tmp_store()
        with s.tx() as db:
            s.insert_conn(db, conn(domain="a_b.example"))
            s.insert_conn(db, conn(domain="axb.example"))
        rows, _ = s.history("network", text="a_b")
        self.assertEqual([r["domain"] for r in rows], ["a_b.example"])

    def test_history_paging(self):
        s = tmp_store()
        with s.tx() as db:
            for i in range(5):
                s.insert_conn(db, conn(start_ts=i))
        page1, last = s.history("network", limit=2)
        page2, _ = s.history("network", before_id=last, limit=2)
        self.assertEqual(len(page1 + page2), 4)
        self.assertLess(page2[0]["id"], page1[-1]["id"])

    def test_close_dangling_uses_heartbeat(self):
        s = tmp_store()
        with s.tx() as db:
            s.insert_conn(db, conn(start_ts=100))
        s.set("heartbeat", 500.0)
        s.close_dangling()
        self.assertEqual(s.q("SELECT end_ts FROM conns")[0][0], 500.0)

    def test_prune_respects_cap(self):
        s = tmp_store(max_mb=64)
        s.max_bytes = 200 * 1024                       # tiny cap for the test
        with s.tx() as db:
            for i in range(6000):
                s.insert_conn(db, conn(start_ts=i, end_ts=i + 1, domain="x" * 40))
        before = s.size_bytes()
        deleted = s.prune()
        self.assertGreater(deleted, 0)
        self.assertLess(deleted, 6000)                 # never wipes the whole log
        self.assertLess(s.size_bytes(), before)
        oldest = s.q("SELECT MIN(start_ts) FROM conns")[0][0]
        self.assertEqual(oldest, deleted)              # exactly the oldest rows went
        for _ in range(5):                             # later rounds converge on the cap
            s.prune()
        self.assertLessEqual(s.size_bytes(), s.max_bytes)
        self.assertGreater(s.q("SELECT COUNT(*) FROM conns")[0][0], 0)

    def test_settings_roundtrip(self):
        s = tmp_store()
        s.set("router", {"host": "192.168.2.1", "port": 22})
        self.assertEqual(s.get("router")["port"], 22)
        self.assertEqual(s.get("missing", "d"), "d")


CITY = ['"1.0.0.0","1.0.0.255","OC","AU","Queensland","South Brisbane","-27.4766","153.0166"',
        '"93.184.216.0","93.184.216.255","NA","US","California","Los Angeles","34.05","-118.24"',
        '"2a00:1450::","2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff","EU","IE","Leinster","Dublin",'
        '"53.34","-6.26"',
        'garbage line']
ASN = ['"93.184.216.0","93.184.216.255","15133","Edgecast Inc."']


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "geoip.sqlite")
        geo.build(self.path, "2026-11", fetch=lambda kind, m: CITY if kind == "city" else ASN)

    def test_offline_lookup_v4_v6_and_asn(self):
        db = geo.OfflineDB(self.path)
        g = db.lookup("93.184.216.34")
        self.assertEqual((g["cc"], g["city"], g["org"]), ("US", "Los Angeles", "Edgecast Inc."))
        self.assertEqual(db.lookup("2a00:1450::5")["city"], "Dublin")
        self.assertIsNone(db.lookup("8.8.8.8"))            # gap between ranges
        self.assertEqual(db.built_month(), "2026-11")

    def test_fallback_order_and_online_queue(self):
        s = tmp_store()
        g = geo.Geo(s, self.path, download=False, online=True)
        self.assertEqual(g.lookup("93.184.216.34")["cc"], "US")        # offline
        s.geo_store("8.8.8.8", {"cc": "US", "city": "Mountain View", "lat": 1, "lon": 2}, "ip-api")
        self.assertEqual(g.lookup("8.8.8.8")["city"], "Mountain View")  # cached online result
        self.assertIsNone(g.lookup("9.9.9.9"))                          # unknown -> queued
        self.assertEqual(g.pending.get_nowait(), "9.9.9.9")
        self.assertIsNone(g.lookup("192.168.1.1"))                      # private: never looked up
        self.assertTrue(g.pending.empty())

    def test_online_off_never_queues(self):
        g = geo.Geo(tmp_store(), self.path, download=False, online=False)
        self.assertIsNone(g.lookup("9.9.9.9"))
        self.assertTrue(g.pending.empty())

    def test_months_to_try(self):
        jan = time.mktime((2026, 1, 3, 12, 0, 0, 0, 0, 0))
        self.assertEqual(geo._months_to_try(jan), ["2026-01", "2025-12"])


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.store = tmp_store()
        self.a = auth.Auth(self.store)

    def test_hash_roundtrip(self):
        h = auth.hash_password("correct horse")
        self.assertTrue(auth.verify_password("correct horse", h))
        self.assertFalse(auth.verify_password("wrong", h))
        self.assertFalse(auth.verify_password("x", "garbage"))

    def test_setup_needs_code_then_login(self):
        self.assertTrue(self.a.needs_setup())
        self.a.announce_setup()
        with self.assertRaises(auth.AuthError):
            self.a.setup("WRONG-CODE", "longpassword", "test")
        with self.assertRaises(auth.AuthError):
            self.a.setup(self.a.setup_code, "short", "test")
        token, csrf = self.a.setup(self.a.setup_code.lower(), "longpassword", "test")
        self.assertFalse(self.a.needs_setup())
        self.assertEqual(self.a.session(token)["csrf"], csrf)
        self.assertIsNone(self.a.session("forged"))
        token2, _ = self.a.login("longpassword", "test")
        self.a.logout(self.a.session(token2))
        self.assertIsNone(self.a.session(token2))

    def test_password_change_logs_out_others(self):
        self.a.announce_setup()
        t1, _ = self.a.setup(self.a.setup_code, "longpassword", "test")
        t2, _ = self.a.login("longpassword", "test")
        self.a.change_password(self.a.session(t1), "longpassword", "newpassword1")
        self.assertIsNotNone(self.a.session(t1))
        self.assertIsNone(self.a.session(t2))

    def test_lockout_after_failures(self):
        self.store.set("admin_password", auth.hash_password("longpassword"))
        for _ in range(auth.FAIL_MAX):
            with self.assertRaises(auth.AuthError):
                self.a.login("nope", "test")
        with self.assertRaises(auth.AuthError) as cm:
            self.a.login("longpassword", "test")          # right password, still locked
        self.assertIn("try again", str(cm.exception))

    def test_reset(self):
        self.store.set("admin_password", auth.hash_password("longpassword"))
        self.a.reset_password()
        self.assertTrue(self.a.needs_setup())


if __name__ == "__main__":
    unittest.main()
