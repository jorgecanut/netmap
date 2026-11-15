import ipaddress
import os
import tempfile
import time
import unittest

from netmap_core import threats


class Lists(unittest.TestCase):
    def test_parse_skips_comments_and_garbage(self):
        nets = threats.parse_list("# header\n1.2.3.4\n5.6.0.0/16 ; SBL123\nnot-an-ip\n\n"
                                  "2001:db8::/32\n")
        self.assertEqual([str(n) for n in nets], ["1.2.3.4/32", "5.6.0.0/16", "2001:db8::/32"])

    def test_index_matches_exact_and_cidr(self):
        idx = threats.Index()
        idx.add(ipaddress.ip_network("1.2.3.4/32"), "tor")
        idx.add(ipaddress.ip_network("5.6.0.0/16"), "spamhaus")
        idx.add(ipaddress.ip_network("5.6.7.0/24"), "firehol")
        idx.add(ipaddress.ip_network("2001:db8::/32"), "cins")
        self.assertEqual(idx.match("1.2.3.4"), {"tor"})
        self.assertEqual(idx.match("1.2.3.5"), set())
        self.assertEqual(idx.match("5.6.7.8"), {"spamhaus", "firehol"})
        self.assertEqual(idx.match("2001:db8::1"), {"cins"})
        self.assertEqual(idx.match("garbage"), set())

    def test_flags_sorted_by_severity_with_meaning(self):
        f = threats.flags_for({"tor", "feodo"})
        self.assertEqual([x["key"] for x in f], ["feodo", "tor"])
        self.assertEqual(f[0]["category"], "malware-c2")
        self.assertEqual(f[0]["severity"], threats.SEV["high"])
        self.assertTrue(f[0]["meaning"])

    def test_loads_cached_lists_without_network(self):
        d = tempfile.mkdtemp()
        t = threats.Threats(d)
        with open(os.path.join(t.dir, "feodo.txt"), "w") as f:
            f.write("203.0.113.66\n")
        t._load_from_disk()
        self.assertEqual(t.match("203.0.113.66")[0]["key"], "feodo")
        self.assertEqual(t.status()["loaded"], 1)

    def test_failed_download_keeps_last_good_copy(self):
        d = tempfile.mkdtemp()
        t = threats.Threats(d)
        p = os.path.join(t.dir, "tor.txt")
        with open(p, "w") as f:
            f.write("198.51.100.9\n")
        old = time.time() - threats.REFRESH * 2
        os.utime(p, (old, old))                    # stale -> refresh tries to download
        t._load_from_disk()                        # what start() does first
        saved = threats.SOURCES
        threats.SOURCES = [dict(saved[-1], url="http://127.0.0.1:9/unreachable")]
        try:
            t.refresh()
        finally:
            threats.SOURCES = saved
        self.assertIn("tor", t.errors)
        self.assertEqual(t.match("198.51.100.9")[0]["key"], "tor")


if __name__ == "__main__":
    unittest.main()
