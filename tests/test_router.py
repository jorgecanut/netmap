import unittest

from netmap_core import router
from netmap_core.util import is_private
from tests import samples as S


def classify(line, wan=None):
    wan_ips = set(wan or [S.WAN])
    return router.classify(router.parse_conntrack(line), is_private, wan_ips)


class ParseConntrack(unittest.TestCase):
    def test_new_event(self):
        ev = router.parse_conntrack(S.NEW_OUT)
        self.assertEqual(ev["event"], "NEW")
        self.assertEqual(ev["proto"], "tcp")
        self.assertEqual(ev["id"], "3021434816")
        self.assertAlmostEqual(ev["ts"], S.T0 + 0.1)
        self.assertEqual(ev["o"], {"src": "192.168.2.10", "dst": "93.184.216.34",
                                   "sport": 51234, "dport": 443})
        self.assertEqual(ev["r"]["dst"], S.WAN)

    def test_destroy_has_bytes(self):
        ev = router.parse_conntrack(S.DESTROY_OUT)
        self.assertEqual(ev["event"], "DESTROY")
        self.assertEqual(ev["o"]["bytes"], 1200)
        self.assertEqual(ev["r"]["bytes"], 9000)

    def test_snapshot_line_has_no_event(self):
        ev = router.parse_conntrack(S.SNAPSHOT[0])
        self.assertIsNone(ev["event"])
        self.assertIsNone(ev["ts"])
        self.assertEqual(ev["id"], "12345")

    def test_non_tcp_udp_ignored(self):
        self.assertIsNone(router.parse_conntrack(S.NEW_ICMP))
        self.assertIsNone(router.parse_conntrack("conntrack v1.4.8 (conntrack-tools): "
                                                 "12 flow entries have been shown."))
        self.assertIsNone(router.parse_conntrack(""))


class Classify(unittest.TestCase):
    def test_outbound(self):
        c = classify(S.NEW_OUT)
        self.assertEqual((c["direction"], c["device"], c["remote_ip"], c["remote_port"]),
                         ("out", "192.168.2.10", "93.184.216.34", 443))

    def test_bytes_from_device_point_of_view(self):
        c = classify(S.DESTROY_OUT)
        self.assertEqual((c["bytes_out"], c["bytes_in"]), (1200, 9000))

    def test_port_forward_inbound(self):
        c = classify(S.NEW_PORTFWD)
        self.assertEqual((c["direction"], c["device"], c["remote_ip"], c["local_port"]),
                         ("in", "192.168.2.50", "8.8.4.4", 32400))

    def test_router_own_traffic(self):
        c = classify(S.NEW_ROUTER_OUT)
        self.assertEqual((c["direction"], c["device"], c["remote_ip"]),
                         ("out", "router", "1.1.1.1"))

    def test_internal_between_subnets(self):
        c = classify(S.NEW_INTERNAL)
        self.assertEqual((c["direction"], c["device"], c["remote_ip"]),
                         ("internal", "192.168.3.20", "192.168.2.5"))

    def test_internal_dns_is_noise(self):
        self.assertIsNone(classify(S.NEW_DNS_INTERNAL))

    def test_wan_address_is_learned(self):
        wan = set()
        router.classify(router.parse_conntrack(S.NEW_OUT), is_private, wan)
        self.assertEqual(wan, {S.WAN})
        c = router.classify(router.parse_conntrack(S.NEW_PORTFWD), is_private, wan)
        self.assertEqual(c["direction"], "in")

    def test_unplaceable_ipv6_returns_none(self):
        line = ("[1.0]\t[NEW] tcp 6 120 SYN_SENT src=2a01:db8::10 dst=2606:4700::1 sport=1 "
                "dport=443 [UNREPLIED] src=2606:4700::1 dst=2a01:db8::10 sport=443 dport=1 id=7")
        self.assertIsNone(classify(line))

    def test_ipv6_with_configured_subnet(self):
        line = ("[1.0]\t[NEW] tcp 6 120 SYN_SENT src=2a01:db8::10 dst=2606:4700::1 sport=1 "
                "dport=443 [UNREPLIED] src=2606:4700::1 dst=2a01:db8::10 sport=443 dport=1 id=7")
        is_local = lambda ip: ip.startswith("2a01:db8:") or is_private(ip)   # noqa: E731
        c = router.classify(router.parse_conntrack(line), is_local, set())
        self.assertEqual((c["direction"], c["device"]), ("out", "2a01:db8::10"))


class LeasesAndDns(unittest.TestCase):
    def test_leases(self):
        l = router.parse_leases(S.LEASES)
        self.assertEqual(l["192.168.2.10"], {"mac": "aa:bb:cc:dd:ee:01", "name": "laptop"})
        self.assertEqual(l["192.168.3.30"]["name"], "")

    def test_dns(self):
        got = [router.parse_dns(l) for l in S.DNS]
        self.assertEqual(got, [None, None, ("example.com", "93.184.216.34"),
                               ("www.google.com", "142.250.1.1"), None])


class ExplainErrors(unittest.TestCase):
    def test_messages_are_actionable(self):
        self.assertIn("authorized_keys", router._explain("Permission denied (publickey).", 255))
        self.assertIn("apk add conntrack", router._explain("sh: conntrack: not found", 127))
        self.assertIn("Forget host key", router._explain("Host key verification failed.", 255))


if __name__ == "__main__":
    unittest.main()
