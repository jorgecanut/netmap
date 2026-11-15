"""End-to-end: the real server on a free port, a fake router over a fake ssh,
and the browser's API calls (login, CSRF, settings, live, history, rules)."""

import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from netmap_core import config
from netmap_core.app import App

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wrapper(name, script, d):
    """Executable that runs a test script with this Python (works without +x on the repo)."""
    path = os.path.join(d, name)
    with open(path, "w") as f:
        f.write('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, os.path.join(HERE, script)))
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


@unittest.skipIf(os.name == "nt", "uses a /bin/sh wrapper for the fake ssh")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        os.environ["NETMAP_SSH"] = wrapper("ssh", "fake_ssh.py", cls.dir)
        os.environ["NETMAP_SSH_KEYGEN"] = wrapper("ssh-keygen", "fake_keygen.py", cls.dir)
        lists = os.path.join(cls.dir, "threat_lists")
        os.makedirs(lists)
        with open(os.path.join(lists, "feodo.txt"), "w") as f:
            f.write("8.8.4.4\n")                    # the port-forward visitor in samples
        for name in ("spamhaus", "firehol", "blocklistde", "cins", "tor"):
            open(os.path.join(lists, name + ".txt"), "w").close()   # fresh: no download
        cls.port = free_port()
        cfg = config.parse(["--port", str(cls.port), "--data-dir", cls.dir, "--no-browser",
                            "--no-geo-download", "--no-geo-online", "--home", "40.4,-3.7"])
        cls.app = App(cfg)
        cls.thread = threading.Thread(target=cls.app.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.app.server is not None:
                break
            time.sleep(0.05)
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.cookie = None
        cls.csrf = None

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        for k in ("NETMAP_SSH", "NETMAP_SSH_KEYGEN"):
            os.environ.pop(k, None)

    def call(self, method, path, body=None, headers=None, csrf=True):
        h = {"Host": "localhost:%d" % self.port}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method != "GET":
            h["Content-Type"] = "application/json"
            if csrf and self.csrf:
                h["X-NetMap-CSRF"] = self.csrf
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, method=method, headers=h,
                                     data=json.dumps(body or {}).encode() if method != "GET" else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                if "json" not in r.headers.get("Content-Type", ""):
                    return r.status, raw.decode(errors="replace"), r.headers
                return r.status, json.loads(raw or b"null"), r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw), e.headers
            except ValueError:
                return e.code, raw.decode(errors="replace"), e.headers

    def login(self):
        if self.__class__.cookie:
            return
        code = self.app.auth.setup_code
        st, body, hdr = self.call("POST", "/api/setup", {"code": code, "password": "test-password"})
        self.assertEqual(st, 200, body)
        self.__class__.cookie = hdr["Set-Cookie"].split(";")[0]
        self.__class__.csrf = body["csrf"]

    def wait_for(self, fn, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(0.2)
        self.fail("condition not met in %ss" % timeout)

    # --- tests (run in name order) ---------------------------------------------------

    def test_1_security_before_login(self):
        st, body, hdr = self.call("GET", "/api/me")
        self.assertEqual((st, body["authed"], body["setup"]), (200, False, True))
        self.assertIn("frame-ancestors 'none'", hdr["Content-Security-Policy"])
        self.assertEqual(self.call("GET", "/api/live?scope=local")[0], 401)
        self.assertEqual(self.call("GET", "/api/me", headers={"Host": "evil.example"})[0], 403)
        st, body, _ = self.call("POST", "/api/setup", {"code": "WRONG", "password": "test-password"})
        self.assertEqual(st, 403)
        st, page, hdr = self.call("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("/static/app.js", page)
        self.assertEqual(self.call("GET", "/static/../store.py")[0], 404)

    def test_2_login_and_csrf(self):
        self.login()
        self.assertTrue(self.call("GET", "/api/me")[1]["authed"])
        st, body, _ = self.call("POST", "/api/subnets", {"name": "x", "cidr": "10.9.0.0/16"},
                                csrf=False)
        self.assertEqual(st, 403)
        self.assertIn("CSRF", body["error"])
        st, _, _ = self.call("POST", "/api/subnets", {"name": "x", "cidr": "10.9.0.0/16"},
                             headers={"Origin": "https://evil.example"})
        self.assertEqual(st, 403)

    def test_3_router_feed_end_to_end(self):
        self.login()
        for name, cidr, color in (("LAN", "192.168.2.0/24", "#3987e5"),
                                  ("IoT", "192.168.3.0/24", "#9085e9")):
            st, body, _ = self.call("POST", "/api/subnets", {"name": name, "cidr": cidr,
                                                              "color": color})
            self.assertEqual(st, 200, body)
        st, body, _ = self.call("POST", "/api/subnets", {"name": "bad", "cidr": "nope"})
        self.assertEqual(st, 400)
        st, body, _ = self.call("POST", "/api/router/test")
        self.assertEqual(st, 200)
        self.assertFalse(body["ok"])                   # no address yet
        st, body, _ = self.call("POST", "/api/router", {"enabled": True, "host": "192.168.2.1",
                                                         "port": 22, "user": "root", "dns": True})
        self.assertEqual(st, 200, body)
        st, body, _ = self.call("POST", "/api/router/test")
        self.assertEqual(body, {"ok": True, "devices": 3})

        def has_flagged():
            v = self.call("GET", "/api/live?scope=network")[1]
            return v if v["stats"]["flagged"] and v["router"]["state"] == "connected" else None
        v = self.wait_for(has_flagged)
        by_ip = {h["ip"]: h for h in v["hosts"]}
        self.assertEqual(by_ip["8.8.4.4"]["flags"][0]["category"], "malware-c2")
        self.assertEqual(by_ip["8.8.4.4"]["dirs"], ["in"])
        self.assertEqual(by_ip["192.168.2.5"]["dirs"], ["internal"])
        self.assertNotIn("192.168.3.1", by_ip)                       # DNS noise filtered
        dev = by_ip["192.168.2.5"]["devices"][0]
        self.assertEqual((dev["name"], dev["subnet"], dev["color"]), ("LG-TV", "IoT", "#9085e9"))
        self.assertEqual([s["name"] for s in v["subnets"]], ["IoT", "LAN"])

        def closed():
            rows = self.call("GET", "/api/history?scope=network")[1]["rows"]
            return [r for r in rows if r["remote_ip"] == "93.184.216.34" and r["end"]]
        row = self.wait_for(closed)[0]
        self.assertEqual((row["bytes_out"], row["bytes_in"]), (1200, 9000))
        self.assertEqual(row["domain"], "example.com")
        rows = self.call("GET", "/api/history?scope=network&subnets=IoT")[1]["rows"]
        self.assertEqual({r["device"] for r in rows}, {"192.168.3.20", "192.168.3.30"})
        at = self.call("GET", "/api/at?scope=network&t=%f" % (row["start"] + 1))[1]
        self.assertIn("93.184.216.34", {h["ip"] for h in at["hosts"]})

    def test_4_rules_and_verdicts(self):
        self.login()
        st, body, _ = self.call("POST", "/api/rules/test", {"expr": 'subnet == "IoT"',
                                                             "scope": "network"})
        self.assertEqual(st, 200, body)
        self.assertGreaterEqual(body["matched"], 1)
        st, body, _ = self.call("POST", "/api/rules", {"name": "x", "expr": "__import__('os')",
                                                        "severity": 2})
        self.assertEqual(st, 400)
        self.assertIn("unknown", body["error"])
        st, body, _ = self.call("POST", "/api/rules", {"name": "IoT out", "category": "iot",
                                                        "expr": 'subnet == "IoT"', "severity": 3})
        self.assertEqual(st, 200, body)
        st, body, _ = self.call("POST", "/api/verdicts", {"target": "ip:8.8.4.4",
                                                           "verdict": "trusted"})
        self.assertEqual(st, 200, body)
        st, body, _ = self.call("POST", "/api/verdicts", {"target": "ip:nonsense",
                                                           "verdict": "trusted"})
        self.assertEqual(st, 400)
        cfg = self.call("GET", "/api/config")[1]
        self.assertEqual([r["name"] for r in cfg["rules"]], ["IoT out"])
        self.assertEqual(cfg["verdicts"][0]["target"], "ip:8.8.4.4")
        self.assertTrue(cfg["router"]["public_key"].startswith("ssh-ed25519"))
        self.assertIn("192.168.3.20", [d["ip"] for d in cfg["devices"]])

    def test_5_local_scope_and_logout(self):
        self.login()
        st, v, _ = self.call("GET", "/api/live?scope=local")
        self.assertEqual(st, 200)
        self.assertIn("collector", v)
        st, _, hdr = self.call("POST", "/api/logout")
        self.assertEqual(st, 200)
        self.assertIn("Max-Age=0", hdr["Set-Cookie"])
        self.assertEqual(self.call("GET", "/api/live?scope=local")[0], 401)


if __name__ == "__main__":
    unittest.main()
