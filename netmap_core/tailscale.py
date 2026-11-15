"""Tailscale peers for the 'This machine' tab (only if the tailscale CLI exists)."""

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time

from .util import Throttle, is_public, parse_ip

log = logging.getLogger("netmap.tailscale")
throttle = Throttle(log)
POLL = 10


def _find_cli():
    exe = shutil.which("tailscale")
    if exe:
        return exe
    for c in (r"C:\Program Files\Tailscale\tailscale.exe",
              r"C:\Program Files (x86)\Tailscale\tailscale.exe",
              "/usr/bin/tailscale", "/usr/local/bin/tailscale",
              "/Applications/Tailscale.app/Contents/MacOS/Tailscale"):
        if os.path.exists(c):
            return c
    return None


def _first_tailnet_ip(ips):
    for ip in ips or []:
        s = ip.split("/")[0]
        a = parse_ip(s)
        if a and (a.version == 6 or str(a).startswith("100.")):
            return s
    return ips[0].split("/")[0] if ips else ""


def _endpoint_ip(curaddr):
    m = re.match(r"^\[?([0-9a-fA-F:.]+?)\]?:\d+$", curaddr or "")
    return m.group(1) if m and is_public(m.group(1)) else None


def parse_status(data):
    peers = []
    for p in (data.get("Peer") or {}).values():
        ep = _endpoint_ip(p.get("CurAddr"))
        peers.append({"name": p.get("HostName") or (p.get("DNSName") or "").split(".")[0]
                      or "peer", "ip": _first_tailnet_ip(p.get("TailscaleIPs")),
                      "os": p.get("OS", ""), "online": bool(p.get("Online")),
                      "active": bool(p.get("Active")), "relay": p.get("Relay", ""),
                      "direct": ep is not None, "endpoint_ip": ep})
    peers.sort(key=lambda x: (not x["online"], not x["active"], x["name"].lower()))
    return peers


class Tailscale:
    def __init__(self, geo):
        self.geo = geo
        self.state = {"available": None, "error": None, "peers": []}
        self.lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._loop, name="tailscale", daemon=True).start()

    def view(self):
        with self.lock:
            st = {"available": self.state["available"], "error": self.state["error"],
                  "peers": [dict(p) for p in self.state["peers"]]}
        for p in st["peers"]:
            g = self.geo.lookup(p["endpoint_ip"]) if p["endpoint_ip"] else None
            p["geo"] = ({"lat": g["lat"], "lon": g["lon"], "cc": g.get("cc", ""),
                         "city": g.get("city", "")} if g and g.get("lat") is not None
                        else None)
        return st

    def _loop(self):
        exe = _find_cli()
        if not exe:
            with self.lock:
                self.state.update(available=False, error="Tailscale CLI not found")
            log.debug("tailscale CLI not found; tailnet panel hidden")
            return
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        while True:
            try:
                out = subprocess.run([exe, "status", "--json"], capture_output=True,
                                     text=True, timeout=15, creationflags=flags)
                if out.returncode != 0:
                    raise RuntimeError(out.stderr.strip() or "exit %d" % out.returncode)
                peers = parse_status(json.loads(out.stdout))
                with self.lock:
                    self.state.update(available=True, error=None, peers=peers)
                throttle.ok("ts", "tailscale status works again")
            except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as e:
                msg = "tailscale not ready: %s" % e
                with self.lock:
                    self.state.update(available=True, error=msg)
                throttle.fail("ts", "%s", msg)
            time.sleep(POLL)
