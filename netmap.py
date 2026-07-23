#!/usr/bin/env python3
"""
NetMap — a live world map of your computer's network connections.

Usage:
    python netmap.py                 (opens http://localhost:8339 in your browser)

Options:
    --port N         serve on a different port            (default 8339)
    --interval S     seconds between connection scans     (default 2)
    --no-browser     don't auto-open the browser
    --home LAT,LON   set your own map location manually   (skips self-geolocation)

Notes:
  * Works best with psutil installed:   pip install psutil
    (adds per-process names; without it, NetMap falls back to parsing
    `netstat -ano` + `tasklist` on Windows).
  * Remote IPs are geolocated server-side via the free ip-api.com service
    (plain HTTP, ~city-level accuracy). Results are cached next to this
    script in netmap_geo_cache.json so repeat lookups are instant.
  * The web page is served on 127.0.0.1 only — nothing is exposed to your
    network, and no connection data leaves your machine except the IP
    addresses sent to ip-api.com for geolocation.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import psutil
except ImportError:
    psutil = None

# ----------------------------------------------------------------------------
# Configuration / shared state
# ----------------------------------------------------------------------------

DEFAULT_PORT = 8339
GEO_BATCH_URL = ("http://ip-api.com/batch?fields=status,message,country,"
                 "countryCode,regionName,city,lat,lon,isp,org,query")
GEO_SELF_URL = ("http://ip-api.com/json/?fields=status,country,countryCode,"
                "regionName,city,lat,lon,query")
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "netmap_geo_cache.json")

STALE_AFTER = 8       # seconds without being seen -> connection shown as fading
DROP_AFTER = 90       # seconds without being seen -> connection removed
GEO_RETRY = 60        # seconds before retrying a failed geolocation
CACHE_SAVE_EVERY = 30

LOCK = threading.Lock()
CONNS = {}            # key -> {ip, port, proto, status, pid, proc, first_seen, last_seen}
GEO = {}              # ip  -> {status: ok|pending|fail, ts, ...fields}
HOME = None           # {lat, lon, city, country, countryCode, query} or None
GEO_STATE = "waiting" # waiting | ok | offline
RATES = {"down_bps": 0.0, "up_bps": 0.0}
SCAN_ERROR = None
POLL_INTERVAL = 2.0

# Tailscale
TAILNET = {"available": None, "self": None, "peers": [], "error": None}
EXTRA_GEO_IPS = set()  # public endpoint IPs (e.g. tailnet direct peers) to geolocate
TS_RANGES = [ipaddress.ip_network("100.64.0.0/10"),
             ipaddress.ip_network("fd7a:115c:a1e0::/48")]
TS_POLL = 10          # seconds between `tailscale status` polls

# ----------------------------------------------------------------------------
# Connection collection
# ----------------------------------------------------------------------------

_pid_name_cache = {}


def _proc_name_psutil(pid):
    if pid in (None, 0):
        return "system"
    name = _pid_name_cache.get(pid)
    if name:
        return name
    try:
        name = psutil.Process(pid).name()
    except Exception:
        name = "pid %s" % pid
    _pid_name_cache[pid] = name
    return name


def collect_psutil():
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        raise RuntimeError("psutil.net_connections failed: %s" % e)
    for c in conns:
        if not c.raddr:
            continue
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        out.append({
            "ip": c.raddr.ip.split("%")[0],
            "port": c.raddr.port,
            "proto": proto,
            "status": (c.status or "").upper() if proto == "tcp" else "UDP",
            "pid": c.pid,
            "proc": _proc_name_psutil(c.pid),
        })
    return out


def _tasklist_names():
    names = {}
    try:
        out = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=15).stdout
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                try:
                    names[int(parts[1])] = parts[0]
                except ValueError:
                    pass
    except Exception:
        pass
    return names


def collect_netstat_windows():
    out = subprocess.run(["netstat", "-ano"], capture_output=True,
                         text=True, timeout=20).stdout
    names = _tasklist_names()
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0].lower()
        if proto == "tcp" and len(parts) >= 5:
            remote, status, pid_s = parts[2], parts[3], parts[4]
        elif proto == "udp":
            remote, status, pid_s = parts[2], "UDP", parts[-1]
        else:
            continue
        m = re.match(r"^\[?([0-9a-fA-F:.%]+?)\]?:(\d+)$", remote)
        if not m:
            continue
        ip, port = m.group(1).split("%")[0], int(m.group(2))
        if port == 0:
            continue
        try:
            pid = int(pid_s)
        except ValueError:
            pid = None
        rows.append({
            "ip": ip, "port": port, "proto": proto,
            "status": status.upper(), "pid": pid,
            "proc": names.get(pid, "pid %s" % pid),
        })
    return rows


def collect_connections():
    if psutil is not None:
        return collect_psutil()
    if os.name == "nt":
        return collect_netstat_windows()
    raise RuntimeError("psutil is not installed and no netstat fallback is "
                       "available on this OS. Run: pip install psutil")


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def is_tailnet(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in net for net in TS_RANGES)


def poller():
    global SCAN_ERROR
    last_io, last_t = None, None
    while True:
        now = time.time()
        try:
            rows = collect_connections()
            SCAN_ERROR = None
        except Exception as e:
            SCAN_ERROR = str(e)
            rows = []
        with LOCK:
            for r in rows:
                if not is_public(r["ip"]):
                    continue
                key = "%s|%s|%s|%s" % (r["ip"], r["port"], r["proto"], r["pid"])
                rec = CONNS.get(key)
                if rec is None:
                    r["first_seen"] = now
                    r["last_seen"] = now
                    CONNS[key] = r
                else:
                    rec["last_seen"] = now
                    rec["status"] = r["status"]
                    rec["proc"] = r["proc"]
            for key in [k for k, v in CONNS.items()
                        if now - v["last_seen"] > DROP_AFTER]:
                del CONNS[key]
        if psutil is not None:
            try:
                io = psutil.net_io_counters()
                if last_io is not None:
                    dt = max(now - last_t, 0.001)
                    RATES["down_bps"] = max(0.0, (io.bytes_recv - last_io.bytes_recv) / dt)
                    RATES["up_bps"] = max(0.0, (io.bytes_sent - last_io.bytes_sent) / dt)
                last_io, last_t = io, now
            except Exception:
                pass
        time.sleep(POLL_INTERVAL)


# ----------------------------------------------------------------------------
# Tailscale peer discovery
# ----------------------------------------------------------------------------

def _find_tailscale():
    """Locate the tailscale CLI: PATH first, then the usual install paths."""
    import shutil
    exe = shutil.which("tailscale")
    if exe:
        return exe
    candidates = [
        r"C:\Program Files\Tailscale\tailscale.exe",
        r"C:\Program Files (x86)\Tailscale\tailscale.exe",
        "/usr/bin/tailscale", "/usr/local/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _first_tailnet_ip(ips):
    for ip in ips or []:
        s = ip.split("/")[0]
        if is_tailnet(s):
            return s
    return (ips[0].split("/")[0] if ips else "")


def _endpoint_ip(curaddr):
    """Extract a public IP from a 'host:port' direct-endpoint string."""
    if not curaddr:
        return None
    m = re.match(r"^\[?([0-9a-fA-F:.]+?)\]?:\d+$", curaddr)
    if not m:
        return None
    ip = m.group(1)
    return ip if is_public(ip) else None


def tailnet_worker():
    exe = _find_tailscale()
    if not exe:
        with LOCK:
            TAILNET["available"] = False
            TAILNET["error"] = "Tailscale CLI not found"
        return
    flags = 0
    if os.name == "nt":                       # suppress a console flash on Windows
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    while True:
        try:
            out = subprocess.run([exe, "status", "--json"], capture_output=True,
                                 text=True, timeout=15, creationflags=flags).stdout
            data = json.loads(out)
            self_raw = data.get("Self") or {}
            self_info = {
                "name": (self_raw.get("HostName")
                         or (self_raw.get("DNSName") or "").split(".")[0]),
                "ip": _first_tailnet_ip(self_raw.get("TailscaleIPs")),
                "os": self_raw.get("OS", ""),
            }
            peers = []
            new_endpoints = set()
            for p in (data.get("Peer") or {}).values():
                endpoint_ip = _endpoint_ip(p.get("CurAddr"))
                if endpoint_ip:
                    new_endpoints.add(endpoint_ip)
                peers.append({
                    "name": (p.get("HostName")
                             or (p.get("DNSName") or "").split(".")[0] or "peer"),
                    "ip": _first_tailnet_ip(p.get("TailscaleIPs")),
                    "os": p.get("OS", ""),
                    "online": bool(p.get("Online")),
                    "active": bool(p.get("Active")),
                    "exit_node": bool(p.get("ExitNode")),
                    "relay": p.get("Relay", ""),          # DERP region if relayed
                    "direct": endpoint_ip is not None,
                    "endpoint_ip": endpoint_ip,
                    "rx": p.get("RxBytes", 0),
                    "tx": p.get("TxBytes", 0),
                })
            peers.sort(key=lambda x: (not x["online"], not x["active"],
                                      x["name"].lower()))
            with LOCK:
                TAILNET["available"] = True
                TAILNET["error"] = None
                TAILNET["self"] = self_info
                TAILNET["peers"] = peers
                EXTRA_GEO_IPS.update(new_endpoints)
        except subprocess.TimeoutExpired:
            with LOCK:
                TAILNET["available"] = True
                TAILNET["error"] = "tailscale status timed out"
        except Exception as e:
            with LOCK:
                # CLI exists but not logged in / stopped -> report, keep trying
                TAILNET["available"] = True
                TAILNET["error"] = "tailscale not ready (%s)" % type(e).__name__
        time.sleep(TS_POLL)


# ----------------------------------------------------------------------------
# Geolocation
# ----------------------------------------------------------------------------

def _load_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for ip, g in data.items():
            if isinstance(g, dict) and g.get("status") == "ok":
                GEO[ip] = g
        print("  loaded %d cached IP locations" % len(GEO))
    except Exception:
        pass


def _save_cache():
    try:
        with LOCK:
            ok = {ip: g for ip, g in GEO.items() if g.get("status") == "ok"}
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(ok, f)
    except Exception:
        pass


def _http_json(url, payload=None, timeout=12):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json",
                 "User-Agent": "netmap/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def geolocate_home():
    global HOME, GEO_STATE
    try:
        r = _http_json(GEO_SELF_URL)
        if r.get("status") == "success":
            HOME = {"lat": r["lat"], "lon": r["lon"],
                    "city": r.get("city", ""), "country": r.get("country", ""),
                    "countryCode": r.get("countryCode", "")}
            GEO_STATE = "ok"
            print("  home location: %s, %s" % (HOME["city"], HOME["country"]))
    except Exception:
        GEO_STATE = "offline"


def geo_worker():
    global GEO_STATE
    last_save = time.time()
    if HOME is None:
        geolocate_home()
    while True:
        now = time.time()
        with LOCK:
            wanted = {v["ip"] for v in CONNS.values()} | set(EXTRA_GEO_IPS)
            pending = [ip for ip in wanted
                       if ip not in GEO
                       or (GEO[ip].get("status") == "fail"
                           and now - GEO[ip].get("ts", 0) > GEO_RETRY)]
            for ip in pending:
                GEO[ip] = {"status": "pending", "ts": now}
        if pending:
            for i in range(0, len(pending), 100):
                batch = pending[i:i + 100]
                try:
                    results = _http_json(GEO_BATCH_URL, payload=batch)
                    GEO_STATE = "ok"
                    with LOCK:
                        for r in results:
                            ip = r.get("query")
                            if not ip:
                                continue
                            if r.get("status") == "success":
                                GEO[ip] = {
                                    "status": "ok", "ts": now,
                                    "lat": r["lat"], "lon": r["lon"],
                                    "city": r.get("city", ""),
                                    "region": r.get("regionName", ""),
                                    "country": r.get("country", ""),
                                    "countryCode": r.get("countryCode", ""),
                                    "isp": r.get("isp", ""),
                                    "org": r.get("org", ""),
                                }
                            else:
                                GEO[ip] = {"status": "fail", "ts": now,
                                           "msg": r.get("message", "")}
                except Exception:
                    GEO_STATE = "offline"
                    with LOCK:
                        for ip in batch:
                            GEO[ip] = {"status": "fail", "ts": now,
                                       "msg": "lookup unreachable"}
                time.sleep(1.6)   # stay well inside ip-api's free rate limit
            if HOME is None:
                geolocate_home()
        if now - last_save > CACHE_SAVE_EVERY:
            _save_cache()
            last_save = now
        time.sleep(3)


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------

def snapshot():
    now = time.time()
    with LOCK:
        conns = list(CONNS.values())
        geo = dict(GEO)
    hosts = {}
    for c in conns:
        h = hosts.setdefault(c["ip"], {
            "ip": c["ip"], "conns": [], "active": 0,
            "first_seen": c["first_seen"], "last_seen": c["last_seen"],
        })
        age = now - c["last_seen"]
        active = age <= STALE_AFTER
        h["conns"].append({
            "port": c["port"], "proto": c["proto"], "status": c["status"],
            "proc": c["proc"], "active": active,
        })
        h["active"] += 1 if active else 0
        h["first_seen"] = min(h["first_seen"], c["first_seen"])
        h["last_seen"] = max(h["last_seen"], c["last_seen"])
    out_hosts = []
    countries = set()
    for h in hosts.values():
        g = geo.get(h["ip"])
        if g and g.get("status") == "ok":
            h["geo"] = {k: g[k] for k in ("lat", "lon", "city", "region",
                                          "country", "countryCode", "isp", "org")}
            countries.add(g["countryCode"])
        else:
            h["geo"] = None
        h["count"] = len(h["conns"])
        h["age"] = round(now - h["last_seen"], 1)
        h["conns"].sort(key=lambda c: (-c["active"], c["proc"], c["port"]))
        del h["first_seen"], h["last_seen"]
        out_hosts.append(h)
    out_hosts.sort(key=lambda h: (-h["active"], h["age"], h["ip"]))

    with LOCK:
        ts = {"available": TAILNET["available"], "error": TAILNET["error"],
              "self": TAILNET["self"], "peers": [dict(p) for p in TAILNET["peers"]]}
    ts_active = 0
    for p in ts["peers"]:
        eip = p.get("endpoint_ip")
        g = geo.get(eip) if eip else None
        if g and g.get("status") == "ok":
            p["geo"] = {k: g[k] for k in ("lat", "lon", "city", "region",
                                          "country", "countryCode", "isp", "org")}
        else:
            p["geo"] = None
        if p.get("online") and p.get("active"):
            ts_active += 1

    return {
        "home": HOME,
        "geo_state": GEO_STATE,
        "scan_error": SCAN_ERROR,
        "psutil": psutil is not None,
        "tailnet": ts,
        "stats": {
            "active": sum(1 for c in conns if now - c["last_seen"] <= STALE_AFTER),
            "hosts": len(out_hosts),
            "countries": len(countries),
            "down_bps": round(RATES["down_bps"]),
            "up_bps": round(RATES["up_bps"]),
            "ts_peers": len(ts["peers"]),
            "ts_active": ts_active,
        },
        "hosts": out_hosts,
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            body = HTML_PAGE.encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif self.path.startswith("/data"):
            body = json.dumps(snapshot()).encode("utf-8")
            ctype = "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/quit":
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            _save_cache()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


# ----------------------------------------------------------------------------
# Web page (single embedded file: Leaflet map + side panel)
# ----------------------------------------------------------------------------

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetMap — live connection map</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
  href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<style>
  :root{
    color-scheme: dark;
    --surface-1:#141413; --surface-2:#1e1e1c; --surface-3:#2a2a27;
    --border:#3a3a36;
    --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8a897f;
    --series-1:#3987e5;         /* connection arcs & markers   */
    --accent-home:#199e70;      /* home marker                 */
    --status-good:#0ca30c; --status-warning:#fab219; --status-critical:#d03b3b;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--surface-1);
    font:13px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif;
    color:var(--text-primary);overflow:hidden}
  #app{display:grid;grid-template-rows:auto 1fr;height:100%}

  header{display:flex;align-items:center;gap:16px;padding:10px 16px;
    background:var(--surface-2);border-bottom:1px solid var(--border);
    flex-wrap:wrap}
  h1{font-size:15px;margin:0;font-weight:600;letter-spacing:.02em}
  h1 span{color:var(--series-1)}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;
    border-radius:999px;background:var(--surface-3);color:var(--text-secondary);
    font-size:11px}
  .pill .led{width:7px;height:7px;border-radius:50%;background:var(--status-good)}
  .pill.warn .led{background:var(--status-warning)}
  .pill.bad  .led{background:var(--status-critical)}
  .tiles{display:flex;gap:10px;margin-left:auto;flex-wrap:wrap}
  .tile{background:var(--surface-3);border-radius:8px;padding:5px 12px;
    text-align:right;min-width:86px}
  .tile b{display:block;font-size:16px;font-variant-numeric:tabular-nums}
  .tile small{color:var(--text-muted);font-size:10px;text-transform:uppercase;
    letter-spacing:.06em}
  #quitBtn{align-self:center;background:var(--surface-3);color:var(--text-secondary);
    border:1px solid var(--border);border-radius:8px;padding:6px 12px;font:inherit;
    font-size:11px;cursor:pointer}
  #quitBtn:hover{border-color:var(--status-critical);color:var(--text-primary)}
  #stopped{position:fixed;inset:0;z-index:2000;display:none;place-items:center;
    background:var(--surface-1)}
  #stopped div{text-align:center;color:var(--text-secondary)}
  #stopped b{display:block;font-size:18px;color:var(--text-primary);
    margin-bottom:6px}

  main{display:grid;grid-template-columns:1fr 340px;min-height:0}
  #map{height:100%;background:var(--surface-1)}
  aside{border-left:1px solid var(--border);background:var(--surface-2);
    display:flex;flex-direction:column;min-height:0}
  .filter{padding:10px 12px;border-bottom:1px solid var(--border)}
  .filter input{width:100%;padding:6px 10px;border-radius:6px;
    border:1px solid var(--border);background:var(--surface-1);
    color:var(--text-primary);font:inherit;outline:none}
  .filter input:focus{border-color:var(--series-1)}
  #list{overflow-y:auto;flex:1;padding:6px 0}
  .host{padding:8px 12px;border-bottom:1px solid #262623;cursor:pointer}
  .host:hover{background:var(--surface-3)}
  .host.inactive{opacity:.45}
  .host .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .host .procs{font-weight:600;overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap}
  .host .cnt{color:var(--text-muted);font-size:11px;flex:none}
  .host .loc{color:var(--text-secondary);font-size:12px;margin-top:1px}
  .host .ipline{color:var(--text-muted);font-size:11px;
    font-family:Consolas,ui-monospace,monospace;margin-top:1px}
  .empty{padding:24px 16px;color:var(--text-muted);text-align:center}
  .section-hd{display:flex;align-items:center;gap:8px;padding:9px 12px 5px;
    font-size:10px;text-transform:uppercase;letter-spacing:.08em;
    color:var(--text-muted);background:var(--surface-2);position:sticky;top:0;
    border-top:1px solid var(--border)}
  .section-hd .tn{color:var(--accent-home);font-weight:600}
  .peer{padding:8px 12px;border-bottom:1px solid #262623;cursor:default}
  .peer.mapped{cursor:pointer}
  .peer.mapped:hover{background:var(--surface-3)}
  .peer.off{opacity:.5}
  .peer .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .peer .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .peer .state{font-size:10px;flex:none;padding:1px 7px;border-radius:999px;
    background:var(--surface-3);color:var(--text-muted)}
  .peer .state.on{color:var(--accent-home)}
  .peer .state.act{background:#123; color:var(--series-1)}
  .peer .meta{color:var(--text-secondary);font-size:12px;margin-top:1px}
  .peer .ipline{color:var(--text-muted);font-size:11px;
    font-family:Consolas,ui-monospace,monospace;margin-top:1px}

  .leaflet-container{font:inherit}
  .leaflet-tooltip.nm{background:var(--surface-2);color:var(--text-primary);
    border:1px solid var(--border);border-radius:8px;box-shadow:0 4px 14px #0008;
    padding:8px 10px;max-width:280px;white-space:normal}
  .leaflet-tooltip.nm::before{display:none}
  .tt-ip{font-family:Consolas,ui-monospace,monospace;color:var(--text-secondary)}
  .tt-loc{font-weight:600}
  .tt-isp{color:var(--text-muted);font-size:11px}
  .tt-conns{margin-top:4px;font-size:11px;color:var(--text-secondary)}

  .nm-dot{position:relative;width:100%;height:100%}
  .nm-dot .core{position:absolute;inset:0;border-radius:50%;
    background:var(--series-1);border:2px solid var(--surface-1)}
  .nm-dot .ring{position:absolute;inset:0;border-radius:50%;
    border:2px solid var(--series-1);opacity:0;transform:scale(1)}
  .nm-dot.active .ring{animation:pulse 1.8s ease-out infinite}
  .nm-dot.home .core{background:var(--accent-home)}
  .nm-dot.home .ring{border-color:var(--accent-home);
    animation:pulse 2.4s ease-out infinite}
  .nm-dot.peer .core{background:var(--accent-home);border-radius:3px}
  .nm-dot.peer .ring{border-color:var(--accent-home);border-radius:3px}
  .nm-dot.peer.active .ring{animation:pulse 2s ease-out infinite}
  path.nm-peerarc{stroke-dasharray:2 6;animation:dashflow 1.4s linear infinite}
  @keyframes pulse{0%{opacity:.85;transform:scale(1)}
    100%{opacity:0;transform:scale(3.2)}}
  path.nm-arc{stroke-dasharray:3 9;animation:dashflow 1.1s linear infinite}
  .osm-dark{filter:invert(1) hue-rotate(180deg) brightness(.85) saturate(.35)
    contrast(.95)}
  @keyframes dashflow{to{stroke-dashoffset:-12}}

  #banner{position:absolute;left:50%;top:64px;transform:translateX(-50%);
    z-index:1000;background:var(--surface-2);border:1px solid var(--status-warning);
    color:var(--text-primary);padding:8px 14px;border-radius:8px;display:none;
    max-width:80%;box-shadow:0 4px 14px #0008}
  @media (max-width:900px){main{grid-template-columns:1fr}aside{display:none}}
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>Net<span>Map</span></h1>
    <span class="pill" id="geoPill"><span class="led"></span><span id="geoTxt">geo: waiting</span></span>
    <span class="pill" id="tsPill" style="display:none"><span class="led"></span><span id="tsTxt">tailscale</span></span>
    <div class="tiles">
      <div class="tile"><b id="tActive">–</b><small>active conns</small></div>
      <div class="tile"><b id="tHosts">–</b><small>remote hosts</small></div>
      <div class="tile"><b id="tCountries">–</b><small>countries</small></div>
      <div class="tile"><b id="tRate">–</b><small>&#8595; / &#8593; rate</small></div>
      <button id="quitBtn" title="Stop NetMap">&#10005; quit</button>
    </div>
  </header>
  <main>
    <div id="map"></div>
    <aside>
      <div class="filter">
        <input id="q" type="search" placeholder="Filter by process, IP, country&hellip;"
               autocomplete="off">
      </div>
      <div id="list"><div class="empty">Waiting for data&hellip;</div></div>
    </aside>
  </main>
</div>
<div id="banner"></div>
<div id="stopped"><div><b>NetMap stopped</b>You can close this tab.<br>
Double-click NetMap again to restart it.</div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script>
"use strict";
const HAS_MAP = typeof L !== "undefined";
let map = null, tileBanner = null;
if(HAS_MAP){
  map = L.map("map", {worldCopyJump:true, zoomControl:true, minZoom:2})
    .setView([25, 0], 2);
  // Primary basemap: CARTO dark. If its tiles won't load (ad-blocker, DNS
  // filtering, firewall), fall back to standard OpenStreetMap tiles with a
  // CSS dark filter so the map still draws.
  const osmAttr = '&copy; <a href="https://www.openstreetmap.org/copyright">'
    + 'OpenStreetMap</a>';
  let tileOK = false, tileErrs = 0, fellBack = false;
  const carto = L.tileLayer(
    "https://{s}.basemap.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: osmAttr + ' &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains:"abcd", maxZoom:19
  }).addTo(map);
  function fallbackTiles(){
    if(fellBack) return;
    fellBack = true;
    map.removeLayer(carto);
    const osm = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: osmAttr, maxZoom:19, className:"osm-dark"});
    let osmOK = false;
    osm.on("tileload", () => { osmOK = true; });
    osm.on("tileerror", () => {
      if(!osmOK) tileBanner = "Map tiles are unreachable (network blocks both "
        + "cartocdn.com and openstreetmap.org). Connections still plot on black.";
    });
    osm.addTo(map);
  }
  carto.on("tileload", () => { tileOK = true; });
  carto.on("tileerror", () => {
    tileErrs++;
    if(!tileOK && tileErrs >= 3) fallbackTiles();
  });
  // Also catch the silent case: no tile ever loads and none errors in time.
  setTimeout(() => { if(!tileOK) fallbackTiles(); }, 8000);
} else {
  document.getElementById("map").innerHTML =
    '<div class="empty" style="padding-top:15vh">Map library could not load '
    + '(check access to cdnjs.cloudflare.com).<br>'
    + 'The live connection list on the right still works.</div>';
}

const css = getComputedStyle(document.documentElement);
const BLUE = css.getPropertyValue("--series-1").trim();

let homeMarker = null, homeLL = null;
const layers = new Map();       // ip -> {marker, arc}   (public hosts)
const peerLayers = new Map();   // peer name -> {marker, arc} (tailnet, geolocated)
const GREEN = getComputedStyle(document.documentElement)
  .getPropertyValue("--accent-home").trim();
let latest = null;

function flag(cc){
  if(!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()]
    .map(c => 127397 + c.charCodeAt(0)));
}
function fmtRate(bps){
  if(bps == null) return "–";
  if(bps < 1024) return bps + " B/s";
  if(bps < 1048576) return (bps/1024).toFixed(1) + " KB/s";
  return (bps/1048576).toFixed(1) + " MB/s";
}
function esc(s){
  return String(s ?? "").replace(/[&<>"]/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function arcPoints(a, b){
  // quadratic bezier between two lat/lngs, bowed perpendicular to the chord
  let lon2 = b[1];
  if(Math.abs(lon2 - a[1]) > 180) lon2 += (a[1] > lon2 ? 360 : -360);
  const p0 = a, p2 = [b[0], lon2];
  const mx = (p0[0]+p2[0])/2, my = (p0[1]+p2[1])/2;
  const dx = p2[0]-p0[0], dy = p2[1]-p0[1];
  const dist = Math.hypot(dx, dy) || 1;
  const bow = Math.min(dist * 0.18, 14);
  const c = [mx + (-dy/dist)*bow, my + (dx/dist)*bow];
  const pts = [];
  for(let i = 0; i <= 40; i++){
    const t = i/40, u = 1-t;
    pts.push([u*u*p0[0] + 2*u*t*c[0] + t*t*p2[0],
              u*u*p0[1] + 2*u*t*c[1] + t*t*p2[1]]);
  }
  return pts;
}
function dotIcon(extra, size){
  return L.divIcon({className:"", iconSize:[size,size],
    html:'<div class="nm-dot '+extra+'">'
        +'<span class="ring"></span><span class="core"></span></div>'});
}
function tooltipHTML(h){
  const g = h.geo || {};
  const conns = h.conns.slice(0, 8).map(c =>
    esc(c.proc) + " &rarr; :" + c.port + " " + c.proto.toUpperCase()
    + (c.active ? "" : " (closed)")).join("<br>");
  const more = h.conns.length > 8 ? "<br>&hellip; +" + (h.conns.length-8) + " more" : "";
  return '<div class="tt-loc">' + flag(g.countryCode) + " "
    + esc(g.city ? g.city + ", " : "") + esc(g.country || "Unknown location") + "</div>"
    + '<div class="tt-ip">' + esc(h.ip) + "</div>"
    + (g.isp ? '<div class="tt-isp">' + esc(g.isp) + "</div>" : "")
    + '<div class="tt-conns">' + conns + more + "</div>";
}

function peerTooltip(p){
  const g = p.geo || {};
  const via = p.direct
    ? (g.city ? "direct &rarr; " + esc(g.city + ", " + g.country) : "direct connection")
    : (p.relay ? "relayed via DERP &ldquo;" + esc(p.relay) + "&rdquo;" : "not connected");
  return '<div class="tt-loc">' + (p.geo ? flag(g.countryCode) + " " : "")
    + esc(p.name) + "</div>"
    + '<div class="tt-ip">' + esc(p.ip || "") + (p.os ? " &middot; " + esc(p.os) : "")
    + "</div>"
    + '<div class="tt-isp">' + via + "</div>";
}

function render(d){
  latest = d;
  document.getElementById("tActive").textContent = d.stats.active;
  document.getElementById("tHosts").textContent = d.stats.hosts;
  document.getElementById("tCountries").textContent = d.stats.countries;
  document.getElementById("tRate").textContent =
    d.psutil ? fmtRate(d.stats.down_bps) + " / " + fmtRate(d.stats.up_bps) : "n/a";

  const pill = document.getElementById("geoPill");
  const txt = document.getElementById("geoTxt");
  pill.className = "pill" + (d.geo_state === "ok" ? "" :
                             d.geo_state === "waiting" ? " warn" : " bad");
  txt.textContent = "geo: " + (d.geo_state === "ok" ? "live" :
                    d.geo_state === "waiting" ? "waiting" : "offline, retrying");

  const banner = document.getElementById("banner");
  const bannerMsg = d.scan_error
    ? "Connection scan failed: " + d.scan_error : tileBanner;
  if(bannerMsg){
    banner.textContent = bannerMsg;
    banner.style.display = "block";
  } else banner.style.display = "none";

  if(HAS_MAP && d.home && !homeMarker){
    homeLL = [d.home.lat, d.home.lon];
    homeMarker = L.marker(homeLL, {icon: dotIcon("home", 14), zIndexOffset:1000})
      .addTo(map)
      .bindTooltip('<div class="tt-loc">' + flag(d.home.countryCode)
        + ' This computer</div><div class="tt-ip">'
        + esc(d.home.city) + ", " + esc(d.home.country) + "</div>",
        {className:"nm", direction:"top", offset:[0,-8]});
    map.setView(homeLL, 3);
  }

  const seen = new Set();
  for(const h of d.hosts){
    if(!HAS_MAP || !h.geo) continue;
    seen.add(h.ip);
    const ll = [h.geo.lat, h.geo.lon];
    const size = Math.min(10 + h.count * 2, 22);
    let entry = layers.get(h.ip);
    if(!entry){
      const marker = L.marker(ll, {icon: dotIcon(h.active ? "active" : "", size)})
        .addTo(map)
        .bindTooltip(tooltipHTML(h),
          {className:"nm", direction:"top", offset:[0,-8], sticky:true});
      let arc = null;
      if(homeLL){
        arc = L.polyline(arcPoints(homeLL, ll), {
          color: BLUE, weight: 1.5, opacity: h.active ? .6 : .18,
          className: h.active ? "nm-arc" : "", interactive: false
        }).addTo(map);
      }
      entry = {marker, arc, active: h.active, size};
      layers.set(h.ip, entry);
    } else {
      if(entry.active !== h.active || entry.size !== size){
        entry.marker.setIcon(dotIcon(h.active ? "active" : "", size));
        if(entry.arc) entry.arc.setStyle({opacity: h.active ? .6 : .18,
          className: h.active ? "nm-arc" : ""});
        entry.active = h.active; entry.size = size;
      }
      if(entry.arc === null && homeLL){
        entry.arc = L.polyline(arcPoints(homeLL, ll), {
          color: BLUE, weight: 1.5, opacity: .6,
          className: "nm-arc", interactive: false}).addTo(map);
      }
      entry.marker.setTooltipContent(tooltipHTML(h));
    }
    entry.marker.setOpacity(h.active ? 1 : .35);
  }
  for(const [ip, entry] of layers){
    if(!seen.has(ip)){
      map.removeLayer(entry.marker);
      if(entry.arc) map.removeLayer(entry.arc);
      layers.delete(ip);
    }
  }

  // ---- Tailscale ----
  const tn = d.tailnet || {available:null, peers:[]};
  const tsPill = document.getElementById("tsPill");
  const tsTxt = document.getElementById("tsTxt");
  if(tn.available === false){
    tsPill.style.display = "none";      // Tailscale not installed -> hide quietly
  } else if(tn.available){
    tsPill.style.display = "";
    if(tn.error){
      tsPill.className = "pill warn";
      tsTxt.textContent = "tailscale: " + tn.error;
    } else {
      tsPill.className = "pill";
      tsTxt.textContent = "tailscale: " + d.stats.ts_active + " active / "
        + d.stats.ts_peers + " peers";
    }
  }

  const pseen = new Set();
  if(HAS_MAP){
    for(const p of tn.peers){
      if(!p.geo) continue;
      pseen.add(p.name);
      const ll = [p.geo.lat, p.geo.lon];
      const on = p.online && p.active;
      let entry = peerLayers.get(p.name);
      if(!entry){
        const marker = L.marker(ll, {icon: dotIcon("peer" + (on?" active":""), 14),
          zIndexOffset:500}).addTo(map)
          .bindTooltip(peerTooltip(p),
            {className:"nm", direction:"top", offset:[0,-8], sticky:true});
        let arc = null;
        if(homeLL){
          arc = L.polyline(arcPoints(homeLL, ll), {
            color: GREEN, weight: 1.5, opacity: on ? .55 : .18,
            className: on ? "nm-peerarc" : "", interactive: false}).addTo(map);
        }
        entry = {marker, arc};
        peerLayers.set(p.name, entry);
      } else {
        entry.marker.setIcon(dotIcon("peer" + (on?" active":""), 14));
        entry.marker.setTooltipContent(peerTooltip(p));
        if(entry.arc) entry.arc.setStyle({opacity: on ? .55 : .18,
          className: on ? "nm-peerarc" : ""});
      }
      entry.marker.setOpacity(on ? 1 : .4);
    }
    for(const [name, entry] of peerLayers){
      if(!pseen.has(name)){
        map.removeLayer(entry.marker);
        if(entry.arc) map.removeLayer(entry.arc);
        peerLayers.delete(name);
      }
    }
  }
  renderList();
}

function renderList(){
  if(!latest) return;
  const q = document.getElementById("q").value.trim().toLowerCase();
  const list = document.getElementById("list");
  const rows = [];
  for(const h of latest.hosts){
    const g = h.geo || {};
    const procs = [...new Set(h.conns.map(c => c.proc))];
    const hay = (h.ip + " " + procs.join(" ") + " " + (g.country||"")
      + " " + (g.city||"")).toLowerCase();
    if(q && !hay.includes(q)) continue;
    const ports = [...new Set(h.conns.map(c => ":" + c.port))].slice(0,6).join(" ");
    rows.push('<div class="host' + (h.active ? "" : " inactive")
      + '" data-ip="' + esc(h.ip) + '">'
      + '<div class="top"><div class="procs">' + esc(procs.join(", "))
      + '</div><div class="cnt">' + h.count + (h.count>1?" conns":" conn") + "</div></div>"
      + '<div class="loc">' + flag(g.countryCode) + " "
      + esc(g.city ? g.city + ", " : "")
      + (g.country ? esc(g.country) : "location pending&hellip;") + "</div>"
      + '<div class="ipline">' + esc(h.ip) + "&ensp;" + esc(ports) + "</div>"
      + "</div>");
  }
  // ---- Tailscale peer section ----
  const tn = latest.tailnet || {available:null, peers:[]};
  let tsHTML = "";
  if(tn.available && !tn.error && tn.peers.length){
    const prows = [];
    for(const p of tn.peers){
      const g = p.geo || {};
      const hay = (p.name + " " + (p.ip||"") + " " + (p.os||"") + " "
        + (g.country||"") + " tailscale tailnet").toLowerCase();
      if(q && !hay.includes(q)) continue;
      const on = p.online && p.active;
      const state = on ? '<span class="state on act">active</span>'
        : p.online ? '<span class="state on">online</span>'
        : '<span class="state">offline</span>';
      const where = p.direct
        ? (g.city ? flag(g.countryCode) + " direct &middot; " + esc(g.city + ", " + g.country)
                  : "direct &middot; locating&hellip;")
        : (p.relay ? "relayed via &ldquo;" + esc(p.relay) + "&rdquo;" : "not connected");
      prows.push('<div class="peer' + (p.geo ? " mapped" : "")
        + (p.online ? "" : " off") + '" data-peer="' + esc(p.name) + '">'
        + '<div class="top"><div class="nm">' + esc(p.name) + "</div>" + state + "</div>"
        + '<div class="meta">' + where + "</div>"
        + '<div class="ipline">' + esc(p.ip || "") + (p.os ? " &middot; " + esc(p.os) : "")
        + "</div></div>");
    }
    if(prows.length){
      tsHTML = '<div class="section-hd"><span class="tn">&#9679; Tailscale</span> peers'
        + " (" + latest.stats.ts_active + " active)</div>" + prows.join("");
    }
  }
  const hostsHTML = rows.length ? rows.join("")
    : '<div class="empty">' + (q ? "No matches." : "No public connections seen yet&hellip;") + "</div>";
  const hostHd = tsHTML
    ? '<div class="section-hd">Public connections</div>' : "";
  list.innerHTML = tsHTML + hostHd + hostsHTML;
}

document.getElementById("list").addEventListener("click", e => {
  const peerRow = e.target.closest(".peer.mapped");
  if(peerRow){
    const entry = peerLayers.get(peerRow.dataset.peer);
    if(entry && map){
      map.flyTo(entry.marker.getLatLng(), Math.max(map.getZoom(), 5));
      entry.marker.openTooltip();
    }
    return;
  }
  const row = e.target.closest(".host");
  if(!row) return;
  const entry = layers.get(row.dataset.ip);
  if(entry && map){
    map.flyTo(entry.marker.getLatLng(), Math.max(map.getZoom(), 5));
    entry.marker.openTooltip();
  }
});
document.getElementById("q").addEventListener("input", renderList);

let quitting = false;
document.getElementById("quitBtn").addEventListener("click", async () => {
  quitting = true;
  try{ await fetch("/quit", {method:"POST"}); }catch(e){}
  document.getElementById("stopped").style.display = "grid";
});

async function tick(){
  if(quitting) return;
  try{
    const res = await fetch("/data", {cache:"no-store"});
    render(await res.json());
  }catch(e){ /* server briefly unavailable; retry on next tick */ }
}
tick();
setInterval(tick, 2500);
</script>
</body>
</html>
"""

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    global POLL_INTERVAL, HOME, GEO_STATE
    ap = argparse.ArgumentParser(description="NetMap - live connection world map")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--home", metavar="LAT,LON",
                    help="set your map location manually, e.g. 39.74,-104.99")
    args = ap.parse_args()
    POLL_INTERVAL = max(0.5, args.interval)

    if args.home:
        try:
            lat, lon = (float(x) for x in args.home.split(","))
            HOME = {"lat": lat, "lon": lon, "city": "", "country": "",
                    "countryCode": ""}
        except ValueError:
            sys.exit("--home must look like 39.74,-104.99")

    print("NetMap starting...")
    if psutil is None:
        print("  psutil not installed - using netstat fallback "
              "(pip install psutil for process detail)")
    _load_cache()

    threading.Thread(target=poller, daemon=True).start()
    threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=tailnet_worker, daemon=True).start()

    url = "http://localhost:%d" % args.port
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError:
        # Port already taken -> NetMap is probably already running.
        # Just open (or re-open) the existing map instead of erroring.
        print("  NetMap already running - opening %s" % url)
        if not args.no_browser:
            webbrowser.open(url)
        return
    print("  serving on %s   (Ctrl+C to stop)" % url)
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nNetMap stopped.")
        _save_cache()


if __name__ == "__main__":
    main()
