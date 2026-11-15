#!/usr/bin/env python3
"""
NetMap — a live world map of your computer's network connections.

Usage:
    python netmap.py                 (opens http://localhost:8339 in your browser)

Options:
    --port N         serve on a different port            (default 8339,
                     or the NETMAP_PORT environment variable)
    --interval S     seconds between connection scans     (default 2)
    --no-browser     don't auto-open the browser
    --home LAT,LON   set your own map location manually   (skips self-geolocation)

Notes:
  * No installs required. NetMap reads the socket table with the standard
    library on every supported OS — /proc on Linux, `netstat -ano` +
    `tasklist` on Windows, `lsof` on macOS. If psutil happens to be present
    it is used instead, since it is faster and reports connection state
    for every process; but it is a bonus, not a requirement.
  * Remote IPs are geolocated server-side via the free ip-api.com service
    (plain HTTP, ~city-level accuracy). Results are cached next to this
    script in netmap_geo_cache.json so repeat lookups are instant.
  * The web page is served on 127.0.0.1 only — nothing is exposed to your
    network, and no connection data leaves your machine except the IP
    addresses sent to ip-api.com for geolocation.
"""

import argparse
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
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

# --- windowless launch (NetMap.bat uses pythonw) ------------------------------
# pythonw.exe gives the process no console. print() then silently does nothing
# (CPython no-ops when sys.stdout is None) and, far worse, an unhandled
# exception in main or in any worker thread kills NetMap with NO window, NO
# error and nothing listening on the port — indistinguishable from "it just
# doesn't start". Route output and every traceback to netmap.log beside the
# script so a silent failure always leaves evidence.
# NETMAP_DATA_DIR moves the log and caches elsewhere (the Docker image points it
# at a volume); by default they live beside the script, as before.
DATA_DIR = os.environ.get("NETMAP_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
_LOG_PATH = os.path.join(DATA_DIR, "netmap.log")
_WINDOWLESS = sys.stdout is None or sys.stderr is None
if _WINDOWLESS:
    try:
        _log = open(_LOG_PATH, "a", encoding="utf-8", buffering=1)
    except Exception:
        _log = open(os.devnull, "w")
    if sys.stdout is None:
        sys.stdout = _log
    if sys.stderr is None:
        sys.stderr = _log


def _log_crash(kind, exc_type, exc, tb):
    import traceback
    try:
        sys.stderr.write("\n%s  %s in %s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), exc_type.__name__, kind))
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
        sys.stderr.flush()
    except Exception:
        pass


sys.excepthook = lambda t, v, tb: _log_crash("main thread", t, v, tb)
if hasattr(threading, "excepthook"):        # 3.8+
    threading.excepthook = lambda a: _log_crash(
        "thread %s" % getattr(a.thread, "name", "?"),
        a.exc_type, a.exc_value, a.exc_traceback)


# ----------------------------------------------------------------------------
# Configuration / shared state
# ----------------------------------------------------------------------------

VERSION = "2026.11.15.3"   # date + same-day build number, matching NetWatch, so
                           # the running build can be identified from the header
                           # and the startup log rather than guessed at
DEFAULT_PORT = 8339
GEO_BATCH_URL = ("http://ip-api.com/batch?fields=status,message,country,"
                 "countryCode,regionName,city,lat,lon,isp,org,query")
GEO_SELF_URL = ("http://ip-api.com/json/?fields=status,country,countryCode,"
                "regionName,city,lat,lon,query")
CACHE_FILE = os.path.join(DATA_DIR, "netmap_geo_cache.json")

STALE_AFTER = 8       # seconds without being seen -> connection shown as fading
DROP_AFTER = 90       # seconds without being seen -> connection removed
GEO_RETRY = 60        # seconds before retrying a failed geolocation
CACHE_SAVE_EVERY = 30

# Connection history: one entry per remote address, so repeat traffic updates
# an entry instead of growing the file. Hard cap; the address idle the longest
# is evicted first, which keeps the file (~0.5 MB at the cap) from growing.
HISTORY_FILE = os.path.join(DATA_DIR, "netmap_history.json")
HISTORY_MAX = 2048
HISTORY_LIST_MAX = 8      # procs / ports remembered per address
HISTORY = {}              # ip -> {ip, first_seen, last_seen, conns, procs, ports, geo}

LOCK = threading.Lock()
CONNS = {}            # key -> {ip, port, proto, status, pid, proc, first_seen, last_seen}
GEO = {}              # ip  -> {status: ok|pending|fail, ts, ...fields}
# Names the browser may use to reach NetMap (checked against the Host header).
# localhost only by default; --bind / --allow-host extend it for LAN access.
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
HOME = None           # {lat, lon, city, country, countryCode, query} or None
GEO_STATE = "waiting" # waiting | ok | offline
RATES = {"down_bps": 0.0, "up_bps": 0.0}
SCAN_ERROR = None
POLL_INTERVAL = 2.0
# Random per-run secret embedded in the page. State-changing requests (/quit)
# must echo it back, so only the page NetMap itself served can issue them.
QUIT_TOKEN = secrets.token_urlsafe(32)

# Tailscale
TAILNET = {"available": None, "self": None, "peers": [], "error": None}
EXTRA_GEO_IPS = set()  # public endpoint IPs (e.g. tailnet direct peers) to geolocate
TS_RANGES = [ipaddress.ip_network("100.64.0.0/10"),
             ipaddress.ip_network("fd7a:115c:a1e0::/48")]
TS_POLL = 10          # seconds between `tailscale status` polls

# ----------------------------------------------------------------------------
# Threat intelligence (public blocklists -> flag remote IPs)
# ----------------------------------------------------------------------------
# Ported from NetWatch. NetMap previously showed you every destination with no
# verdict on whether any of them were dangerous, which was its biggest gap: a
# map of where your traffic goes is much more useful when the bad dots are red.

THREAT_CACHE = os.path.join(DATA_DIR, "netmap_threat_cache.json")
THREAT_REFRESH = 6 * 3600
THREAT_CACHE_MAX = 50000     # cap the match memo (bounds long-run memory)
THREAT_LOCK = threading.RLock()
THREAT = {"exact": {}, "nets": [], "loaded": 0, "ts": 0, "error": None, "gen": 0}

THREAT_SOURCES = {
    "tor": "https://check.torproject.org/torbulkexitlist",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
               "master/firehol_level1.netset",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
}
# Human-readable name per source, plus what a hit on it actually means. Shown in
# the detail drawer so "flagged" is an explanation rather than a red dot.
THREAT_LABELS = {
    "tor": "Tor exit node",
    "firehol": "FireHOL level 1",
    "spamhaus": "Spamhaus DROP",
    "blocklist": "Public blocklist",
}
THREAT_MEANING = {
    "tor": "The far end is a Tor exit relay. Traffic to it is anonymised — normal "
           "for a Tor user on your LAN, suspicious for an IoT device or a TV.",
    "firehol": "Aggregated list of IPs that should never appear in normal traffic: "
               "bogons, hijacked ranges, and known attack infrastructure.",
    "spamhaus": "Spamhaus DROP — netblocks leased or hijacked wholesale by "
                "criminal operations. No legitimate traffic should go here.",
    "blocklist": "Matched a public reputation blocklist.",
}


def _parse_netset(text, source="blocklist"):
    """Parse a plain-text IP/CIDR blocklist. Returns (exact, nets) where exact is
    {ip: source} and nets is [(network, source)] — the source tag is what lets the
    UI say "Tor exit node" instead of a bare red dot."""
    exact, nets = {}, []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            if "/" in token:
                nets.append((ipaddress.ip_network(token, strict=False), source))
            else:
                ipaddress.ip_address(token)
                exact[token] = source
        except ValueError:
            continue
    return exact, nets


def _http_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _threat_install(exact, nets, ts):
    """Swap in a new blocklist set and bump the generation counter so every
    memoised verdict from the previous generation is discarded."""
    with THREAT_LOCK:
        THREAT["exact"] = exact
        THREAT["nets"] = nets
        THREAT["loaded"] = len(exact) + len(nets)
        THREAT["ts"] = ts
        THREAT["gen"] += 1


def threat_worker():
    # Try disk cache first for an instant start.
    try:
        with open(THREAT_CACHE, "r", encoding="utf-8") as f:
            c = json.load(f)
        cached_exact = c.get("exact", {})
        if isinstance(cached_exact, list):     # pre-attribution cache format
            cached_exact = {ip: "blocklist" for ip in cached_exact}
        cached_nets = []
        for item in c.get("nets", []):
            # new format: ["1.2.3.0/24", "spamhaus"]; old format: "1.2.3.0/24"
            net, src = item if isinstance(item, (list, tuple)) else (item, "blocklist")
            cached_nets.append((ipaddress.ip_network(net), src))
        _threat_install(cached_exact, cached_nets, c.get("ts", 0))
    except Exception:
        pass
    while True:
        exact, nets, srcs_ok = {}, [], 0
        for name, url in THREAT_SOURCES.items():
            try:
                e, nn = _parse_netset(_http_text(url), name)
                for ip, src in e.items():
                    prev = exact.get(ip)
                    # an IP on several lists keeps all of them, comma-joined
                    exact[ip] = src if not prev else prev + "," + src
                nets += nn
                srcs_ok += 1
            except Exception:
                pass
        if srcs_ok:
            _threat_install(exact, nets, time.time())
            with THREAT_LOCK:
                THREAT["error"] = None
            try:
                with open(THREAT_CACHE, "w", encoding="utf-8") as f:
                    json.dump({"exact": exact,
                               "nets": [[str(n), s] for n, s in nets],
                               "ts": THREAT["ts"]}, f)
            except Exception:
                pass
        else:
            with THREAT_LOCK:
                THREAT["error"] = "could not fetch blocklists"
        time.sleep(THREAT_REFRESH)


_threat_verdict = {}      # ip -> comma-joined source keys, or "" (memoised)
_threat_verdict_gen = -1  # generation the memo cache above was built against


def threat_match(ip):
    """Comma-joined blocklist source keys for `ip` (e.g. "tor" or
    "firehol,spamhaus"), or None if it isn't listed. Truthy on a hit, so callers
    that only test for listedness keep working."""
    global _threat_verdict_gen
    with THREAT_LOCK:
        gen = THREAT["gen"]
        exact = THREAT["exact"]
        nets = THREAT["nets"]
        loaded = THREAT["loaded"]
    # The lists load asynchronously at startup. Without this guard the first few
    # seconds of traffic get memoised as "clean" against an EMPTY blocklist and are
    # never re-checked — a silent false negative on every single restart. Verdicts
    # are therefore tied to a generation, and nothing is cached before a list exists.
    if gen != _threat_verdict_gen:
        _threat_verdict.clear()
        _threat_verdict_gen = gen
    if not loaded:
        return None
    v = _threat_verdict.get(ip)
    if v is not None:
        return v or None
    hits = []
    src = exact.get(ip)
    if src:
        hits.append(src)
    try:
        a = ipaddress.ip_address(ip)
        for net, nsrc in nets:
            if a in net and nsrc not in hits:
                hits.append(nsrc)
    except ValueError:
        pass
    hit = ",".join(sorted(set(",".join(hits).split(","))) if hits else [])
    # Bound the cache: on an always-on service the set of distinct remote IPs
    # grows forever, so clear (and re-memoize on demand) once it gets large.
    if len(_threat_verdict) >= THREAT_CACHE_MAX:
        _threat_verdict.clear()
    _threat_verdict[ip] = hit
    return hit or None


def threat_sources(ip):
    """[{key,label,meaning}] for each blocklist `ip` appears on (empty if clean)."""
    hit = threat_match(ip) or ""
    out = []
    for key in [k for k in hit.split(",") if k]:
        out.append({"key": key,
                    "label": THREAT_LABELS.get(key, key),
                    "meaning": THREAT_MEANING.get(key, "")})
    return out


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


def _sys32(exe):
    """Absolute path to a Windows system tool. Running it by bare name would let a
    same-named .exe in the current directory (NetMap.bat cd's to the script
    folder) be picked up instead of the real one."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", exe)


def _tasklist_names():
    names = {}
    try:
        out = subprocess.run([_sys32("tasklist.exe"), "/fo", "csv", "/nh"],
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
    out = subprocess.run([_sys32("netstat.exe"), "-ano"], capture_output=True,
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


# --- stdlib collectors -------------------------------------------------------
# psutil is nicer when it is there, but requiring it contradicts the project's
# own rule (no pip installs) and left Linux and macOS with no fallback at all.
# These read the same socket table the OS shows netstat.

_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
               "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
               "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
               "0A": "LISTEN", "0B": "CLOSING"}


def _hex_to_ip(h):
    """/proc/net stores addresses as little-endian hex words."""
    if len(h) == 8:
        b = bytes.fromhex(h)
        return "%d.%d.%d.%d" % (b[3], b[2], b[1], b[0])
    if len(h) == 32:
        raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def _linux_inode_map():
    """socket inode -> (process name, pid), for processes we may read.
    Sockets owned by other users need root; ours always resolve."""
    m = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return m
    for pid in pids:
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue                      # not ours, or already exited
        name = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            if name is None:
                try:
                    with open("/proc/%s/comm" % pid) as fh:
                        name = fh.read().strip()
                except OSError:
                    name = "pid %s" % pid
            m[target[8:-1]] = (name, int(pid))
    return m


def _linux_netns_dirs():
    """One /proc/<pid>/net directory per network namespace we can see.

    /proc/net only lists sockets in NetMap's own namespace. Docker containers
    (every TrueNAS app, for instance) each have their own, so their traffic was
    invisible. With the host's PID namespace shared we can see their processes,
    and /proc/<pid>/net shows the socket table of that process's namespace."""
    dirs = ["/proc/net"]
    try:
        seen = {os.readlink("/proc/self/ns/net")}
    except OSError:
        return dirs                       # can't tell namespaces apart; own only
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return dirs
    for pid in pids:
        try:
            ns = os.readlink("/proc/%s/ns/net" % pid)
        except OSError:
            continue                      # no permission, or already exited
        if ns not in seen:
            seen.add(ns)
            dirs.append("/proc/%s/net" % pid)
    return dirs


def collect_linux():
    inodes = _linux_inode_map()
    rows = []
    for netdir in _linux_netns_dirs():
        rows.extend(_read_proc_net(netdir, inodes))
    return rows


def _read_proc_net(netdir, inodes):
    rows = []
    for fam in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(os.path.join(netdir, fam)) as fh:
                next(fh, None)                     # header
                lines = fh.readlines()
        except (OSError, StopIteration):
            continue
        udp = fam.startswith("udp")
        for line in lines:
            f = line.split()
            if len(f) < 10 or ":" not in f[2]:
                continue
            ip_h, port_h = f[2].rsplit(":", 1)
            try:
                port = int(port_h, 16)
            except ValueError:
                continue
            ip = _hex_to_ip(ip_h)
            if not port or not ip:
                continue
            proc, pid = inodes.get(f[9], (None, None))
            rows.append({
                "ip": ip, "port": port,
                "proto": "udp" if udp else "tcp",
                "status": "UDP" if udp else _TCP_STATES.get(f[3].upper(), f[3]),
                "pid": pid,
                "proc": proc or ("pid %s" % pid if pid else "unknown"),
            })
    return rows


def collect_lsof_macos():
    try:
        out = subprocess.run(["lsof", "-i", "-nP"], capture_output=True,
                             text=True, timeout=25).stdout
    except Exception as e:
        raise RuntimeError("lsof failed: %s" % e)
    rows = []
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 9 or "->" not in f[8]:
            continue
        remote = f[8].split("->")[1]
        m = re.match(r"^\[?([0-9a-fA-F:.%]+?)\]?:(\d+)$", remote)
        if not m:
            continue
        try:
            pid = int(f[1])
        except ValueError:
            pid = None
        rows.append({
            "ip": m.group(1).split("%")[0], "port": int(m.group(2)),
            "proto": "udp" if f[7].upper() == "UDP" else "tcp",
            "status": (f[9].strip("()").upper() if len(f) > 9 else "ESTABLISHED"),
            "pid": pid, "proc": f[0],
        })
    return rows


def _collector_name():
    if os.name == "nt":
        return "netstat + tasklist"
    if sys.platform.startswith("linux"):
        return "/proc/net (all network namespaces)"
    if sys.platform == "darwin":
        return "lsof"
    return "unsupported"


def collect_connections():
    # On Linux the /proc reader wins even when psutil is installed: psutil only
    # sees NetMap's own network namespace, which hides every Docker container.
    if sys.platform.startswith("linux"):
        return collect_linux()
    if psutil is not None:
        return collect_psutil()
    if os.name == "nt":
        return collect_netstat_windows()
    if sys.platform == "darwin":
        return collect_lsof_macos()
    raise RuntimeError("no way to read the socket table on this platform (%s); "
                       "installing psutil would add one" % sys.platform)


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


def _remember(lst, item):
    """Add item to a short most-recent-first list, capped at HISTORY_LIST_MAX."""
    if item in lst:
        lst.remove(item)
    lst.insert(0, item)
    del lst[HISTORY_LIST_MAX:]


def _history_new_conn(r, now):
    """Record a newly seen connection. Caller holds LOCK."""
    h = HISTORY.get(r["ip"])
    if h is None:
        h = HISTORY[r["ip"]] = {"ip": r["ip"], "first_seen": now, "last_seen": now,
                                "conns": 0, "procs": [], "ports": [], "geo": None}
    h["last_seen"] = now
    h["conns"] += 1
    _remember(h["procs"], r["proc"])
    _remember(h["ports"], "%s/%s" % (r["port"], r["proto"]))


def _history_trim():
    """Enforce HISTORY_MAX by evicting the longest-idle addresses. Caller holds LOCK."""
    extra = len(HISTORY) - HISTORY_MAX
    if extra > 0:
        for ip in sorted(HISTORY, key=lambda k: HISTORY[k]["last_seen"])[:extra]:
            del HISTORY[ip]


def _load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for h in data if isinstance(data, list) else []:
            if isinstance(h, dict) and isinstance(h.get("ip"), str):
                h.setdefault("procs", []); h.setdefault("ports", [])
                h.setdefault("conns", 0); h.setdefault("geo", None)
                h.setdefault("first_seen", h.get("last_seen", 0))
                h.setdefault("last_seen", 0)
                HISTORY[h["ip"]] = h
        with LOCK:
            _history_trim()
        print("  loaded %d addresses of connection history" % len(HISTORY))
    except FileNotFoundError:
        pass
    except Exception as e:
        print("  could not read %s (%s); starting a new history"
              % (HISTORY_FILE, e))


def _history_snapshot():
    """History newest-first, with location and threat verdict attached."""
    with LOCK:
        rows = [dict(h, procs=list(h["procs"]), ports=list(h["ports"]))
                for h in HISTORY.values()]
        geo = dict(GEO)
    for h in rows:
        g = geo.get(h["ip"])
        if g and g.get("status") == "ok":
            h["geo"] = {k: g.get(k, "") for k in ("city", "country",
                                                   "countryCode", "isp")}
        h["threat"] = threat_match(h["ip"]) or ""
        h["threat_labels"] = [THREAT_LABELS.get(k, k)
                              for k in h["threat"].split(",") if k]
    rows.sort(key=lambda h: -h["last_seen"])
    return rows


def _save_history():
    """Write atomically (temp file + rename) so a crash never leaves half a file."""
    try:
        rows = _history_snapshot()
        for h in rows:
            del h["threat"], h["threat_labels"]   # recomputed on load
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rows, f)
        os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass


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
                    _history_new_conn(r, now)
                else:
                    rec["last_seen"] = now
                    rec["status"] = r["status"]
                    rec["proc"] = r["proc"]
            for key in [k for k, v in CONNS.items()
                        if now - v["last_seen"] > DROP_AFTER]:
                del CONNS[key]
            for v in CONNS.values():          # keep last_seen fresh in history
                h = HISTORY.get(v["ip"])
                if h is not None and v["last_seen"] == now:
                    h["last_seen"] = now
            _history_trim()
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
            _save_history()
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
    flagged = 0
    for h in hosts.values():
        # threat_match memoises and takes its own lock; NetMap's LOCK is already
        # released here, which is what we want — it scans thousands of CIDRs.
        h["threat"] = threat_match(h["ip"]) or ""
        h["threat_labels"] = [THREAT_LABELS.get(k, k)
                              for k in h["threat"].split(",") if k]
        if h["threat"]:
            flagged += 1
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
    # flagged first: if anything on this machine is talking to a blocklisted
    # address, that is the one row you need to see without scrolling.
    out_hosts.sort(key=lambda h: (-bool(h["threat"]), -h["active"], h["age"],
                                  h["ip"]))

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

    with THREAT_LOCK:
        threat_stat = {"loaded": THREAT["loaded"], "ts": THREAT["ts"],
                       "error": THREAT["error"]}
    return {
        "version": VERSION,
        "home": HOME,
        "geo_state": GEO_STATE,
        "scan_error": SCAN_ERROR,
        "psutil": psutil is not None,
        "collector": _collector_name() if (psutil is None
                                           or sys.platform.startswith("linux"))
                     else "psutil",
        "threat": threat_stat,
        "tailnet": ts,
        "stats": {
            "active": sum(1 for c in conns if now - c["last_seen"] <= STALE_AFTER),
            "hosts": len(out_hosts),
            "flagged": flagged,
            "countries": len(countries),
            "down_bps": round(RATES["down_bps"]),
            "up_bps": round(RATES["up_bps"]),
            "ts_peers": len(ts["peers"]),
            "ts_active": ts_active,
        },
        "hosts": out_hosts,
    }


class Handler(BaseHTTPRequestHandler):
    def _allowed_hosts(self):
        port = self.server.server_address[1]
        return {"%s:%d" % (h, port) for h in ALLOWED_HOSTS}

    def _host_ok(self):
        """Block DNS rebinding: a hostile site that re-points its own domain at
        127.0.0.1 still sends its own name in Host, so only accept requests that
        were addressed to this machine's loopback by name or address."""
        host = (self.headers.get("Host") or "").lower()
        return host in self._allowed_hosts()

    def _reject(self, code=403):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self._host_ok():
            return self._reject()
        if self.path == "/" or self.path.startswith("/index"):
            body = HTML_PAGE.replace("__NETMAP_TOKEN__", QUIT_TOKEN).encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif self.path.startswith("/history"):
            body = json.dumps({"max": HISTORY_MAX,
                               "hosts": _history_snapshot()}).encode("utf-8")
            ctype = "application/json"
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
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Three independent checks, any one of which stops a cross-site request:
        # Host (DNS rebinding), Origin (CSRF from any other page), and the per-run
        # token (a custom header also forces a CORS preflight we never answer).
        origin = self.headers.get("Origin")
        origin_ok = origin is None or any(
            origin.lower() == "http://" + h for h in self._allowed_hosts())
        token_ok = hmac.compare_digest(
            self.headers.get("X-NetMap-Token", ""), QUIT_TOKEN)
        if not (self._host_ok() and origin_ok and token_ok):
            return self._reject()
        if self.path == "/quit":
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            _save_cache()
            _save_history()
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
  href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"
  integrity="sha512-h9FcoyWjHcOcmEVkxOfTLnmZFWIH0iZhZT1H2TbOq55xssQGEJHEaIm+PgoUaZbRvQTNTluNOEfb1ZRy6D3BOw=="
  crossorigin="anonymous" referrerpolicy="no-referrer">
<style>
  :root{
    color-scheme: dark;
    /* Dark grey, shared with NetWatch so the two read as one family. */
    --surface-1:#212429; --surface-2:#282c32; --surface-3:#343941;
    --border:#454b55; --border-soft:#333840;
    --text-primary:#ffffff; --text-secondary:#c7cbd2; --text-muted:#8c919b;
    --series-1:#3987e5;         /* connection arcs & markers   */
    --accent:#3987e5; --accent-2:#9085e9;
    --accent-home:#199e70;      /* home marker                 */
    --status-good:#0ca30c; --status-warning:#fab219; --status-critical:#d03b3b;
    --bad:#d03b3b;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--surface-1);
    font:13px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif;
    color:var(--text-primary);overflow:hidden}
  #app{display:grid;grid-template-rows:auto 1fr;height:100%}

  header{display:flex;align-items:center;gap:14px;padding:10px 16px;position:relative;
    background:linear-gradient(180deg,#2e333a,#242830);
    border-bottom:1px solid var(--border);flex-wrap:wrap;
    box-shadow:0 1px 0 rgba(255,255,255,.03),0 4px 18px rgba(0,0,0,.35)}
  header::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;
    background:linear-gradient(90deg,var(--accent),var(--accent-2),transparent 65%);opacity:.55}
  .brand{display:flex;flex-direction:column}
  .brow{display:flex;align-items:center;gap:9px}
  h1{margin:0;line-height:0}
  .logo{height:38px;width:auto;display:block;overflow:visible}
  .logo .lblip{animation:nmblip 2.8s ease-in-out infinite}
  @keyframes nmblip{0%,70%,100%{opacity:1}82%{opacity:.3}}
  .tag{display:block;font-size:9px;color:var(--text-muted);letter-spacing:.1em;
    text-transform:uppercase;margin-top:-1px;white-space:nowrap}
  #ver{color:var(--text-muted);font-size:11px;font-family:Consolas,ui-monospace,monospace}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;
    border-radius:999px;background:var(--surface-3);border:1px solid var(--border);
    color:var(--text-secondary);font-size:11px}
  .pill .led{width:7px;height:7px;border-radius:50%;background:var(--status-good);
    box-shadow:0 0 7px currentColor;color:var(--status-good)}
  .pill.warn .led{background:var(--status-warning);color:var(--status-warning)}
  .pill.bad  .led{background:var(--status-critical);color:var(--status-critical)}
  .tiles{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap;align-items:stretch}
  .tile{position:relative;background:linear-gradient(180deg,#383d46,#2c3038);
    border:1px solid var(--border);border-radius:10px;padding:6px 13px 6px 14px;
    text-align:right;min-width:86px;overflow:hidden;transition:all .16s}
  .tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;
    background:var(--accent);opacity:.55}
  .tile.flagged::before{background:var(--bad)}
  .tile.flagged.hot{border-color:rgba(208,59,59,.55);
    background:linear-gradient(180deg,#40282b,#312024)}
  .tile.flagged.hot b{color:#ff8f8f}
  .tile b{display:block;font-size:17px;font-variant-numeric:tabular-nums;line-height:1.15}
  .tile small{color:var(--text-muted);font-size:9.5px;text-transform:uppercase;
    letter-spacing:.07em}
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
  .tabs{display:flex;gap:4px;padding:8px 12px 0}
  .tabs button{flex:1;background:transparent;color:var(--text-muted);font:inherit;
    font-size:12px;border:1px solid transparent;border-bottom:none;cursor:pointer;
    padding:6px 8px;border-radius:7px 7px 0 0}
  .tabs button:hover{color:var(--text-primary)}
  .tabs button.on{background:var(--surface-1);color:var(--text-primary);
    border-color:var(--border)}
  .tabs .n{color:var(--text-muted);font-size:10.5px;margin-left:3px}
  .host .when{color:var(--text-muted);font-size:11px;margin-top:1px}
  .hist-note{padding:6px 12px 2px;color:var(--text-muted);font-size:10.5px}
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
  .host.flag{border-left:3px solid var(--bad);
    background:linear-gradient(90deg,rgba(208,59,59,.12),transparent 60%)}
  .threatline{margin-bottom:3px}
  .badge-threat{font-size:9px;padding:1px 6px;border-radius:4px;font-weight:600;
    text-transform:uppercase;letter-spacing:.03em;background:#4a2020;color:#ff9b9b}
  .nm-dot.bad .core{background:var(--bad)}
  .nm-dot.bad .ring{border-color:var(--bad)}
  .tt-threat{color:#ff9b9b;font-weight:600}
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
    <div class="brand">
      <div class="brow">
        <h1><svg class="logo" viewBox="0 0 140 44" role="img" aria-label="NetMap">
          <defs><linearGradient id="nmGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="#5aa0f0"/><stop offset="1" stop-color="#9085e9"/>
          </linearGradient></defs>
          <text x="1" y="27" textLength="104" lengthAdjust="spacingAndGlyphs"
            font-size="23" font-weight="700" letter-spacing=".2"
            font-family="Segoe UI,system-ui,-apple-system,sans-serif"
            fill="var(--text-primary)">Net<tspan fill="url(#nmGrad)">Map</tspan></text>
          <path d="M1 36 H106 C114 36 116 33 119 28 L124 18" fill="none"
            stroke="url(#nmGrad)" stroke-width="2" stroke-linecap="round"
            stroke-opacity=".9"/>
          <circle cx="28" cy="36" r="2.7" fill="url(#nmGrad)"/>
          <circle cx="70" cy="36" r="2.7" fill="url(#nmGrad)"/>
          <circle class="lblip" cx="125.5" cy="14.5" r="4.2" fill="#e2564f"/>
        </svg></h1>
      </div>
      <small class="tag">This machine. Every connection. One map.</small>
    </div>
    <span id="ver" title="running build">v–</span>
    <span class="pill" id="geoPill"><span class="led"></span><span id="geoTxt">geo: waiting</span></span>
    <span class="pill" id="threatPill" style="display:none"><span class="led"></span><span id="threatTxt">threat</span></span>
    <span class="pill" id="tsPill" style="display:none"><span class="led"></span><span id="tsTxt">tailscale</span></span>
    <div class="tiles">
      <div class="tile"><b id="tActive">–</b><small>active conns</small></div>
      <div class="tile"><b id="tHosts">–</b><small>remote hosts</small></div>
      <div class="tile flagged" id="tileFlagged"
        title="Remote hosts on a public threat blocklist"><b id="tFlagged">–</b><small>flagged</small></div>
      <div class="tile"><b id="tCountries">–</b><small>countries</small></div>
      <div class="tile"><b id="tRate">–</b><small>&#8595; / &#8593; rate</small></div>
      <button id="quitBtn" title="Stop NetMap">&#10005; quit</button>
    </div>
  </header>
  <main>
    <div id="map"></div>
    <aside>
      <div class="tabs" role="tablist">
        <button id="tabLive" class="on" role="tab">Live</button>
        <button id="tabHist" role="tab"
          title="Every remote address seen, newest first (up to 2048)">History<span
          class="n" id="histN"></span></button>
      </div>
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
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"
  integrity="sha512-puJW3E/qXDqYp9IfhAI54BJEaWIfloJ7JWs7OeD5i6ruC9JZL1gERT1wjtwXFlh7CjE7ZJ+/vcRZRkIYIb6p4g=="
  crossorigin="anonymous" referrerpolicy="no-referrer"></script>
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
  return ((h.threat_labels && h.threat_labels.length)
      ? '<div class="tt-threat">&#9888; ' + esc(h.threat_labels.join(", ")) + "</div>" : "")
    + '<div class="tt-loc">' + flag(g.countryCode) + " "
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
  if(d.version) document.getElementById("ver").textContent = "v" + d.version;
  const nFlag = d.stats.flagged || 0;
  document.getElementById("tFlagged").textContent = nFlag;
  document.getElementById("tileFlagged").classList.toggle("hot", !!nFlag);
  // threat pill: says whether the blocklists actually loaded, so an empty
  // "flagged" count can be read as "nothing bad" rather than "not checked"
  const th = d.threat || {}, thp = document.getElementById("threatPill"),
        tht = document.getElementById("threatTxt");
  if(th.loaded){
    thp.style.display = ""; thp.className = "pill" + (nFlag ? " bad" : "");
    tht.textContent = "threat lists: " + th.loaded.toLocaleString() + " entries"
      + (nFlag ? " \u00b7 " + nFlag + " hit" + (nFlag===1?"":"s") : "");
  } else if(th.error){
    thp.style.display = ""; thp.className = "pill warn";
    tht.textContent = "threat: " + th.error;
  } else { thp.style.display = "none"; }
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
    // A blocklisted destination is drawn red and lifted above its neighbours —
    // it is the one dot on the map that should catch your eye first.
    const bad = !!h.threat;
    const cls = (h.active ? "active" : "") + (bad ? " bad" : "");
    const arcCol = bad ? "#d03b3b" : BLUE;
    const arcOp = bad ? .85 : (h.active ? .6 : .18);
    let entry = layers.get(h.ip);
    if(!entry){
      const marker = L.marker(ll, {icon: dotIcon(cls, size),
          zIndexOffset: bad ? 800 : 0})
        .addTo(map)
        .bindTooltip(tooltipHTML(h),
          {className:"nm", direction:"top", offset:[0,-8], sticky:true});
      let arc = null;
      if(homeLL){
        arc = L.polyline(arcPoints(homeLL, ll), {
          color: arcCol, weight: bad ? 2.2 : 1.5, opacity: arcOp,
          className: h.active ? "nm-arc" : "", interactive: false
        }).addTo(map);
      }
      entry = {marker, arc, active: h.active, size, bad};
      layers.set(h.ip, entry);
    } else {
      if(entry.active !== h.active || entry.size !== size || entry.bad !== bad){
        entry.marker.setIcon(dotIcon(cls, size));
        entry.marker.setZIndexOffset(bad ? 800 : 0);
        if(entry.arc) entry.arc.setStyle({color: arcCol, weight: bad ? 2.2 : 1.5,
          opacity: arcOp, className: h.active ? "nm-arc" : ""});
        entry.active = h.active; entry.size = size; entry.bad = bad;
      }
      if(entry.arc === null && homeLL){
        entry.arc = L.polyline(arcPoints(homeLL, ll), {
          color: arcCol, weight: bad ? 2.2 : 1.5, opacity: arcOp,
          className: "nm-arc", interactive: false}).addTo(map);
      }
      entry.marker.setTooltipContent(tooltipHTML(h));
    }
    entry.marker.setOpacity((h.active || bad) ? 1 : .35);
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

// ---- History tab ----
let tab = "live", hist = null, histAt = 0;
function ago(sec){
  sec = Math.max(0, Math.round(sec));
  if(sec < 60) return sec + "s ago";
  if(sec < 3600) return Math.floor(sec/60) + "m ago";
  if(sec < 86400) return Math.floor(sec/3600) + "h ago";
  return Math.floor(sec/86400) + "d ago";
}
async function loadHistory(force){
  if(!force && Date.now() - histAt < 10000) return;
  histAt = Date.now();
  try{
    const res = await fetch("/history", {cache:"no-store"});
    hist = await res.json();
    document.getElementById("histN").textContent = hist.hosts.length;
    if(tab === "history") renderList();
  }catch(e){}
}
function setTab(t){
  tab = t;
  document.getElementById("tabLive").classList.toggle("on", t === "live");
  document.getElementById("tabHist").classList.toggle("on", t === "history");
  if(t === "history") loadHistory(true);
  renderList();
}
document.getElementById("tabLive").addEventListener("click", () => setTab("live"));
document.getElementById("tabHist").addEventListener("click", () => setTab("history"));

function renderHistory(q){
  const list = document.getElementById("list");
  if(!hist){ list.innerHTML = '<div class="empty">Loading history&hellip;</div>'; return; }
  const now = Date.now() / 1000;
  const live = new Set((latest ? latest.hosts : []).filter(h => h.active).map(h => h.ip));
  const rows = [];
  for(const h of hist.hosts){
    const g = h.geo || {};
    const labels = (h.threat_labels || []).join(" ");
    const hay = (h.ip + " " + h.procs.join(" ") + " " + (g.country||"") + " "
      + (g.city||"") + " " + (g.isp||"") + " " + labels
      + (h.threat ? " flagged threat" : "")).toLowerCase();
    if(q && !hay.includes(q)) continue;
    const tb = h.threat
      ? '<div class="threatline"><span class="badge-threat">&#9888; '
        + esc(labels || "flagged") + "</span></div>" : "";
    rows.push('<div class="host' + (live.has(h.ip) ? "" : " inactive")
      + (h.threat ? " flag" : "") + '" data-ip="' + esc(h.ip) + '">' + tb
      + '<div class="top"><div class="procs">' + esc(h.procs.join(", "))
      + '</div><div class="cnt">' + h.conns + (h.conns === 1 ? " conn" : " conns")
      + "</div></div>"
      + '<div class="loc">' + flag(g.countryCode) + " " + esc(g.city ? g.city + ", " : "")
      + esc(g.country || "unknown location")
      + (g.isp ? " &middot; " + esc(g.isp) : "") + "</div>"
      + '<div class="ipline">' + esc(h.ip) + "&ensp;"
      + esc(h.ports.map(p => ":" + p).join(" ")) + "</div>"
      + '<div class="when">' + (live.has(h.ip) ? "live now" : "last seen " + ago(now - h.last_seen))
      + " &middot; first seen " + ago(now - h.first_seen) + "</div></div>");
  }
  list.innerHTML = '<div class="hist-note">' + hist.hosts.length + " of " + hist.max
    + " addresses kept &middot; oldest dropped first</div>"
    + (rows.length ? rows.join("")
       : '<div class="empty">' + (q ? "No matches." : "Nothing recorded yet&hellip;") + "</div>");
}

function renderList(){
  if(!latest) return;
  const q = document.getElementById("q").value.trim().toLowerCase();
  if(tab === "history") return renderHistory(q);
  const list = document.getElementById("list");
  const rows = [];
  for(const h of latest.hosts){
    const g = h.geo || {};
    const procs = [...new Set(h.conns.map(c => c.proc))];
    const labels = (h.threat_labels || []).join(" ");
    const hay = (h.ip + " " + procs.join(" ") + " " + (g.country||"")
      + " " + (g.city||"") + " " + labels
      + (h.threat ? " flagged threat" : "")).toLowerCase();
    if(q && !hay.includes(q)) continue;
    const ports = [...new Set(h.conns.map(c => ":" + c.port))].slice(0,6).join(" ");
    const tb = h.threat
      ? '<span class="badge-threat">&#9888; ' + esc(labels || "flagged") + "</span>" : "";
    rows.push('<div class="host' + (h.active ? "" : " inactive")
      + (h.threat ? " flag" : "")
      + '" data-ip="' + esc(h.ip) + '">'
      + (tb ? '<div class="threatline">' + tb + "</div>" : "")
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
  try{ await fetch("/quit", {method:"POST",
    headers:{"X-NetMap-Token": "__NETMAP_TOKEN__"}}); }catch(e){}
  document.getElementById("stopped").style.display = "grid";
});

async function tick(){
  if(quitting) return;
  try{
    const res = await fetch("/data", {cache:"no-store"});
    render(await res.json());
  }catch(e){ /* server briefly unavailable; retry on next tick */ }
  loadHistory(false);   // refreshes the History tab and its count every 10 s
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
    # NETMAP_PORT lets a container set the port in its environment; an explicit
    # --port on the command line still wins.
    try:
        env_port = int(os.environ.get("NETMAP_PORT") or DEFAULT_PORT)
    except ValueError:
        sys.exit("NETMAP_PORT must be a number, got %r" % os.environ["NETMAP_PORT"])
    ap.add_argument("--port", type=int, default=env_port)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--bind", metavar="ADDR",
                    default=os.environ.get("NETMAP_BIND") or "127.0.0.1",
                    help="IPv4 address to listen on (default 127.0.0.1; "
                         "0.0.0.0 = every interface). Env: NETMAP_BIND")
    ap.add_argument("--allow-host", metavar="NAMES",
                    default=os.environ.get("NETMAP_ALLOWED_HOSTS") or "",
                    help="comma-separated hostnames/IPs browsers may use to reach "
                         "NetMap, e.g. 192.168.1.50,truenas.local. "
                         "Env: NETMAP_ALLOWED_HOSTS")
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

    print("NetMap v%s starting..." % VERSION)
    if sys.platform.startswith("linux"):
        print("  reading sockets from %s" % _collector_name())
    elif psutil is None:
        print("  reading sockets with the standard library (%s); psutil is "
              "optional and not installed" % _collector_name())
    else:
        print("  reading sockets via psutil")
    _load_cache()
    _load_history()

    threading.Thread(target=poller, daemon=True).start()
    threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=threat_worker, daemon=True).start()
    threading.Thread(target=tailnet_worker, daemon=True).start()

    for name in args.allow_host.split(","):
        if name.strip():
            ALLOWED_HOSTS.add(name.strip().lower())
    if args.bind not in ("0.0.0.0", ""):
        ALLOWED_HOSTS.add(args.bind.lower())
    loopback_only = args.bind.startswith("127.")
    url = "http://localhost:%d" % args.port
    try:
        server = ThreadingHTTPServer((args.bind, args.port), Handler)
    except OSError as e:
        # Port taken. Usually that means NetMap is already running, so re-open
        # the existing map — but it can also be an unrelated program sitting on
        # 8339, in which case opening the URL shows something that is not NetMap.
        # Say which, rather than always claiming the cheerful explanation.
        print("  cannot bind 127.0.0.1:%d (%s)" % (args.port, e))
        print("  if NetMap is already running this is expected - opening %s" % url)
        print("  if it is not, something else holds the port; try: "
              "python netmap.py --port 8340")
        if not args.no_browser:
            webbrowser.open(url)
        return
    if loopback_only:
        print("  serving on %s   (Ctrl+C to stop)" % url)
    else:
        print("  listening on %s:%d - reachable from your network, with NO login"
              % (args.bind, args.port))
        print("  open it as: %s" % ", ".join(
            "http://%s:%d" % (h, args.port) for h in sorted(ALLOWED_HOSTS)))
        if ALLOWED_HOSTS == {"localhost", "127.0.0.1"}:
            print("  WARNING: no --allow-host / NETMAP_ALLOWED_HOSTS set, so requests "
                  "from other machines will get 403. Add the server's IP or name.")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    # `docker stop` and TrueNAS send SIGTERM, not Ctrl+C: save state on it too,
    # or every restart would lose up to CACHE_SAVE_EVERY seconds of history.
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: (_save_cache(), _save_history(),
                                                  sys.exit(0)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nNetMap stopped.")
        _save_cache()
        _save_history()


if __name__ == "__main__":
    main()
