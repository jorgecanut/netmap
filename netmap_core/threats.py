"""Threat intelligence: public IP blocklists, each with a category and severity.

To add a list, append a dict to SOURCES. The file must be plain text with one
IP or CIDR per line ('#' and ';' start comments). Each list keeps its last good
download in <data>/threat_lists/<key>.txt, so one failing source never empties
the others, and a restart works offline.
"""

import ipaddress
import logging
import os
import threading
import time
import urllib.request

from .util import Throttle, atomic_write, parse_ip

log = logging.getLogger("netmap.threats")
throttle = Throttle(log)

SEVERITIES = ["none", "info", "low", "medium", "high"]
SEV = {name: i for i, name in enumerate(SEVERITIES)}
REFRESH = 6 * 3600

SOURCES = [
    {"key": "feodo", "label": "Feodo Tracker", "category": "malware-c2", "severity": "high",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "meaning": "Botnet command-and-control server (Emotet, QakBot, Dridex...). A device "
                "talking to one is very likely infected."},
    {"key": "spamhaus", "label": "Spamhaus DROP", "category": "hijacked", "severity": "high",
     "url": "https://www.spamhaus.org/drop/drop.txt",
     "meaning": "Netblock hijacked or leased by criminals. No legitimate traffic goes here."},
    {"key": "firehol", "label": "FireHOL level 1", "category": "known-bad",
     "severity": "medium",
     "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
            "firehol_level1.netset",
     "meaning": "Aggregate of addresses that should never appear in normal traffic: "
                "attack infrastructure, bogons, hijacked ranges."},
    {"key": "blocklistde", "label": "blocklist.de", "category": "attacker",
     "severity": "medium", "url": "https://lists.blocklist.de/lists/all.txt",
     "meaning": "Seen attacking servers in the last 48 h (SSH/mail/web brute force). "
                "Expected as incoming noise; outgoing to it is odd."},
    {"key": "cins", "label": "CINS Army", "category": "attacker", "severity": "low",
     "url": "https://cinsscore.com/list/ci-badguys.txt",
     "meaning": "Poor-reputation scanners and attackers seen by Sentinel IPS sensors."},
    {"key": "tor", "label": "Tor exit node", "category": "anonymizer", "severity": "info",
     "url": "https://check.torproject.org/torbulkexitlist",
     "meaning": "Tor exit relay. Normal for a Tor user; suspicious for an IoT device."},
]
BY_KEY = {s["key"]: s for s in SOURCES}


def parse_list(text):
    """Networks in a plain-text IP/CIDR list. Bad lines are skipped."""
    nets = []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line.split()[0], strict=False))
        except ValueError:
            continue
    return nets


class Index:
    """Exact-prefix buckets: one dict lookup per prefix length present, instead
    of testing every network (FireHOL alone has thousands)."""

    def __init__(self):
        self.buckets = {}            # (version, prefixlen) -> {prefix_int: set(keys)}

    def add(self, net, key):
        b = self.buckets.setdefault((net.version, net.prefixlen), {})
        b.setdefault(int(net.network_address) >> (net.max_prefixlen - net.prefixlen),
                     set()).add(key)

    def match(self, ip):
        a = parse_ip(ip)
        if a is None:
            return set()
        n, bits, hits = int(a), a.max_prefixlen, set()
        for (ver, plen), b in self.buckets.items():
            if ver == a.version:
                keys = b.get(n >> (bits - plen))
                if keys:
                    hits |= keys
        return hits

    def __len__(self):
        return sum(len(b) for b in self.buckets.values())


def flags_for(keys):
    out = []
    for k in sorted(keys, key=lambda k: -SEV[BY_KEY[k]["severity"]] if k in BY_KEY else 0):
        s = BY_KEY.get(k, {"label": k, "category": "blocklist", "severity": "low",
                           "meaning": ""})
        out.append({"src": "list", "name": s["label"], "key": k, "category": s["category"],
                    "severity": SEV[s["severity"]], "meaning": s["meaning"]})
    return out


class Threats:
    def __init__(self, data_dir):
        self.dir = os.path.join(data_dir, "threat_lists")
        os.makedirs(self.dir, exist_ok=True)
        self.index = Index()
        self.counts = {}              # key -> entries loaded
        self.updated = {}             # key -> ts of the file in use
        self.errors = {}              # key -> last error text
        self.lock = threading.Lock()

    def match(self, ip):
        """List of flag dicts for `ip` (empty when clean)."""
        with self.lock:
            idx = self.index
        return flags_for(idx.match(ip))

    def status(self):
        with self.lock:
            return {"loaded": sum(self.counts.values()),
                    "sources": [{"key": s["key"], "label": s["label"],
                                 "category": s["category"], "severity": s["severity"],
                                 "entries": self.counts.get(s["key"], 0),
                                 "updated": self.updated.get(s["key"]),
                                 "error": self.errors.get(s["key"])} for s in SOURCES]}

    def start(self):
        self._load_from_disk()
        threading.Thread(target=self._worker, name="threat-lists", daemon=True).start()

    def _path(self, key):
        return os.path.join(self.dir, key + ".txt")

    def _load_from_disk(self):
        texts = {}
        for s in SOURCES:
            p = self._path(s["key"])
            try:
                with open(p, encoding="utf-8") as f:
                    texts[s["key"]] = (f.read(), os.path.getmtime(p))
            except FileNotFoundError:
                continue                      # not downloaded yet; refresh() will fetch it
            except OSError as e:
                log.warning("cannot read cached list %s: %s", p, e)
        self._install(texts)

    def _install(self, texts):
        idx, counts, updated = Index(), {}, {}
        for key, (text, ts) in texts.items():
            nets = parse_list(text)
            for n in nets:
                idx.add(n, key)
            counts[key], updated[key] = len(nets), ts
        with self.lock:
            self.index, self.counts, self.updated = idx, counts, updated
        if counts:
            log.info("threat lists loaded: %s", ", ".join(
                "%s=%d" % kv for kv in sorted(counts.items())))

    def refresh(self):
        changed = False
        for s in SOURCES:
            p = self._path(s["key"])
            try:
                if os.path.exists(p) and time.time() - os.path.getmtime(p) < REFRESH - 60:
                    continue
                req = urllib.request.Request(s["url"], headers={"User-Agent": "netmap"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    text = r.read().decode("utf-8", "replace")
                if not parse_list(text):
                    raise ValueError("download contained no IPs (format changed?)")
                atomic_write(p, text)
                changed = True
                self.errors.pop(s["key"], None)
                throttle.ok(s["key"], "threat list %s downloading again", s["key"])
            except (OSError, ValueError) as e:
                self.errors[s["key"]] = str(e)
                throttle.fail(s["key"], "threat list %s (%s) not updated: %s; keeping the "
                              "last good copy", s["key"], s["url"], e)
        if changed:
            self._load_from_disk()

    def _worker(self):
        while True:
            self.refresh()
            time.sleep(REFRESH)
