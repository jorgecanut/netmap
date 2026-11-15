"""OpenWrt router feed (the 'Network' tab).

NetMap logs in to the router over SSH with its own key. On the router that key
is locked to one script (docs/router/netmap-feed.sh) that only allows:

    conntrack-snapshot   conntrack -L     (connections open right now)
    conntrack-events     conntrack -E     (each connection as it opens/closes)
    dns                  logread -f       (dnsmasq query log -> domain names)
    leases               cat dhcp.leases  (device names)

Parsing (parse_conntrack, classify, parse_leases, parse_dns) is pure and unit
tested; RouterFeed only runs ssh and hands the results to the tracker.
"""

import collections
import logging
import os
import re
import subprocess
import threading
import time

from .util import Throttle, parse_ip

log = logging.getLogger("netmap.router")
throttle = Throttle(log, every=300)

# Internal (LAN<->LAN) connections on these ports are housekeeping, not news:
# DNS, DHCP, NTP, NetBIOS, mDNS, SSDP. They would otherwise be most of the log.
NOISE_PORTS = {53, 67, 68, 123, 137, 138, 5353, 1900}
_KV = re.compile(r"(\w[\w-]*)=(\S+)")
_EVENT = re.compile(r"\[(NEW|UPDATE|DESTROY)\]")
_TS = re.compile(r"^\s*\[(\d+(?:\.\d+)?)\]")
_PROTOS = {"tcp", "udp"}


# --- parsing ----------------------------------------------------------------------

def parse_conntrack(line):
    """One line of `conntrack -L -o id` or `conntrack -E -o timestamp,id`.

    Returns {event, ts, proto, id, o: {...}, r: {...}} where o is the original
    direction (as the initiator sent it) and r the reply direction, each with
    src, dst, sport, dport and (if accounting is on) bytes. None for lines
    that are not TCP/UDP flows."""
    toks = line.split()
    proto = next((t for t in toks if t in _PROTOS), None)
    if proto is None:
        return None
    m = _EVENT.search(line)
    ts = _TS.match(line)
    o, r, cur = {}, {}, None
    ct_id = None
    for k, v in _KV.findall(line):
        if k == "src":
            cur = o if "src" not in o else r
        if k == "id":
            ct_id = v
            continue
        if cur is None or k in cur:
            continue
        if k in ("sport", "dport", "bytes", "packets"):
            try:
                cur[k] = int(v)
            except ValueError:
                continue                      # e.g. "sport=?" on odd protocols; keep the rest
        elif k in ("src", "dst"):
            cur[k] = v
    if not all(k in o for k in ("src", "dst")) or not all(k in r for k in ("src", "dst")):
        return None
    return {"event": m.group(1) if m else None,
            "ts": float(ts.group(1)) if ts else None,
            "proto": proto, "id": ct_id, "o": o, "r": r}


def classify(ev, is_local, wan_ips):
    """Who did what. Returns a dict (direction, device, remote_ip, remote_port,
    local_port, bytes_out, bytes_in) from the LAN device's point of view, or
    None when the flow can't be placed (e.g. IPv6 with no subnet configured).

    `wan_ips` is learned here: for NATed outbound flows the reply goes to the
    router's public address, so the router's own traffic can be recognised."""
    o, r = ev["o"], ev["r"]
    if o["src"] != r["dst"] and is_local(o["src"]) and not is_local(o["dst"]):
        wan_ips.add(r["dst"])                       # SNAT target = our WAN address

    def out(direction, device, remote, rport, lport, b_out, b_in):
        return {"direction": direction, "device": device, "remote_ip": remote,
                "remote_port": rport, "local_port": lport,
                "bytes_out": b_out, "bytes_in": b_in}

    if o["src"] in wan_ips:                         # router's own outbound traffic
        return out("out", "router", o["dst"], o.get("dport"), o.get("sport"),
                   o.get("bytes"), r.get("bytes"))
    if o["dst"] in wan_ips:                         # from the internet to us
        if r["src"] != o["dst"]:                    # port forward: DNAT to a device
            return out("in", r["src"], o["src"], o.get("sport"), r.get("sport"),
                       r.get("bytes"), o.get("bytes"))
        return out("in", "router", o["src"], o.get("sport"), o.get("dport"),
                   r.get("bytes"), o.get("bytes"))
    src_l, dst_l = is_local(o["src"]), is_local(o["dst"])
    if src_l and not dst_l:
        return out("out", o["src"], o["dst"], o.get("dport"), o.get("sport"),
                   o.get("bytes"), r.get("bytes"))
    if dst_l and not src_l:                         # inbound we couldn't tie to WAN
        dev = r["src"] if r["src"] != o["dst"] and is_local(r["src"]) else o["dst"]
        return out("in", dev, o["src"], o.get("sport"), o.get("dport"),
                   r.get("bytes"), o.get("bytes"))
    if src_l and dst_l:
        if o.get("dport") in NOISE_PORTS:
            return None
        return out("internal", o["src"], o["dst"], o.get("dport"), o.get("sport"),
                   o.get("bytes"), r.get("bytes"))
    return None


def parse_leases(text):
    """dnsmasq /tmp/dhcp.leases -> {ip: {name, mac}}."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and parse_ip(f[2]):
            out[f[2]] = {"mac": f[1], "name": "" if f[3] == "*" else f[3]}
    return out


_DNS = re.compile(r"dnsmasq\[\d+\]: (?:reply|cached) (\S+) is ([0-9A-Fa-f:.]+)\s*$")


def parse_dns(line):
    """'... dnsmasq[123]: reply example.com is 93.184.216.34' -> (domain, ip)."""
    m = _DNS.search(line)
    if m and parse_ip(m.group(2)):
        return m.group(1).lower(), m.group(2)
    return None


# --- SSH -----------------------------------------------------------------------------

class SSH:
    """Runs one allowed router command over ssh with NetMap's key."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.key = os.path.join(data_dir, "router_key")
        self.known_hosts = os.path.join(data_dir, "router_known_hosts")
        self.bin = os.environ.get("NETMAP_SSH", "ssh")
        self.keygen = os.environ.get("NETMAP_SSH_KEYGEN", "ssh-keygen")
        self.key_lock = threading.Lock()   # three feed threads start at once

    def ensure_key(self):
        with self.key_lock:
            self._ensure_key()

    def _ensure_key(self):
        if not os.path.exists(self.key):
            try:
                subprocess.run([self.keygen, "-q", "-t", "ed25519", "-N", "", "-C",
                                "netmap", "-f", self.key], check=True, timeout=30,
                               capture_output=True)
                log.info("created router SSH key %s", self.key)
            except (OSError, subprocess.SubprocessError) as e:
                raise RuntimeError("cannot create an SSH key with %s: %s (is "
                                   "openssh-client installed?)" % (self.keygen, e))
        try:
            os.chmod(self.key, 0o600)
        except OSError as e:
            log.warning("cannot restrict permissions on %s: %s", self.key, e)

    def public_key(self):
        self.ensure_key()
        with open(self.key + ".pub", encoding="utf-8") as f:
            return f.read().strip()

    def forget_host_key(self):
        try:
            os.remove(self.known_hosts)
        except FileNotFoundError:
            pass                              # nothing remembered yet

    def argv(self, cfg, command):
        return [self.bin, "-i", self.key, "-p", str(cfg["port"]), "-T",
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=" + self.known_hosts,
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3",
                "%s@%s" % (cfg["user"], cfg["host"]), command]

    def popen(self, cfg, command):
        self.ensure_key()
        env = dict(os.environ, HOME=self.data_dir)      # ssh wants a writable ~
        return subprocess.Popen(self.argv(cfg, command), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                text=True, bufsize=1, env=env,
                                errors="replace")


def _drain(stream, sink):
    """Keep the last stderr lines of a long-running ssh for error messages."""
    for line in stream:
        sink.append(line.strip())


class RouterFeed:
    """Background threads that keep the SSH streams open and reconnect."""

    def __init__(self, store, data_dir, sink):
        self.store = store
        self.ssh = SSH(data_dir)
        self.sink = sink               # tracker: router_snapshot/event/leases/dns
        self.gen = 0                   # bumped on settings change -> reconnect
        self.procs = set()
        self.lock = threading.Lock()
        self.status = {"state": "off", "error": None, "since": None, "events": 0,
                       "last_event": None, "dns": "off", "dns_error": None}

    def config(self):
        c = self.store.get("router", {}) or {}
        return {"enabled": bool(c.get("enabled")), "host": c.get("host", ""),
                "port": int(c.get("port") or 22), "user": c.get("user") or "root",
                "dns": bool(c.get("dns", True))}

    def reconfigure(self):
        """Called after the router settings change: drop the sessions so the
        threads reconnect with the new settings right away."""
        with self.lock:
            self.gen += 1
            procs = list(self.procs)
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass                          # already exited

    def start(self):
        for target, name in ((self._events_loop, "router-conntrack"),
                             (self._dns_loop, "router-dns"),
                             (self._leases_loop, "router-leases")):
            threading.Thread(target=target, name=name, daemon=True).start()

    def test(self):
        """One-shot check for the settings page: run `leases` and report."""
        cfg = self.config()
        if not cfg["host"]:
            return {"ok": False, "error": "no router address set"}
        try:
            p = self.ssh.popen(cfg, "leases")
            out, err = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            return {"ok": False, "error": "timed out connecting to %s" % cfg["host"]}
        except (OSError, RuntimeError) as e:
            return {"ok": False, "error": str(e)}
        if p.returncode != 0:
            return {"ok": False, "error": _explain(err, p.returncode)}
        return {"ok": True, "devices": len(parse_leases(out))}

    # --- loops ----------------------------------------------------------------------

    def _stream(self, command, on_line):
        """Run `command` until it ends or settings change. Returns error text or None."""
        cfg, gen = self.config(), self.gen
        errs = collections.deque(maxlen=10)
        try:
            p = self.ssh.popen(cfg, command)
        except (OSError, RuntimeError) as e:
            return str(e)
        with self.lock:
            self.procs.add(p)
        drain = threading.Thread(target=_drain, args=(p.stderr, errs), daemon=True)
        drain.start()
        try:
            for line in p.stdout:
                if gen != self.gen:
                    break
                on_line(line)
        finally:
            with self.lock:
                self.procs.discard(p)
            if p.poll() is None:
                p.kill()
            p.wait()
            drain.join(2)                       # collect the final error lines
            for pipe in (p.stdout, p.stderr):   # reconnects would otherwise leak fds
                try:
                    pipe.close()
                except OSError:
                    pass
        if gen != self.gen or p.returncode == 0:
            return None                 # reconfigured, or finished normally (snapshot)
        return _explain("\n".join(errs), p.returncode)

    def _wait_enabled(self, key="state"):
        while True:
            cfg = self.config()
            if cfg["enabled"] and cfg["host"] and (key == "state" or cfg["dns"]):
                return
            self.status[key] = "off"
            time.sleep(3)

    def _events_loop(self):
        backoff = 5
        while True:
            self._wait_enabled()
            self.status.update(state="connecting")
            snap = []
            err = self._stream("conntrack-snapshot",
                               lambda l: snap.append(parse_conntrack(l)))
            if err is None:
                self.sink.router_snapshot([e for e in snap if e])
                self.status.update(state="connected", error=None, since=time.time())
                throttle.ok("conntrack", "router feed connected again")
                backoff = 5
                err = self._stream("conntrack-events", self._on_event)
            if err:
                self.status.update(state="error", error=err)
                throttle.fail("conntrack", "router connection feed: %s", err)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _on_event(self, line):
        ev = parse_conntrack(line)
        if ev is None or ev["event"] not in ("NEW", "DESTROY"):
            if line.strip() and ev is None and "conntrack v" not in line:
                log.debug("ignored router line: %s", line.strip()[:200])
            return
        self.status["events"] += 1
        self.status["last_event"] = time.time()
        try:
            self.sink.router_event(ev)
        except Exception:
            log.exception("could not record router event: %s", line.strip()[:300])

    def _dns_loop(self):
        backoff = 5
        while True:
            self._wait_enabled("dns")
            self.status["dns"] = "connected"

            def on_line(line):
                d = parse_dns(line)
                if d:
                    self.sink.router_dns(*d)
            err = self._stream("dns", on_line)
            if err:
                self.status.update(dns="error", dns_error=err)
                throttle.fail("dns", "router DNS feed: %s", err)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _leases_loop(self):
        while True:
            self._wait_enabled()
            cfg = self.config()
            try:
                p = self.ssh.popen(cfg, "leases")
                out, err = p.communicate(timeout=30)
                if p.returncode == 0:
                    self.sink.router_leases(parse_leases(out))
                    throttle.ok("leases")
                else:
                    throttle.fail("leases", "router DHCP leases: %s",
                                  _explain(err, p.returncode))
            except subprocess.TimeoutExpired:
                p.kill()
                throttle.fail("leases", "router DHCP leases: timed out")
            except (OSError, RuntimeError) as e:
                throttle.fail("leases", "router DHCP leases: %s", e)
            time.sleep(60)


def _explain(stderr, code):
    """Turn ssh's stderr into an actionable message."""
    s = (stderr or "").strip()
    low = s.lower()
    if "permission denied" in low:
        return ("router refused NetMap's key - add the public key shown in Settings > "
                "Router to /etc/dropbear/authorized_keys (see docs/ROUTER.md)")
    if "host key verification failed" in low or "remote host identification" in low:
        return ("the router's host key changed (reinstalled?). If expected, press "
                "'Forget host key' in Settings > Router")
    if "not allowed" in low:
        return "the router's netmap-feed script rejected the command: " + s
    if "conntrack: not found" in low or "conntrack: command not found" in low:
        return "conntrack is not installed on the router: apk add conntrack"
    if "connection refused" in low or "timed out" in low or "no route" in low:
        return "cannot reach the router's SSH server: " + s
    if code == 0 and not s:
        return "the router closed the stream"
    return "%s (exit code %s)" % (s or "ssh ended", code)
