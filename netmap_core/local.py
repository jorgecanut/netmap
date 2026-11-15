"""Read this machine's socket table (the 'This machine' tab).

Linux: /proc/<pid>/net/* for every network namespace (so Docker containers
are included), mapped to processes through /proc/<pid>/fd. Windows: netstat +
tasklist. macOS: lsof. psutil, when installed, is used only for the up/down
rate tiles and for platforms without a reader of their own.
"""

import logging
import os
import re
import socket
import subprocess
import sys

from .util import Throttle

log = logging.getLogger("netmap.local")
throttle = Throttle(log)

try:
    import psutil
except ImportError:
    psutil = None

_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
               "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
               "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
_ADDR_RE = re.compile(r"^\[?([0-9a-fA-F:.%]+?)\]?:(\d+)$")


def collector_name():
    if sys.platform.startswith("linux"):
        return "/proc/net (all network namespaces)"
    if os.name == "nt":
        return "netstat + tasklist"
    if sys.platform == "darwin":
        return "lsof"
    return "psutil" if psutil else "unsupported"


def collect():
    """Rows: {ip, port, local_port, proto, status, pid, proc}."""
    if sys.platform.startswith("linux"):
        return collect_linux()
    if os.name == "nt":
        return collect_windows()
    if sys.platform == "darwin":
        return collect_macos()
    if psutil is not None:
        return collect_psutil()
    raise RuntimeError("no way to read the socket table on %s; installing psutil "
                       "would add one" % sys.platform)


# --- Linux ------------------------------------------------------------------------

def _hex_to_ip(h):
    """/proc/net stores addresses as little-endian 32-bit words."""
    if len(h) == 8:
        b = bytes.fromhex(h)
        return "%d.%d.%d.%d" % (b[3], b[2], b[1], b[0])
    if len(h) == 32:
        raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def _pids():
    try:
        return [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError as e:
        raise RuntimeError("cannot list /proc: %s" % e)


def _inode_map(pids):
    """socket inode -> (process name, pid). Other users' processes need root
    (or CAP_SYS_PTRACE in Docker); ours always resolve."""
    m, denied = {}, 0
    for pid in pids:
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue                          # process exited meanwhile
        name = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue                      # fd closed meanwhile
            if not target.startswith("socket:["):
                continue
            if name is None:
                try:
                    with open("/proc/%s/comm" % pid) as fh:
                        name = fh.read().strip()
                except OSError:
                    name = "pid %s" % pid
            m[target[8:-1]] = (name, int(pid))
    if denied:
        throttle.fail("fd-denied", "cannot see which process owns sockets of %d processes "
                      "(permission denied); they show as 'unknown'. Run as root, or in "
                      "Docker add SYS_PTRACE + DAC_READ_SEARCH and apparmor:unconfined",
                      denied)
    return m


def _netns_dirs(pids):
    """One /proc/<pid>/net per network namespace. /proc/net alone only shows our
    own namespace, which hides every Docker container."""
    dirs = ["/proc/net"]
    try:
        seen = {os.readlink("/proc/self/ns/net")}
    except OSError as e:
        throttle.fail("netns", "cannot read network namespaces (%s); only this "
                      "namespace's connections are shown", e)
        return dirs
    for pid in pids:
        try:
            ns = os.readlink("/proc/%s/ns/net" % pid)
        except OSError:
            continue                          # no permission, or exited
        if ns not in seen:
            seen.add(ns)
            dirs.append("/proc/%s/net" % pid)
    return dirs


def collect_linux():
    pids = _pids()
    inodes = _inode_map(pids)
    rows = []
    for d in _netns_dirs(pids):
        rows.extend(_read_proc_net(d, inodes))
    return rows


def _read_proc_net(netdir, inodes):
    rows = []
    for fam in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(os.path.join(netdir, fam)) as fh:
                next(fh, None)
                lines = fh.readlines()
        except OSError:
            continue                          # family absent, or namespace gone
        udp = fam.startswith("udp")
        for line in lines:
            f = line.split()
            if len(f) < 10 or ":" not in f[2]:
                continue
            ip_h, port_h = f[2].rsplit(":", 1)
            lport_h = f[1].rsplit(":", 1)[-1]
            try:
                port, lport = int(port_h, 16), int(lport_h, 16)
            except ValueError:
                continue                      # truncated line (socket table changed mid-read)
            ip = _hex_to_ip(ip_h)
            if not port or not ip:
                continue
            proc, pid = inodes.get(f[9], (None, None))
            rows.append({"ip": ip, "port": port, "local_port": lport,
                         "proto": "udp" if udp else "tcp",
                         "status": "UDP" if udp else _TCP_STATES.get(f[3].upper(), f[3]),
                         "pid": pid, "proc": proc or ("pid %s" % pid if pid else "unknown")})
    return rows


# --- Windows -----------------------------------------------------------------------

def _sys32(exe):
    """Absolute path to a Windows tool, so a same-named .exe in the current
    folder is never run instead."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", exe)


def _tasklist_names():
    names = {}
    try:
        out = subprocess.run([_sys32("tasklist.exe"), "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as e:
        throttle.fail("tasklist", "tasklist failed, process names unavailable: %s", e)
        return names
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            names[int(parts[1])] = parts[0]
    return names


def collect_windows():
    try:
        out = subprocess.run([_sys32("netstat.exe"), "-ano"], capture_output=True,
                             text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError("netstat failed: %s" % e)
    names = _tasklist_names()
    rows = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4 or p[0] not in ("TCP", "UDP"):
            continue
        proto = p[0].lower()
        if proto == "tcp" and len(p) >= 5:
            local, remote, status, pid_s = p[1], p[2], p[3], p[4]
        elif proto == "udp":
            local, remote, status, pid_s = p[1], p[2], "UDP", p[-1]
        else:
            continue
        m, ml = _ADDR_RE.match(remote), _ADDR_RE.match(local)
        if not m or m.group(2) == "0":
            continue
        pid = int(pid_s) if pid_s.isdigit() else None
        rows.append({"ip": m.group(1).split("%")[0], "port": int(m.group(2)),
                     "local_port": int(ml.group(2)) if ml else None, "proto": proto,
                     "status": status.upper(), "pid": pid,
                     "proc": names.get(pid, "pid %s" % pid)})
    return rows


# --- macOS ---------------------------------------------------------------------------

def collect_macos():
    try:
        out = subprocess.run(["lsof", "-i", "-nP"], capture_output=True, text=True,
                             timeout=25).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError("lsof failed: %s" % e)
    rows = []
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 9 or "->" not in f[8]:
            continue
        local, remote = f[8].split("->", 1)
        m, ml = _ADDR_RE.match(remote), _ADDR_RE.match(local)
        if not m:
            continue
        rows.append({"ip": m.group(1).split("%")[0], "port": int(m.group(2)),
                     "local_port": int(ml.group(2)) if ml else None,
                     "proto": "udp" if f[7].upper() == "UDP" else "tcp",
                     "status": f[9].strip("()").upper() if len(f) > 9 else "ESTABLISHED",
                     "pid": int(f[1]) if f[1].isdigit() else None, "proc": f[0]})
    return rows


# --- psutil ----------------------------------------------------------------------------

_pid_names = {}


def collect_psutil():
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError) as e:
        raise RuntimeError("psutil.net_connections failed: %s" % e)
    rows = []
    for c in conns:
        if not c.raddr:
            continue
        name = _pid_names.get(c.pid)
        if name is None:
            try:
                name = psutil.Process(c.pid).name() if c.pid else "system"
            except (psutil.Error, OSError):
                name = "pid %s" % c.pid
            _pid_names[c.pid] = name
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        rows.append({"ip": c.raddr.ip.split("%")[0], "port": c.raddr.port,
                     "local_port": c.laddr.port if c.laddr else None, "proto": proto,
                     "status": (c.status or "").upper() if proto == "tcp" else "UDP",
                     "pid": c.pid, "proc": name})
    return rows


class Rates:
    """Whole-machine up/down bytes per second (psutil only)."""

    def __init__(self):
        self.last = None
        self.down = self.up = None

    def sample(self, now):
        if psutil is None:
            return
        try:
            io = psutil.net_io_counters()
        except (psutil.Error, OSError) as e:
            throttle.fail("rates", "cannot read interface counters: %s", e)
            return
        if self.last is not None:
            dt = max(now - self.last[0], 0.001)
            self.down = max(0.0, (io.bytes_recv - self.last[1].bytes_recv) / dt)
            self.up = max(0.0, (io.bytes_sent - self.last[1].bytes_sent) / dt)
        self.last = (now, io)
