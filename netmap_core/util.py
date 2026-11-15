"""Small helpers shared by every module: logging, IP handling, file writes."""

import ipaddress
import logging
import os
import threading
import time

log = logging.getLogger("netmap")


def setup_logging(level=None):
    """Log to stderr (the Docker log / netmap.log when windowless)."""
    level = (level or os.environ.get("NETMAP_LOG_LEVEL") or "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")


class Throttle:
    """Log a recurring problem once, then at most every `every` seconds.

    Background loops retry every few seconds; logging each failure would bury
    the log, logging none hides the cause. This logs the first failure, repeats
    while it persists (with a count), and says when it recovers."""

    def __init__(self, logger, every=600):
        self.log = logger
        self.every = every
        self._state = {}            # key -> [first_ts, last_logged_ts, count]
        self._lock = threading.Lock()

    def fail(self, key, msg, *args, exc_info=False):
        now = time.time()
        with self._lock:
            st = self._state.get(key)
            if st is None:
                self._state[key] = [now, now, 1]
                emit, count = True, 1
            else:
                st[2] += 1
                emit = now - st[1] >= self.every
                if emit:
                    st[1] = now
                count = st[2]
        if emit:
            suffix = "" if count == 1 else " (failed %d times so far)" % count
            self.log.warning(msg + suffix, *args, exc_info=exc_info)

    def ok(self, key, msg=None, *args):
        with self._lock:
            st = self._state.pop(key, None)
        if st is not None and msg:
            self.log.info(msg + " (after %d failures)", *args, st[2])


# --- IP helpers --------------------------------------------------------------

CGNAT = ipaddress.ip_network("100.64.0.0/10")


def parse_ip(s):
    """ipaddress object, or None for anything that is not a plain IP."""
    try:
        return ipaddress.ip_address(str(s).split("%")[0])
    except ValueError:
        return None


def is_public(ip):
    a = parse_ip(ip)
    return bool(a) and a.is_global and not a.is_multicast


def is_private(ip):
    """RFC1918, ULA, link-local, loopback and CGNAT: never on the internet."""
    a = parse_ip(ip)
    if a is None:
        return False
    if a.version == 4 and a in CGNAT:
        return True
    return a.is_private or a.is_link_local or a.is_loopback


def ip_key(ip):
    """16-byte sortable key; IPv4 is mapped into ::ffff:0:0/96 so one table
    and one index cover both families."""
    a = ipaddress.ip_address(ip) if not isinstance(
        ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip
    if a.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + a.packed
    return a.packed


def atomic_write(path, data, mode="w"):
    """Write via temp file + rename so a crash never leaves half a file."""
    tmp = path + ".tmp"
    with open(tmp, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        f.write(data)
    os.replace(tmp, path)
