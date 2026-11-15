"""Sample router output shared by the tests. The router's WAN address is
81.40.10.5; the LAN subnets are 192.168.2.0/24 and 192.168.3.0/24.

Event timestamps are written as offsets from 1763200000 and rebased to "now"
at import, because NetMap ignores router timestamps that are far from its own
clock (a router's clock is often wrong right after boot)."""

import re
import time

_BASE = 1763200000
T0 = float(int(time.time()))

WAN = "81.40.10.5"

# conntrack -E -o timestamp,id  (with nf_conntrack_acct=1 for the bytes)
NEW_OUT = ("[1763200000.100000]\t    [NEW] tcp      6 120 SYN_SENT src=192.168.2.10 "
           "dst=93.184.216.34 sport=51234 dport=443 [UNREPLIED] src=93.184.216.34 "
           "dst=81.40.10.5 sport=443 dport=51234 id=3021434816")
DESTROY_OUT = ("[1763200012.600000]\t [DESTROY] tcp      6 src=192.168.2.10 dst=93.184.216.34 "
               "sport=51234 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=81.40.10.5 "
               "sport=443 dport=51234 packets=12 bytes=9000 [ASSURED] id=3021434816")
NEW_PORTFWD = ("[1763200001.000000]\t    [NEW] tcp      6 120 SYN_RECV src=8.8.4.4 dst=81.40.10.5 "
               "sport=55555 dport=32400 src=192.168.2.50 dst=8.8.4.4 sport=32400 dport=55555 "
               "id=999")
NEW_ROUTER_OUT = ("[1763200002.000000]\t    [NEW] udp      17 30 src=81.40.10.5 dst=1.1.1.1 "
                  "sport=40000 dport=853 [UNREPLIED] src=1.1.1.1 dst=81.40.10.5 sport=853 "
                  "dport=40000 id=1000")
NEW_INTERNAL = ("[1763200003.000000]\t    [NEW] tcp      6 120 SYN_SENT src=192.168.3.20 "
                "dst=192.168.2.5 sport=40001 dport=445 [UNREPLIED] src=192.168.2.5 "
                "dst=192.168.3.20 sport=445 dport=40001 id=1001")
NEW_DNS_INTERNAL = ("[1763200004.000000]\t    [NEW] udp      17 30 src=192.168.3.20 "
                    "dst=192.168.3.1 sport=5000 dport=53 [UNREPLIED] src=192.168.3.1 "
                    "dst=192.168.3.20 sport=53 dport=5000 id=1002")
NEW_ICMP = ("[1763200005.000000]\t    [NEW] icmp     1 30 src=192.168.2.10 dst=8.8.8.8 "
            "type=8 code=0 id=1 [UNREPLIED] src=8.8.8.8 dst=81.40.10.5 type=0 code=0 id=1")

# conntrack -L -o id
SNAPSHOT = [
    "tcp      6 431999 ESTABLISHED src=192.168.2.20 dst=142.250.1.1 sport=40000 dport=443 "
    "src=142.250.1.1 dst=81.40.10.5 sport=443 dport=40000 [ASSURED] mark=0 use=1 id=12345",
    "udp      17 29 src=192.168.3.30 dst=162.159.200.1 sport=123 dport=123 "
    "src=162.159.200.1 dst=81.40.10.5 sport=123 dport=123 mark=0 use=1 id=12346",
]

LEASES = ("1763290000 aa:bb:cc:dd:ee:01 192.168.2.10 laptop 01:aa:bb:cc:dd:ee:01\n"
          "1763290000 aa:bb:cc:dd:ee:02 192.168.3.20 LG-TV *\n"
          "1763290000 aa:bb:cc:dd:ee:03 192.168.3.30 * *\n")

DNS = [
    "Sat Nov 15 20:00:00 2026 daemon.info dnsmasq[1234]: query[A] example.com from 192.168.2.10",
    "Sat Nov 15 20:00:00 2026 daemon.info dnsmasq[1234]: forwarded example.com to 1.1.1.1",
    "Sat Nov 15 20:00:00 2026 daemon.info dnsmasq[1234]: reply example.com is 93.184.216.34",
    "Sat Nov 15 20:00:01 2026 daemon.info dnsmasq[1234]: cached www.google.com is 142.250.1.1",
    "Sat Nov 15 20:00:01 2026 daemon.info dnsmasq[1234]: reply cdn.example is <CNAME>",
]


_TS = re.compile(r"\[(\d{10})\.(\d+)\]")


def shift(line, seconds):
    """The same line with its event timestamp moved by `seconds`."""
    return _TS.sub(lambda m: "[%.6f]" % (float(m.group(1) + "." + m.group(2)) + seconds),
                   line, count=1)


for _name in ("NEW_OUT", "DESTROY_OUT", "NEW_PORTFWD", "NEW_ROUTER_OUT", "NEW_INTERNAL",
              "NEW_DNS_INTERNAL", "NEW_ICMP"):
    globals()[_name] = shift(globals()[_name], T0 - _BASE)
