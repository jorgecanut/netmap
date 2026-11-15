# Router setup (OpenWrt 25.x)

The **Network** tab shows every connection of every device on your network. NetMap
gets them from your OpenWrt router over SSH. It logs in with its own key, and the
router locks that key to one script that can only run four read-only commands.

Tested against OpenWrt 25.12, which uses `apk` instead of `opkg`. On 24.x and
older, use `opkg update && opkg install conntrack` in step 1. Everything else is
the same.

All commands below run **on the router**: `ssh root@192.168.2.1` (use your router's address).

---

## 1. Install conntrack

```sh
apk update
apk add conntrack
conntrack -L | head -3          # should print a few connections
```

If `apk add conntrack` says the package doesn't exist, run `apk search conntrack`
and install the one called `conntrack` or `conntrack-tools`.

## 2. Install the NetMap feed script

Copy [`router/netmap-feed.sh`](router/netmap-feed.sh) from this repository to the router:

```sh
# from the machine that has the NetMap repo:
scp docs/router/netmap-feed.sh root@192.168.2.1:/usr/bin/netmap-feed
ssh root@192.168.2.1 chmod 755 /usr/bin/netmap-feed
```

It allows only these commands, and refuses anything else:

| Command              | Runs                                       | Used for                    |
|----------------------|--------------------------------------------|-----------------------------|
| `conntrack-snapshot` | `conntrack -L -o id`                       | connections open right now  |
| `conntrack-events`   | `conntrack -E -e NEW,DESTROY -o timestamp,id` | each connection as it opens/closes |
| `dns`                | `logread -f -e dnsmasq`                    | domain names (step 5)       |
| `leases`             | `cat /tmp/dhcp.leases`                     | device names                |

To keep the script across firmware upgrades, add it to the backup list:

```sh
echo /usr/bin/netmap-feed >> /etc/sysupgrade.conf
```

## 3. Give NetMap's key access

1. In NetMap open **Settings → Router**, enter the router address, tick
   **Enabled** and press **Save**. NetMap creates its key the first time.
2. Copy the line shown under **NetMap's public key**. It looks like this:

   ```
   command="/usr/bin/netmap-feed",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... netmap
   ```

3. On the router, append it to Dropbear's key file:

   ```sh
   vi /etc/dropbear/authorized_keys      # paste the line on its own row, save
   chmod 600 /etc/dropbear/authorized_keys
   ```

   LuCI also works: **System → Administration → SSH-Keys**. Paste the whole line,
   *including* the `command="..."` part.

4. Back in NetMap press **Test connection**. You should see
   *"Connected. The router reports N DHCP leases."*

The `command=` prefix is what makes this safe. Even if NetMap's key were stolen,
it could only run `netmap-feed`. It could not get a shell, forward ports or change
anything.

## 4. Count bytes per connection (recommended)

Without this the History shows who connected where and for how long, but not how much data was sent.

```sh
echo 'net.netfilter.nf_conntrack_acct=1' > /etc/sysctl.d/90-netmap.conf
sysctl -p /etc/sysctl.d/90-netmap.conf
```

**Hardware/software flow offloading** (Network → Firewall → *Routing/NAT
Offloading*) makes byte counts inaccurate, because offloaded packets skip the
counters. Connections are still logged correctly. Turn offloading off only if
you need exact byte counts: on a Flint 2 that costs CPU at gigabit speeds.

## 5. Domain names (recommended)

With this, rows say `LG-TV → api.lgtvsdp.com` instead of a bare Amazon/Cloudflare IP. That makes the
map far easier to read and makes rules like `ends(domain, ".ru")` possible.

```sh
uci set dhcp.@dnsmasq[0].logqueries='1'
uci commit dhcp
service dnsmasq restart
```

Then keep **Domain names** ticked in Settings → Router.

Notes:
- Busy networks generate a lot of query log. It only goes to the router's RAM log,
  so other messages roll out of `logread` faster. To keep more, raise the log size:
  `uci set system.@system[0].log_size='512'; uci commit system; service log restart`
  (KiB).
- Devices that use their own encrypted DNS (DoH/DoT, e.g. some browsers or Android
  "Private DNS") bypass dnsmasq. Their connections still appear, just without a domain name.

## 6. Name your subnets

In **Settings → Subnets** add each network, e.g. `LAN 192.168.2.0/24`, `IoT
192.168.3.0/24`, `Guest 192.168.4.0/24`, and pick a colour. NetMap suggests ranges
it has seen. Name individual devices in **Settings → Devices**. DHCP names are
used automatically.

**IPv6:** your devices' global IPv6 addresses are not private, so NetMap can't tell they are
yours unless you add the prefix as a subnet (e.g. `2a01:db8:1:2::/64`). You can
find it under LuCI → Network → Interfaces → lan → IPv6 prefix. Until you do,
IPv6 connections are skipped.

---

## What gets logged

| Direction  | Example                                         | On the map |
|------------|-------------------------------------------------|------------|
| `out`      | `192.168.3.20 (LG-TV) → 52.1.2.3:443`           | yes        |
| `in`       | `8.8.4.4 → your port forward → 192.168.2.50:32400` | yes (reversed arc) |
| `internal` | `192.168.3.20 → 192.168.2.5:445` (IoT → LAN)    | list only  |
| router     | the router's own updates, DNS-over-TLS…         | yes, device `router` |

Skipped as noise: internal DNS, DHCP, NTP, NetBIOS, mDNS and SSDP (ports 53, 67,
68, 123, 137, 138, 5353, 1900), ICMP, multicast and broadcast.

## Firewall

NetMap must reach the router's SSH port (22). From the LAN zone that is allowed by
default. If NetMap runs on another subnet or VLAN, allow it with a traffic rule
from that zone to the router (*input*, TCP 22), ideally only from NetMap's IP.

## Troubleshooting

The router pill in the header and **Settings → Router → Status** show the error. The NetMap log
(`docker logs netmap`) has the details.

| Message | Fix |
|---|---|
| `router refused NetMap's key` | Step 3: the key line is missing or mistyped in `/etc/dropbear/authorized_keys`. |
| `conntrack is not installed` | Step 1. |
| `netmap-feed script rejected the command` | The script on the router is old or edited; copy it again (step 2). |
| `cannot reach the router's SSH server` | Wrong address/port, or a firewall rule (above). |
| `the router's host key changed` | You reinstalled the router. Press **Forget host key**, then **Test connection**. |
| `router clock is N s off` | The router has no time yet (NTP). Harmless: NetMap uses its own clock. |
| Connections but no device names | `/tmp/dhcp.leases` is empty (static IPs). Name devices in Settings → Devices. |
| No domain names | Step 5, and the device may use its own encrypted DNS. |

Test the script by hand from the NetMap machine (Docker: `docker exec -it netmap sh`):

```sh
ssh -i /data/router_key -o UserKnownHostsFile=/data/router_known_hosts root@192.168.2.1 leases
```
