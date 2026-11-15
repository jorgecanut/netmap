# Behaviour rules

Rules are your own threat checks, written in **Settings → Rules**. A rule is one
expression in Python syntax. NetMap runs it on every connection twice: when the
connection opens, and again when it closes (when `bytes_*` and `duration` are known).
When it's true, the connection gets a flag with your name, category and severity.
Flags show on the map and in the list, and you can filter History by them (*flagged only*).

```python
subnet == "IoT" and direction == "out" and new_country
```

Before saving, press **Test on recent connections** to see how many of the last
connections it would have matched.

## Safety

Rules look like Python but are **not run by Python**. NetMap parses the expression
and evaluates it with its own small interpreter. Only these are allowed:

- values: text in quotes, numbers, `True` / `False` / `None`, and lists like `("ES", "PT")`
- the fields and functions listed below
- `and` `or` `not`, comparisons `== != < <= > >=`, `in` / `not in`, `is` / `is not`
- arithmetic `+ - * / // %`, on numbers only
- `a if condition else b`

Anything else is rejected when you save: imports, attributes (`x.y`), indexing (`x[0]`),
loops, comprehensions, lambdas, assignments, `**`. So a rule typed into the web page
cannot read files or run commands on the server. A rule that fails while running
(e.g. comparing text with a number) counts as *not matched*. Its error count and
last error show in the rule list, and the other rules keep working.

## Fields

| Field | Meaning |
|---|---|
| `scope` | `"local"` (This machine tab) or `"network"` (router) |
| `direction` | `"out"`, `"in"` (from the internet, e.g. a port forward), `"internal"` (between your subnets) |
| `proto` | `"tcp"` or `"udp"` |
| `device` | device name, or its IP if it has no name; `"router"` for the router itself; the process name on the This machine tab |
| `device_ip` | the device's LAN IP (`""` on the This machine tab) |
| `subnet` | name of the device's subnet from Settings → Subnets (`""` if none) |
| `proc` | process name (This machine tab only) |
| `remote_ip`, `remote_port` | the other end |
| `local_port` | the device's own port |
| `domain` | name the device looked up for `remote_ip` (needs DNS logging, see ROUTER.md) |
| `country` | two-letter code of `remote_ip`, e.g. `"ES"`, `"US"`, `"CN"` |
| `city`, `org` | city and network owner (e.g. `"Amazon.com, Inc."`) |
| `lists` | blocklist keys the IP is on: `feodo`, `spamhaus`, `firehol`, `blocklistde`, `cins`, `tor` |
| `threat` | highest blocklist category: `malware-c2`, `hijacked`, `known-bad`, `attacker`, `anonymizer`, or `""` |
| `threat_severity` | highest blocklist severity, 0–4 (compare with `info`, `low`, `medium`, `high`) |
| `bytes_out`, `bytes_in` | bytes sent / received (0 until the connection closes; needs `nf_conntrack_acct=1` on the router) |
| `duration` | seconds the connection lasted (0 until it closes) |
| `closed` | `True` on the second run, when the connection has ended |
| `hour` | local hour it started, 0–23 |
| `weekday` | 0 = Monday … 6 = Sunday |
| `new_country` | `True` if this device has never contacted this country before |
| `new_remote` | `True` if this device has never contacted this IP before |

`new_country` and `new_remote` each need a database query. They're only computed
when a rule actually reaches them, so put cheap checks first:
`subnet == "IoT" and new_country`, not `new_country and subnet == "IoT"`.

## Functions

| Function | Example |
|---|---|
| `in_net(ip, cidr)` | `in_net(remote_ip, "10.0.0.0/8")` |
| `ends(text, suffix)` | `ends(domain, ".ru")`. Case-insensitive |
| `starts(text, prefix)` | `starts(proc, "python")` |
| `contains(text, part)` | `contains(org, "amazon")`. Case-insensitive |
| `lower(text)` | `lower(device) == "lg-tv"` |
| `len(x)` | `len(lists) >= 2` |

## Examples

```python
# IoT devices talking to a country for the first time            -> medium
subnet == "IoT" and direction == "out" and new_country

# Anything on the IoT network reaching a Tor exit or a blocklisted host -> high
subnet == "IoT" and threat_severity >= low

# Guests trying to reach your other networks                       -> medium
subnet == "Guest" and direction == "internal"

# The TV sending more than 50 MB in one connection                 -> low
device == "LG-TV" and closed and bytes_out > 50 * 1024 * 1024

# Remote administration / old protocols leaving the network        -> medium
direction == "out" and remote_port in (22, 23, 3389, 5900, 2323)

# Inbound connection on a port you never forwarded on purpose      -> high
direction == "in" and local_port not in (32400, 51820)

# Activity in the middle of the night from devices that should sleep -> low
subnet == "IoT" and 1 <= hour <= 5

# Domains in country-code TLDs you never use                       -> low
ends(domain, ".ru") or ends(domain, ".su") or ends(domain, ".cn")

# Large uploads from any device to a non-cloud network             -> medium
closed and bytes_out > 500 * 1024 * 1024 and not contains(org, "google") and not contains(org, "amazon")

# A device you don't expect to use the router's WAN directly       -> info
device == "printer" and direction == "out"
```

## Tips

- **Severity** decides the colour: info grey, low amber, medium orange, high red.
  The *flagged* tile counts hosts with any flag. Blocklist flags work the same way.
- **Category** is free text (`iot-anomaly`, `policy`, `exfiltration`…). It shows on
  the badge tooltip and is searchable in History.
- Rules apply to connections from the moment you save. Already-logged
  connections keep the flags they had.
- If a rule fires too often for a known-good destination, don't weaken the rule. Add a
  **verdict** instead: *Trust IP* / *Trust domain* on the host in the live list, or in
  Settings → Verdicts. Trusted flags stay visible, crossed out, but don't count.
- Rules are stored in the database (`rules` table). To back them up:
  `sqlite3 /data/netmap.sqlite '.dump rules'`.
