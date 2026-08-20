# NetMap

**A live world map of your computer's network connections — in your browser.**

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib)-brightgreen)

NetMap watches the active network connections leaving *your computer*, geolocates
the remote servers, and plots them on a live, dark-themed world map with animated
arcs from your location to each destination. Hover any point to see the process,
port, city, and ISP behind it.

A single Python file, no packages required, on every supported OS. `psutil` is
optional — if it happens to be installed NetMap uses it, since it is faster and
reports throughput, but nothing depends on it.

> **Want your whole network** — phones, TVs, IoT, every device — instead of just
> one computer? See the sibling project **[NetWatch](../../netwatch)**, which does
> the same thing network-wide from a mirrored switch port.

---

## Screenshot

The left panel is a live dark-themed world map with animated arcs from your
location to each remote host; the right panel lists every connection with its
process, city, and ISP. NetMap shares its interface with its network-wide sibling
**[NetWatch](../../netwatch)** — see the screenshots there for the look and feel.

> Tip: run NetMap, take a screenshot, drop it in a `docs/` folder, and reference it
> here (`![NetMap](docs/netmap.png)`) to give your repo a hero image.

---

## Why a helper script instead of a plain web page?

A browser is sandboxed and cannot see your computer's network connections. NetMap
runs a tiny local server that reads the connection table, does the geolocation,
and serves the map at `http://localhost:8339` for you to open. Nothing is exposed
to your network — it binds to `127.0.0.1` only.

## Features

- Live map of every outbound connection from your machine, updated every ~2s
- Your own location shown as a pulsing home marker, with animated arcs to each host
- Markers sized by connection count; hover for process, port, city, and ISP
- **Threat-intelligence flagging** against Tor exit nodes, FireHOL level-1 and
  Spamhaus DROP (auto-refreshed, disk-cached): blocklisted destinations turn red,
  sort to the top of the list, and the tooltip names *which* list matched
- Filterable side panel and live stats (active connections, hosts, flagged,
  countries, ↑/↓ rate)
- Graceful fallbacks when the map tiles or geolocation service are blocked
- Geolocation results cached locally so restarts light up instantly

## Requirements

- Python 3.7+ — and nothing else
- Optional: `psutil`. Used automatically when present (faster, adds throughput).
  Without it NetMap reads the socket table directly: `/proc/net` on Linux,
  `netstat -ano` + `tasklist` on Windows, `lsof` on macOS.

Sockets owned by *other* users are only attributable when running elevated; your
own processes always resolve.

## Quick start

```bash
python netmap.py
```

Your browser opens to `http://localhost:8339` automatically. Press `Ctrl+C` to stop.

**Windows:** double-click `NetMap.bat` to launch it with no console window (right-click
→ *Send to → Desktop* to make a desktop shortcut).

### Options

| Flag | Description |
|------|-------------|
| `--port N` | Serve on a different port (default 8339) |
| `--interval S` | Seconds between connection scans (default 2) |
| `--no-browser` | Don't auto-open the browser |
| `--home LAT,LON` | Set your map location manually (skips self-geolocation) |

## Privacy

NetMap binds to `127.0.0.1` only — nothing is exposed to your network. The only
data that leaves your machine is the set of remote IP addresses sent to the free
[ip-api.com](https://ip-api.com) service for geolocation, cached locally in
`netmap_geo_cache.json`. Use `--home LAT,LON` to skip locating yourself.

## How it works

NetMap reads your machine's connection table (via `psutil` when available,
otherwise the platform's own socket table), keeps only connections to public IPs,
geolocates them in batches, checks each against public reputation blocklists, and
serves a single self-contained HTML page that renders the map with
[Leaflet](https://leafletjs.com/) and polls a small JSON endpoint.

The page is served on `127.0.0.1` only — it is not reachable from your network.

## License

[MIT](LICENSE) © 2026 huskerminion
