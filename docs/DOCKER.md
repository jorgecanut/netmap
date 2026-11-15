# Docker / TrueNAS

NetMap runs on the host's network and process namespaces, so the **This machine**
tab shows the server's own connections and those of every other container on it.
The **Network** tab works from any machine that can SSH to the router.

## docker-compose.yml

The repository's `docker-compose.yml` builds the image from this folder:

```sh
docker compose up -d --build
docker logs netmap          # first start prints the setup code
```

For TrueNAS (**Apps → Discover → ⋮ → Install via YAML**) build the image once from
a shell, then use `image: netmap:latest` with `pull_policy: never`:

```sh
cd /mnt/POOL/apps/netmap && git pull && docker build -t netmap:latest .
```

```yaml
services:
  netmap:
    image: netmap:latest
    pull_policy: never
    container_name: netmap
    restart: unless-stopped
    network_mode: host
    pid: host
    cap_drop: [ALL]
    cap_add: [SYS_PTRACE, DAC_READ_SEARCH]
    security_opt:
      - no-new-privileges:true
      - apparmor:unconfined
    read_only: true
    tmpfs: [/tmp]
    environment:
      - NETMAP_PORT=8339
      - NETMAP_BIND=0.0.0.0
      - NETMAP_ALLOWED_HOSTS=192.168.2.50,netmap.example.com
      - NETMAP_DATA_DIR=/data
      - NETMAP_MAX_DB_MB=4096
    volumes:
      - /mnt/POOL/apps/netmap/data:/data
```

After `git pull`, rebuild the image and **stop + start** the app (a plain restart
keeps the old image).

## First start

1. `docker logs netmap` shows `FIRST-TIME SETUP: ... enter setup code XXXXXX-XXXXXX`.
2. Open NetMap, enter the code and choose the admin password (8+ characters).
3. Settings → Router: see [ROUTER.md](ROUTER.md).

Forgot the password: `docker exec netmap python netmap.py --reset-password`, then
restart the app and use the new setup code from the log.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `NETMAP_PORT` | 8339 | port |
| `NETMAP_BIND` | 127.0.0.1 | listen address; `0.0.0.0` for your network / a reverse proxy |
| `NETMAP_ALLOWED_HOSTS` | (localhost) | names/IPs browsers use, comma-separated. **Include your proxy's hostname.** |
| `NETMAP_DATA_DIR` | script folder | database, caches, router key |
| `NETMAP_MAX_DB_MB` | 4096 | connection log cap; oldest deleted first. The offline location database (`geoip.sqlite`, ~720 MB) comes on top |
| `NETMAP_GEO_DOWNLOAD` | on | `off`: don't download the offline location database |
| `NETMAP_GEO_ONLINE` | on | `off`: never send IPs to ip-api.com |
| `NETMAP_HOME` | auto | `lat,lon` of home on the map |
| `NETMAP_AUTH` | on | `off` only allowed with `NETMAP_BIND=127.0.0.1` |
| `NETMAP_LOG_LEVEL` | INFO | `DEBUG` for more detail |

Everything else (router, subnets, device names, rules, verdicts, password) is set in
the web interface and stored in `/data/netmap.sqlite`.

## Behind a reverse proxy

- Point the proxy at `http://<truenas-ip>:8339`. NetMap must listen where the proxy
  can reach it (`NETMAP_BIND=0.0.0.0` or the TrueNAS IP).
- Add the public hostname to `NETMAP_ALLOWED_HOSTS`, e.g. `netmap.example.com`.
  Requests for any other `Host` get *403 unknown host name*, and the log says which name to add.
- Pass the `Host` header through unchanged (the default in Nginx Proxy Manager, Caddy and Traefik).
- Send `X-Forwarded-Proto: https` so the login cookie is marked `Secure` (also the default in those proxies).
- No WebSockets are needed; NetMap polls plain HTTP.

## Why these privileges

| Setting | Needed for |
|---|---|
| `network_mode: host` | read the host's sockets; reach the router |
| `pid: host` | see every process and container network namespace |
| `SYS_PTRACE`, `DAC_READ_SEARCH`, `apparmor:unconfined` | map sockets to process names (`/proc/<pid>/fd`). Without them the This machine tab still works, with process names shown as "unknown" |
| everything else dropped, `read_only`, `no-new-privileges` | least privilege |

The Network tab needs none of the special privileges. Only the This machine tab does.
