"""Startup configuration: command-line flags, each with an environment variable.

Only things needed before the app can start live here. Everything you manage
day to day (router, subnets, device names, rules, password) is set in the web
interface and stored in the database.
"""

import argparse
import os
import sys

DEFAULT_PORT = 8339


def _env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _env_int(name, default):
    v = _env(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        sys.exit("%s must be a whole number, got %r" % (name, v))


def parse(argv=None):
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(
        prog="netmap.py",
        description="NetMap - live map of this machine's and your network's connections")
    ap.add_argument("--port", type=int, default=_env_int("NETMAP_PORT", DEFAULT_PORT),
                    help="port to serve on (default 8339). Env: NETMAP_PORT")
    ap.add_argument("--bind", metavar="ADDR", default=_env("NETMAP_BIND", "127.0.0.1"),
                    help="IPv4 address to listen on (default 127.0.0.1; 0.0.0.0 = "
                         "every interface). Env: NETMAP_BIND")
    ap.add_argument("--allow-host", metavar="NAMES", default=_env("NETMAP_ALLOWED_HOSTS", ""),
                    help="comma-separated names/IPs browsers use to reach NetMap, e.g. "
                         "netmap.example.com,192.168.1.50. Env: NETMAP_ALLOWED_HOSTS")
    ap.add_argument("--data-dir", metavar="DIR", default=_env("NETMAP_DATA_DIR", script_dir),
                    help="where the database, caches and keys live. Env: NETMAP_DATA_DIR")
    ap.add_argument("--max-db-mb", type=int, default=_env_int("NETMAP_MAX_DB_MB", 4096),
                    help="connection log size cap in MB; oldest rows are deleted "
                         "first (default 4096). Env: NETMAP_MAX_DB_MB")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between scans of this machine's sockets (default 2)")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser")
    ap.add_argument("--home", metavar="LAT,LON", default=_env("NETMAP_HOME"),
                    help="set the map's home location manually. Env: NETMAP_HOME")
    ap.add_argument("--no-auth", action="store_true",
                    default=_env("NETMAP_AUTH", "on").lower() == "off",
                    help="disable the login (only allowed when bound to 127.0.0.1). "
                         "Env: NETMAP_AUTH=off")
    ap.add_argument("--no-geo-download", action="store_true",
                    default=_env("NETMAP_GEO_DOWNLOAD", "on").lower() == "off",
                    help="don't download the offline location database; use the "
                         "online lookup only. Env: NETMAP_GEO_DOWNLOAD=off")
    ap.add_argument("--no-geo-online", action="store_true",
                    default=_env("NETMAP_GEO_ONLINE", "on").lower() == "off",
                    help="never send IPs to ip-api.com; addresses the offline database "
                         "doesn't know stay unlocated. Env: NETMAP_GEO_ONLINE=off")
    ap.add_argument("--reset-password", action="store_true",
                    help="clear the admin password and exit; the next start prints "
                         "a setup code")
    args = ap.parse_args(argv)

    args.interval = max(0.5, args.interval)
    args.allowed_hosts = {h.strip().lower() for h in args.allow_host.split(",") if h.strip()}
    args.allowed_hosts |= {"localhost", "127.0.0.1"}
    if args.bind not in ("0.0.0.0", ""):
        args.allowed_hosts.add(args.bind.lower())
    args.loopback_only = args.bind.startswith("127.")
    if args.no_auth and not args.loopback_only:
        sys.exit("--no-auth / NETMAP_AUTH=off is only allowed with --bind 127.0.0.1: "
                 "anyone on your network could otherwise read every connection")
    if args.home:
        try:
            lat, lon = (float(x) for x in args.home.split(","))
            args.home = (lat, lon)
        except ValueError:
            sys.exit("--home must look like 39.74,-104.99")
    os.makedirs(args.data_dir, exist_ok=True)
    args.db_path = os.path.join(args.data_dir, "netmap.sqlite")
    args.geo_db_path = os.path.join(args.data_dir, "geoip.sqlite")
    return args
