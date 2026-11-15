"""HTTP server: static page + JSON API.

Every API route is declared in ROUTES with its auth level:
  "public"  no login needed (login/setup/me)
  "read"    logged in
  "write"   logged in + X-NetMap-CSRF header matching the session
Handlers take (app, req) and return a JSON-able object or raise ApiError.
"""

import http.cookies
import ipaddress
import json
import logging
import mimetypes
import os
import re
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import VERSION, rules, threats
from .auth import AuthError
from .rules import RuleError, compile_rule, context_for, test_rule
from .store import row_to_conn
from .util import parse_ip

log = logging.getLogger("netmap.web")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
COOKIE = "netmap_session"
MAX_BODY = 256 * 1024
CSP = ("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
       "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "img-src 'self' data: https://server.arcgisonline.com https://tile.openstreetmap.org; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_HOST = re.compile(r"^[A-Za-z0-9.:\-\[\]]{1,253}$")
_USER = re.compile(r"^[a-z_][a-z0-9_\-]{0,31}$")


class ApiError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


class Req:
    def __init__(self, query, body, session, client):
        self.query, self.body, self.session, self.client = query, body, session, client

    def arg(self, name, default=None):
        return self.query.get(name, [default])[0]

    def field(self, name, default=None, kind=str, maxlen=200):
        v = self.body.get(name, default)
        if v is None:
            return None
        if kind is bool:
            return bool(v)
        if kind is int:
            try:
                return int(v)
            except (TypeError, ValueError):
                raise ApiError("%s must be a number" % name)
        v = str(v).strip()
        if len(v) > maxlen:
            raise ApiError("%s is too long (max %d characters)" % (name, maxlen))
        return v


def _scope(req):
    s = req.arg("scope", "local")
    if s not in ("local", "network"):
        raise ApiError("scope must be local or network")
    return s


# --- handlers -----------------------------------------------------------------------

def h_me(app, req):
    s = req.session
    return {"version": VERSION, "authed": s is not None, "setup": app.auth.needs_setup(),
            "auth_disabled": app.auth.disabled, "csrf": s["csrf"] if s else None}


def h_setup(app, req):
    try:
        return app.auth.setup(req.field("code"), req.body.get("password"), req.client)
    except AuthError as e:
        raise ApiError(str(e), 403)


def h_login(app, req):
    try:
        return app.auth.login(req.body.get("password"), req.client)
    except AuthError as e:
        raise ApiError(str(e), 403)


def h_logout(app, req):
    app.auth.logout(req.session)
    return {"ok": True}


def h_password(app, req):
    try:
        app.auth.change_password(req.session, req.body.get("current"), req.body.get("new"))
    except AuthError as e:
        raise ApiError(str(e), 403)
    return {"ok": True}


def h_live(app, req):
    scope = _scope(req)
    v = app.tracker.live_view(scope)
    v.update(app.meta(scope))
    return v


def h_at(app, req):
    scope = _scope(req)
    try:
        t = float(req.arg("t"))
    except (TypeError, ValueError):
        raise ApiError("t must be a unix timestamp")
    v = app.tracker.at_view(scope, t)
    v.update(app.meta(scope))
    v["at"] = t
    return v


def h_range(app, req):
    return {"min": app.store.time_range(_scope(req)), "now": time.time()}


def h_history(app, req):
    scope = _scope(req)
    try:
        before = int(req.arg("before")) if req.arg("before") else None
        limit = min(500, max(1, int(req.arg("limit", "200"))))
        sev = int(req.arg("sev", "0"))
    except ValueError:
        raise ApiError("before, limit and sev must be numbers")
    subnets = [s for s in (req.arg("subnets") or "").split(",") if s]
    rows, last = app.tracker.history(scope, before, limit, sev,
                                     (req.arg("q") or "").strip() or None, subnets)
    return {"rows": rows, "next": last if len(rows) >= limit else None}


def h_config(app, req):
    rt = app.feed.config()
    try:
        pub = app.feed.ssh.public_key()
        key_error = None
    except (OSError, RuntimeError) as e:
        pub, key_error = None, str(e)
    return {
        "subnets": app.store.subnets(), "devices": app.tracker.known_devices(),
        "suggested_subnets": app.tracker.suggested_subnets(),
        "rules": [dict(r, error=app.engine.errors.get(r["id"])) for r in app.store.rules()],
        "rule_fields": rules.FIELDS,
        "rule_functions": {k: v[1] for k, v in rules.FUNCTIONS.items()},
        "severities": threats.SEVERITIES,
        "verdicts": [dict(v, target=k) for k, v in sorted(app.store.verdicts().items())],
        "router": dict(rt, status=app.feed.status, public_key=pub, key_error=key_error),
        "threats": app.threats.status(),
        "db_mb": round(app.store.size_bytes() / 1048576, 1),
        "db_max_mb": app.store.max_bytes // 1048576,
        "geo": {"offline": app.geo.offline_state, "month": app.geo.offline.built_month(),
                "online": app.geo.state},
    }


def h_subnet_save(app, req):
    name = req.field("name", maxlen=40)
    cidr = req.field("cidr", maxlen=50)
    color = req.field("color", "#3987e5", maxlen=7)
    if not name:
        raise ApiError("name is required")
    try:
        cidr = str(ipaddress.ip_network(cidr, strict=False))
    except (ValueError, TypeError):
        raise ApiError("'%s' is not a valid network, e.g. 192.168.3.0/24" % cidr)
    if not _COLOR.match(color):
        raise ApiError("color must look like #3987e5")
    sid = req.field("id", kind=int)
    try:
        with app.store.tx() as db:
            if sid:
                db.execute("UPDATE subnets SET name=?, cidr=?, color=? WHERE id=?",
                           (name, cidr, color, sid))
            else:
                db.execute("INSERT INTO subnets (name, cidr, color) VALUES (?,?,?)",
                           (name, cidr, color))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise ApiError("%s is already defined" % cidr)
        raise
    app.tracker.reload_config()
    return {"ok": True}


def h_subnet_delete(app, req):
    with app.store.tx() as db:
        db.execute("DELETE FROM subnets WHERE id=?", (req.arg("id"),))
    app.tracker.reload_config()
    return {"ok": True}


def h_device_save(app, req):
    ip = req.field("ip", maxlen=45)
    if not parse_ip(ip):
        raise ApiError("'%s' is not an IP address" % ip)
    name = req.field("name", "", maxlen=60)
    with app.store.tx() as db:
        if name:
            db.execute("INSERT OR REPLACE INTO devices VALUES (?,?)", (ip, name))
        else:
            db.execute("DELETE FROM devices WHERE ip=?", (ip,))
    app.tracker.reload_config()
    return {"ok": True}


def h_rule_save(app, req):
    name = req.field("name", maxlen=80)
    expr = req.field("expr", maxlen=rules.MAX_LEN)
    category = req.field("category", "custom", maxlen=40) or "custom"
    severity = req.field("severity", 2, kind=int)
    if not name:
        raise ApiError("name is required")
    if not 1 <= severity <= 4:
        raise ApiError("severity must be 1 (info) to 4 (high)")
    try:
        compile_rule(expr)
    except RuleError as e:
        raise ApiError("rule not saved - %s%s" % (e, " (at column %d)" % e.col if e.col else ""))
    rid = req.field("id", kind=int)
    enabled = 1 if req.body.get("enabled", True) else 0
    with app.store.tx() as db:
        if rid:
            db.execute("UPDATE rules SET name=?, expr=?, category=?, severity=?, enabled=?,"
                       " updated=? WHERE id=?",
                       (name, expr, category, severity, enabled, time.time(), rid))
        else:
            db.execute("INSERT INTO rules (name, expr, category, severity, enabled, updated)"
                       " VALUES (?,?,?,?,?,?)",
                       (name, expr, category, severity, enabled, time.time()))
    app.engine.errors.pop(rid, None)
    app.engine.reload()
    return {"ok": True}


def h_rule_delete(app, req):
    with app.store.tx() as db:
        db.execute("DELETE FROM rules WHERE id=?", (req.arg("id"),))
    app.engine.reload()
    return {"ok": True}


def h_rule_test(app, req):
    expr = req.field("expr", maxlen=rules.MAX_LEN)
    scope = req.field("scope", "network", maxlen=10)
    if scope not in ("local", "network"):
        raise ApiError("scope must be local or network")
    n = min(20000, max(1, req.field("limit", 2000, kind=int)))
    rows = app.store.q("SELECT * FROM conns WHERE scope=? ORDER BY id DESC LIMIT ?",
                       (scope, n))
    conns = [row_to_conn(r) for r in rows]
    try:
        res = test_rule(expr, ((c, context_for(c, app.tracker)) for c in conns))
    except RuleError as e:
        raise ApiError("%s%s" % (e, " (at column %d)" % e.col if e.col else ""))
    now = time.time()
    res["samples"] = [app.tracker.client_conn(c, now) for c in res["samples"]]
    return res


def h_verdict_save(app, req):
    target = req.field("target", maxlen=300)
    verdict = req.field("verdict", maxlen=20)
    kind, _, val = (target or "").partition(":")
    if kind not in ("ip", "domain", "device") or not val:
        raise ApiError("target must be ip:<address>, domain:<name> or device:<ip>")
    if kind in ("ip", "device") and not (parse_ip(val) or val == "router"):
        raise ApiError("'%s' is not an IP address" % val)
    if verdict not in ("trusted", "suspicious", "ignore"):
        raise ApiError("verdict must be trusted, suspicious or ignore")
    with app.store.tx() as db:
        db.execute("INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?)",
                   (kind + ":" + val.lower(), verdict, req.field("note", "", maxlen=200),
                    time.time()))
    app.tracker.reload_config()
    return {"ok": True}


def h_verdict_delete(app, req):
    with app.store.tx() as db:
        db.execute("DELETE FROM verdicts WHERE target=?", (req.arg("target"),))
    app.tracker.reload_config()
    return {"ok": True}


def h_router_save(app, req):
    host = req.field("host", "", maxlen=253)
    user = req.field("user", "root", maxlen=32) or "root"
    port = req.field("port", 22, kind=int)
    if host and not _HOST.match(host):
        raise ApiError("router address may only contain letters, digits, '.', ':' and '-'")
    if not _USER.match(user):
        raise ApiError("invalid SSH user name")
    if not 1 <= port <= 65535:
        raise ApiError("port must be 1-65535")
    app.store.set("router", {"enabled": bool(req.body.get("enabled")), "host": host,
                             "port": port, "user": user, "dns": bool(req.body.get("dns", True))})
    app.feed.reconfigure()
    return {"ok": True}


def h_router_test(app, req):
    return app.feed.test()


def h_router_forget(app, req):
    app.feed.ssh.forget_host_key()
    app.feed.reconfigure()
    return {"ok": True}


def h_quit(app, req):
    threading.Thread(target=app.shutdown, daemon=True).start()
    return {"ok": True}


ROUTES = {
    ("GET", "/api/me"): (h_me, "public"),
    ("POST", "/api/setup"): (h_setup, "public"),
    ("POST", "/api/login"): (h_login, "public"),
    ("POST", "/api/logout"): (h_logout, "write"),
    ("POST", "/api/password"): (h_password, "write"),
    ("GET", "/api/live"): (h_live, "read"),
    ("GET", "/api/at"): (h_at, "read"),
    ("GET", "/api/range"): (h_range, "read"),
    ("GET", "/api/history"): (h_history, "read"),
    ("GET", "/api/config"): (h_config, "read"),
    ("POST", "/api/subnets"): (h_subnet_save, "write"),
    ("DELETE", "/api/subnets"): (h_subnet_delete, "write"),
    ("POST", "/api/devices"): (h_device_save, "write"),
    ("POST", "/api/rules"): (h_rule_save, "write"),
    ("DELETE", "/api/rules"): (h_rule_delete, "write"),
    ("POST", "/api/rules/test"): (h_rule_test, "write"),
    ("POST", "/api/verdicts"): (h_verdict_save, "write"),
    ("DELETE", "/api/verdicts"): (h_verdict_delete, "write"),
    ("POST", "/api/router"): (h_router_save, "write"),
    ("POST", "/api/router/test"): (h_router_test, "write"),
    ("POST", "/api/router/forget-host-key"): (h_router_forget, "write"),
    ("POST", "/api/quit"): (h_quit, "write"),
}


# --- HTTP plumbing ------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    app = None                     # set by serve()
    server_version = "NetMap"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    # helpers
    def _client(self):
        xff = self.headers.get("X-Forwarded-For")
        return self.client_address[0] + (" (via proxy for %s)" % xff if xff else "")

    def _host_ok(self):
        host = (self.headers.get("Host") or "").lower()
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        name = name.strip("[]")
        return name in self.app.allowed_hosts

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        u = urllib.parse.urlsplit(origin)
        return (u.hostname or "").lower() in self.app.allowed_hosts

    def _send(self, status, body, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # Map tile servers (Esri, OpenStreetMap usage policy) require a Referer.
        # Send only the origin cross-site - never page paths or query strings.
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, extra=None):
        self._send(status, json.dumps(obj).encode(), "application/json", extra)

    def _cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = http.cookies.SimpleCookie(raw)
        except http.cookies.CookieError:
            return None
        return c[COOKIE].value if COOKIE in c else None

    def _set_cookie(self, token, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" \
            else ""
        return ("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s"
                % (COOKIE, token, max_age, secure))

    # verbs
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        if not self._host_ok():
            log.warning("rejected request for host %r from %s - add it to "
                        "NETMAP_ALLOWED_HOSTS if that is how you reach NetMap",
                        self.headers.get("Host"), self._client())
            return self._send(403, b"Forbidden: unknown host name. Set NETMAP_ALLOWED_HOSTS.",
                              "text/plain")
        url = urllib.parse.urlsplit(self.path)
        if not url.path.startswith("/api/"):
            return self._static(url.path) if method == "GET" else self._send(
                405, b"", "text/plain")
        route = ROUTES.get((method, url.path))
        if route is None:
            return self._json(404, {"error": "no such API: %s %s" % (method, url.path)})
        fn, level = route
        session = self.app.auth.session(self._cookie_token())
        if level != "public" and session is None:
            return self._json(401, {"error": "login required"})
        if method != "GET":
            if not self._origin_ok():
                return self._json(403, {"error": "cross-site request refused"})
            if level == "write" and self.headers.get("X-NetMap-CSRF") != session["csrf"]:
                return self._json(403, {"error": "missing or wrong CSRF token; reload the page"})
        try:
            body = self._body() if method != "GET" else {}
            req = Req(urllib.parse.parse_qs(url.query), body, session, self._client())
            out = fn(self.app, req)
        except ApiError as e:
            return self._json(e.status, {"error": str(e)})
        except Exception as e:
            log.error("API %s %s failed:\n%s", method, url.path, traceback.format_exc())
            return self._json(500, {"error": "internal error: %s: %s (details in the "
                                             "NetMap log)" % (type(e).__name__, e)})
        if fn in (h_login, h_setup):
            token, csrf = out
            return self._json(200, {"ok": True, "csrf": csrf},
                              [self._set_cookie(token, 30 * 86400)])
        if fn is h_logout:
            return self._json(200, out, [self._set_cookie("", 0)])
        return self._json(200, out)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError("request too large", 413)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError as e:
            raise ApiError("request body is not valid JSON: %s" % e)
        if not isinstance(body, dict):
            raise ApiError("request body must be a JSON object")
        return body

    def _static(self, path):
        name = "index.html" if path in ("/", "/index.html") else path[len("/static/"):] \
            if path.startswith("/static/") else None
        if not name or "/" in name or "\\" in name or name.startswith("."):
            return self._send(404, b"not found", "text/plain")
        full = os.path.join(STATIC_DIR, name)
        try:
            with open(full, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            return self._send(404, b"not found", "text/plain")
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)


def make_server(app, bind, port):
    Handler.app = app
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    return srv

