"""Behaviour rules: Python-syntax expressions, evaluated safely.

A rule is a single expression such as

    subnet == "iot" and direction == "out" and new_country

It is parsed with Python's own parser, then checked against an allowlist of
syntax and evaluated by the small interpreter below - never by eval(). There
are no imports, attributes, loops, assignments or file access, so a rule typed
into the web UI cannot run arbitrary code. See docs/RULES.md for the language.
"""

import ast
import ipaddress
import logging
import operator
import threading
import time

from .threats import SEV
from .util import Throttle

log = logging.getLogger("netmap.rules")
throttle = Throttle(log)

MAX_LEN = 2000
MAX_NODES = 400
MAX_SEQ = 1000


class RuleError(Exception):
    def __init__(self, msg, col=None):
        super().__init__(msg)
        self.col = col


# Field name -> one-line description (shown in the editor and docs).
FIELDS = {
    "scope": "'local' (this machine) or 'network' (router)",
    "direction": "'out', 'in' (from the internet) or 'internal' (between subnets)",
    "proto": "'tcp' or 'udp'",
    "device": "device name (or its IP if it has no name); 'router' for the router",
    "device_ip": "device LAN IP ('' for this machine)",
    "subnet": "name of the device's subnet ('' if none matches)",
    "proc": "process name (this-machine scope only)",
    "remote_ip": "the other end's IP",
    "remote_port": "the other end's port",
    "local_port": "the device's port",
    "domain": "name the device looked up for remote_ip ('' if unknown)",
    "country": "two-letter country code of remote_ip, e.g. 'ES'",
    "city": "city of remote_ip",
    "org": "network owner of remote_ip, e.g. 'Google LLC'",
    "lists": "blocklist keys remote_ip is on, e.g. ['tor']",
    "threat": "highest blocklist category, e.g. 'malware-c2' ('' if none)",
    "threat_severity": "highest blocklist severity, 0-4 (compare with low/medium/high)",
    "bytes_out": "bytes sent (0 until the connection closes)",
    "bytes_in": "bytes received (0 until the connection closes)",
    "duration": "seconds open (0 until the connection closes)",
    "closed": "True once the connection has ended",
    "hour": "local hour it started, 0-23",
    "weekday": "0 = Monday ... 6 = Sunday",
    "new_country": "True if this device never contacted this country before",
    "new_remote": "True if this device never contacted this IP before",
}
CONSTANTS = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4,
             "True": True, "False": False, "None": None}


def _in_net(ip, cidr):
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return False


def _s(x):
    return "" if x is None else str(x)


FUNCTIONS = {
    "in_net": (_in_net, "in_net(ip, '10.0.0.0/8') - IP inside a network"),
    "ends": (lambda s, suf: _s(s).lower().endswith(_s(suf).lower()),
             "ends(domain, '.ru') - case-insensitive suffix"),
    "starts": (lambda s, pre: _s(s).lower().startswith(_s(pre).lower()),
               "starts(proc, 'python')"),
    "contains": (lambda s, sub: _s(sub).lower() in _s(s).lower(),
                 "contains(org, 'amazon') - case-insensitive"),
    "lower": (lambda s: _s(s).lower(), "lower(text)"),
    "len": (lambda x: len(x) if isinstance(x, (str, list, tuple, set)) else 0, "len(lists)"),
}

_CMP = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
        ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
        ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
        ast.Is: operator.is_, ast.IsNot: operator.is_not}
_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
_ALLOWED = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub,
            ast.UAdd, ast.BinOp, ast.Compare, ast.Name, ast.Load, ast.Constant, ast.Tuple,
            ast.List, ast.Set, ast.Call, ast.IfExp) + tuple(_CMP) + tuple(_BIN)


def compile_rule(expr):
    """Parse and validate. Returns the AST; raises RuleError with a column."""
    expr = (expr or "").strip()
    if not expr:
        raise RuleError("the rule is empty")
    if len(expr) > MAX_LEN:
        raise RuleError("the rule is longer than %d characters" % MAX_LEN)
    try:
        tree = ast.parse(expr.replace("\n", " "), mode="eval")
    except SyntaxError as e:
        raise RuleError("syntax error: %s" % e.msg, e.offset)
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_NODES:
        raise RuleError("the rule is too complex (over %d parts)" % MAX_NODES)
    for n in nodes:
        col = getattr(n, "col_offset", None)
        col = col + 1 if col is not None else None
        if not isinstance(n, _ALLOWED):
            raise RuleError("'%s' is not allowed in rules" % type(n).__name__, col)
        if isinstance(n, ast.Name) and n.id not in FIELDS and n.id not in CONSTANTS \
                and n.id not in FUNCTIONS:
            raise RuleError("unknown name '%s' (see the field list)" % n.id, col)
        if isinstance(n, ast.Constant) and not isinstance(
                n.value, (str, int, float, bool, type(None))):
            raise RuleError("only text, numbers, True/False/None are allowed", col)
        if isinstance(n, ast.Call):
            if not isinstance(n.func, ast.Name) or n.func.id not in FUNCTIONS:
                raise RuleError("unknown function (allowed: %s)" % ", ".join(FUNCTIONS), col)
            if n.keywords or any(isinstance(a, ast.Starred) for a in n.args):
                raise RuleError("functions take plain arguments only", col)
    return tree


class Ctx:
    """Rule context. Values may be zero-argument callables, computed on first
    use - so the database-backed fields (new_country, new_remote) only cost a
    query in rules that actually mention them."""

    def __init__(self, values):
        self.v = values

    def __getitem__(self, k):
        x = self.v[k]
        if callable(x):
            x = self.v[k] = x()
        return x


def evaluate(tree, ctx):
    return bool(_ev(tree.body, ctx))


def _ev(n, ctx):
    t = type(n)
    if t is ast.Constant:
        return n.value
    if t is ast.Name:
        if n.id in CONSTANTS:
            return CONSTANTS[n.id]
        return ctx[n.id]
    if t is ast.BoolOp:
        if isinstance(n.op, ast.And):
            for v in n.values:
                if not _ev(v, ctx):
                    return False
            return True
        for v in n.values:
            if _ev(v, ctx):
                return True
        return False
    if t is ast.UnaryOp:
        v = _ev(n.operand, ctx)
        if isinstance(n.op, ast.Not):
            return not v
        _num(v)
        return -v if isinstance(n.op, ast.USub) else +v
    if t is ast.Compare:
        left = _ev(n.left, ctx)
        for op, right_n in zip(n.ops, n.comparators):
            right = _ev(right_n, ctx)
            if not _CMP[type(op)](left, right):
                return False
            left = right
        return True
    if t is ast.BinOp:
        a, b = _ev(n.left, ctx), _ev(n.right, ctx)
        if isinstance(n.op, ast.Add) and isinstance(a, str) and isinstance(b, str):
            return a + b
        _num(a), _num(b)                       # no "x" * 10**9 tricks
        return _BIN[type(n.op)](a, b)
    if t in (ast.Tuple, ast.List, ast.Set):
        if len(n.elts) > MAX_SEQ:
            raise RuleError("list too long")
        vals = [_ev(e, ctx) for e in n.elts]
        return set(vals) if t is ast.Set else tuple(vals)
    if t is ast.Call:
        return FUNCTIONS[n.func.id][0](*[_ev(a, ctx) for a in n.args])
    if t is ast.IfExp:
        return _ev(n.body, ctx) if _ev(n.test, ctx) else _ev(n.orelse, ctx)
    raise RuleError("unsupported expression")       # unreachable after compile_rule


def _num(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError("arithmetic needs numbers, got %r" % (v,))


class Engine:
    """Holds the compiled enabled rules and runs them on each connection."""

    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.compiled = []            # (rule dict, tree)
        self.errors = {}              # rule id -> {"count", "last"}

    def reload(self):
        compiled = []
        for r in self.store.rules(enabled_only=True):
            try:
                compiled.append((r, compile_rule(r["expr"])))
            except RuleError as e:
                log.warning("rule %d '%s' disabled: %s", r["id"], r["name"], e)
        with self.lock:
            self.compiled = compiled
        log.info("%d behaviour rules active", len(compiled))

    def run(self, ctx):
        with self.lock:
            compiled = self.compiled
        flags = []
        for r, tree in compiled:
            try:
                hit = evaluate(tree, ctx)
            except Exception as e:           # a rule bug must never stop logging
                err = self.errors.setdefault(r["id"], {"count": 0, "last": ""})
                err["count"] += 1
                err["last"] = "%s: %s" % (type(e).__name__, e)
                throttle.fail("rule%d" % r["id"], "rule %d '%s' failed: %s",
                              r["id"], r["name"], err["last"])
                continue
            if hit:
                flags.append({"src": "rule", "name": r["name"], "rule_id": r["id"],
                              "category": r["category"], "severity": r["severity"]})
        return flags


def test_rule(expr, contexts, limit=20):
    """Run `expr` over contexts: {"checked", "matched", "errors", "samples"}."""
    tree = compile_rule(expr)
    out = {"checked": 0, "matched": 0, "errors": 0, "first_error": None, "samples": []}
    for conn, ctx in contexts:
        out["checked"] += 1
        try:
            if evaluate(tree, ctx):
                out["matched"] += 1
                if len(out["samples"]) < limit:
                    out["samples"].append(conn)
        except Exception as e:
            out["errors"] += 1
            if out["first_error"] is None:
                out["first_error"] = "%s: %s" % (type(e).__name__, e)
    return out


def context_for(conn, env):
    """Build the rule context for a connection dict. `env` supplies subnet and
    device lookups and the history queries (see tracker.Enricher)."""
    lists = [f["key"] for f in conn.get("flags", []) if f.get("src") == "list"]
    list_flags = [f for f in conn.get("flags", []) if f.get("src") == "list"]
    top = max(list_flags, key=lambda f: f["severity"]) if list_flags else None
    lt = time.localtime(conn["start_ts"])
    closed = conn.get("end_ts") is not None
    dev_ip = conn["device"] if conn["scope"] == "network" else ""
    return Ctx({
        "scope": conn["scope"], "direction": conn["direction"], "proto": conn["proto"],
        "device": env.device_name(conn), "device_ip": dev_ip,
        "subnet": env.subnet_name(dev_ip), "proc": conn.get("proc") or "",
        "remote_ip": conn["remote_ip"], "remote_port": conn.get("remote_port") or 0,
        "local_port": conn.get("local_port") or 0, "domain": conn.get("domain") or "",
        "country": conn.get("cc") or "", "city": conn.get("city") or "",
        "org": conn.get("org") or "", "lists": lists,
        "threat": top["category"] if top else "",
        "threat_severity": top["severity"] if top else 0,
        "bytes_out": conn.get("bytes_out") or 0, "bytes_in": conn.get("bytes_in") or 0,
        "duration": (conn["end_ts"] - conn["start_ts"]) if closed else 0,
        "closed": closed, "hour": lt.tm_hour, "weekday": lt.tm_wday,
        "new_country": lambda: bool(conn.get("cc")) and not env.seen_country(conn),
        "new_remote": lambda: not env.seen_remote(conn),
    })


SEVERITY_NAMES = {v: k for k, v in SEV.items()}
