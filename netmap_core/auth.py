"""Single admin login.

- The password is stored as a salted scrypt hash in the settings table.
- First start (no password yet): a one-time setup code is printed to the log;
  the web page asks for it before letting you choose the password, so nobody
  else on the network can claim the install first.
- Forgot it?  python netmap.py --reset-password   (or `docker exec netmap ...`)
- Sessions: random token in an HttpOnly, SameSite=Strict cookie; only its
  SHA-256 is stored. Every state-changing request also needs the session's
  CSRF token in the X-NetMap-CSRF header.
- Brute force: after 5 failures in 10 minutes, logins pause for 60 seconds.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time

log = logging.getLogger("netmap.auth")

SESSION_DAYS = 30
MIN_PASSWORD = 8
FAIL_WINDOW, FAIL_MAX, LOCKOUT = 600, 5, 60
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


class AuthError(Exception):
    pass


def hash_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
                                      base64.b64encode(salt).decode(),
                                      base64.b64encode(h).decode())


def verify_password(pw, stored):
    try:
        _, n, r, p, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), dklen=32,
                             n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(got, base64.b64decode(h))
    except (ValueError, TypeError) as e:
        log.error("stored password hash is unreadable (%s); reset it with "
                  "--reset-password", e)
        return False


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, store, disabled=False):
        self.store = store
        self.disabled = disabled
        self.setup_code = None
        self.fails = []
        self.lock = threading.Lock()
        self.nocheck_csrf = secrets.token_urlsafe(24)   # used when auth is disabled

    # --- state -------------------------------------------------------------------

    def needs_setup(self):
        return not self.disabled and not self.store.get("admin_password")

    def announce_setup(self):
        if self.needs_setup():
            self.setup_code = "%s-%s" % (secrets.token_hex(3).upper(),
                                         secrets.token_hex(3).upper())
            log.warning("FIRST-TIME SETUP: open NetMap and enter setup code %s to choose "
                        "the admin password", self.setup_code)

    def reset_password(self):
        with self.store.tx() as db:
            db.execute("DELETE FROM settings WHERE key='admin_password'")
            db.execute("DELETE FROM sessions")

    # --- actions -------------------------------------------------------------------

    def _throttle(self):
        now = time.time()
        with self.lock:
            self.fails = [t for t in self.fails if now - t < FAIL_WINDOW]
            if len(self.fails) >= FAIL_MAX and now - self.fails[-1] < LOCKOUT:
                raise AuthError("too many failed attempts; try again in %d seconds"
                                % (LOCKOUT - (now - self.fails[-1]) + 1))

    def _failed(self, who):
        with self.lock:
            self.fails.append(time.time())
            n = len(self.fails)
        log.warning("failed login from %s (%d in the last %d min)", who, n,
                    FAIL_WINDOW // 60)

    def setup(self, code, password, who):
        if not self.needs_setup():
            raise AuthError("already set up")
        self._throttle()
        if not self.setup_code or not hmac.compare_digest(
                (code or "").strip().upper(), self.setup_code):
            self._failed(who)
            raise AuthError("wrong setup code (it is in the NetMap log)")
        self._check_strength(password)
        self.store.set("admin_password", hash_password(password))
        self.setup_code = None
        log.info("admin password set from %s", who)
        return self._new_session()

    def login(self, password, who):
        self._throttle()
        stored = self.store.get("admin_password")
        if not stored or not verify_password(password or "", stored):
            self._failed(who)
            raise AuthError("wrong password")
        log.info("admin logged in from %s", who)
        return self._new_session()

    def change_password(self, session, current, new):
        if not verify_password(current or "", self.store.get("admin_password") or ""):
            raise AuthError("current password is wrong")
        self._check_strength(new)
        self.store.set("admin_password", hash_password(new))
        with self.store.tx() as db:          # log out every other session
            db.execute("DELETE FROM sessions WHERE token_hash<>?", (session["hash"],))
        log.info("admin password changed; other sessions logged out")

    def _check_strength(self, pw):
        if not pw or len(pw) < MIN_PASSWORD:
            raise AuthError("the password needs at least %d characters" % MIN_PASSWORD)

    def _new_session(self):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        now = time.time()
        with self.store.tx() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (now,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                       (_token_hash(token), csrf, now, now + SESSION_DAYS * 86400))
        return token, csrf

    def session(self, token):
        """Session dict for a cookie token, or None."""
        if self.disabled:
            return {"hash": "", "csrf": self.nocheck_csrf}
        if not token:
            return None
        h = _token_hash(token)
        r = self.store.q("SELECT csrf, expires FROM sessions WHERE token_hash=?", (h,))
        if not r or r[0][1] < time.time():
            return None
        return {"hash": h, "csrf": r[0][0]}

    def logout(self, session):
        if session and session["hash"]:
            with self.store.tx() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (session["hash"],))
