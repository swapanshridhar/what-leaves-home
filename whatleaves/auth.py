"""One login, set by whoever opens the page first (like Home Assistant or
Uptime Kuma), or in advance with WL_USER and WL_PASSWORD. No default password.
WL_AUTH=off turns it off for setups that already have their own sign-in.

Passwords are stored as PBKDF2-SHA256 hashes; sessions as hashes of a random
token in an HttpOnly, SameSite=Strict cookie, valid 30 days.
"""

import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from .store import ISO

ITERATIONS = 310_000
SESSION_DAYS = 30
COOKIE = "wl_session"


def hash_password(pw, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def check_password(pw, stored):
    try:
        _algo, iterations, salt, digest = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt, int(iterations)).split("$")[3], digest)


class Auth:
    def __init__(self, store, enabled=True, preset_user="", preset_password=""):
        self.store, self.enabled = store, enabled
        self.failures, self.lock = {}, threading.Lock()
        if enabled and preset_user and preset_password:
            self.set_login(preset_user, preset_password)

    def needs_setup(self):
        return self.enabled and not self.store.q("SELECT 1 FROM users LIMIT 1")

    def set_login(self, user, pw):
        if len(pw) < 8:
            raise ValueError("Use at least 8 characters.")
        self.store.x("DELETE FROM users")
        self.store.x("INSERT INTO users VALUES (?, ?)", (user.strip() or "admin", hash_password(pw)))
        self.store.x("DELETE FROM sessions")

    def username(self):
        row = self.store.q("SELECT username FROM users LIMIT 1")
        return row[0][0] if row else ""

    def login(self, user, pw, remote):
        """A new session token, or None. Slows down repeated failures per address."""
        with self.lock:
            fails, until = self.failures.get(remote, (0, 0))
        if time.time() < until:
            time.sleep(1)
            return None
        row = self.store.q("SELECT pwhash FROM users WHERE username=?", (user.strip(),))
        if not row or not check_password(pw, row[0][0]):
            with self.lock:
                fails += 1
                self.failures[remote] = (fails, time.time() + min(2 ** fails, 300) if fails >= 5 else 0)
            time.sleep(0.5)
            return None
        with self.lock:
            self.failures.pop(remote, None)
        return self.new_session(user.strip())

    def new_session(self, user):
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).strftime(ISO)
        self.store.x("INSERT INTO sessions VALUES (?,?,?)", (self._h(token), user, expires))
        return token

    def check(self, token):
        if not self.enabled:
            return True
        if not token:
            return False
        row = self.store.q("SELECT expires FROM sessions WHERE token_hash=?", (self._h(token),))
        return bool(row) and row[0][0] > datetime.now(timezone.utc).strftime(ISO)

    def logout(self, token):
        if token:
            self.store.x("DELETE FROM sessions WHERE token_hash=?", (self._h(token),))

    @staticmethod
    def _h(token):
        return hashlib.sha256(token.encode()).hexdigest()
