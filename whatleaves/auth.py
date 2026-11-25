"""One login, created on the first visit with a one-time setup code that is
printed to the log (docker logs whatleaves), or set in advance with WL_USER and
WL_PASSWORD. No default password. The code means a device elsewhere on the
network can't claim the page before its owner does. WL_AUTH=off turns the login
off for setups that already have their own sign-in.

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
GLOBAL_FAILURES = 30      # failed logins per minute, from everywhere, before all logins pause
MAX_TRACKED = 10_000      # addresses remembered for slowing down
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
        self.failures, self.recent, self.lock = {}, [], threading.Lock()
        if enabled and preset_user and preset_password:
            self.set_login(preset_user, preset_password)
        # Shown only in the log, so only someone who can read the log can create the login.
        self.setup_code = "-".join(f"{secrets.randbelow(10**4):04d}" for _ in range(2))

    def needs_setup(self):
        return self.enabled and not self.store.q("SELECT 1 FROM users LIMIT 1")

    def create_first(self, user, pw, code):
        """The first login. True if created; False if one already exists. One
        transaction, so two visitors racing each other can't both get in."""
        now = time.time()
        with self.lock:
            self.recent = [t for t in self.recent if now - t < 60]
            busy = len(self.recent) >= GLOBAL_FAILURES
        if busy:
            time.sleep(1)
            raise PermissionError("Too many tries. Wait a minute, then try again.")
        if not hmac.compare_digest(str(code).replace(" ", "").strip().encode(), self.setup_code.encode()):
            with self.lock:
                self.recent.append(now)
            time.sleep(0.5)
            raise PermissionError("That setup code is wrong. It's in the app's log: docker logs whatleaves")
        if len(pw) < 8:
            raise ValueError("Use at least 8 characters.")
        pwhash = hash_password(pw)
        with self.store.lock, self.store.db:
            cur = self.store.db.execute(
                "INSERT INTO users SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
                (user.strip() or "admin", pwhash))
            return cur.rowcount == 1

    def set_login(self, user, pw):
        if len(pw) < 8:
            raise ValueError("Use at least 8 characters.")
        pwhash = hash_password(pw)
        with self.store.lock, self.store.db:
            self.store.db.execute("DELETE FROM users")
            self.store.db.execute("INSERT INTO users VALUES (?, ?)", (user.strip() or "admin", pwhash))
            self.store.db.execute("DELETE FROM sessions")

    def username(self):
        row = self.store.q("SELECT username FROM users LIMIT 1")
        return row[0][0] if row else ""

    def login(self, user, pw, remote):
        """A new session token, or None. Slows down repeated failures per address,
        and pauses every login for a minute if failures pour in from everywhere
        (addresses can be faked or rotated; the total can't)."""
        now = time.time()
        with self.lock:
            self.recent = [t for t in self.recent if now - t < 60]
            fails, until = self.failures.get(remote, (0, 0))
            busy = len(self.recent) >= GLOBAL_FAILURES
        if busy or now < until:
            time.sleep(1)
            return None
        row = self.store.q("SELECT pwhash FROM users WHERE username=?", (user.strip(),))
        if not row or not check_password(pw, row[0][0]):
            with self.lock:
                fails += 1
                self.recent.append(now)
                if len(self.failures) >= MAX_TRACKED:
                    self.failures = {k: v for k, v in self.failures.items() if v[1] > now}
                    if len(self.failures) >= MAX_TRACKED:
                        self.failures.clear()
                self.failures[remote] = (fails, now + min(2 ** fails, 300) if fails >= 5 else 0)
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
