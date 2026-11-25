"""The web server: the page, its JSON API, and the login around both."""

import hmac
import http.cookies
import ipaddress
import json
import os
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import analysis
from .auth import COOKIE, SESSION_DAYS
from .sources import AdGuardSource, PiholeSource, test_adguard, test_pihole

STATIC = os.path.join(os.path.dirname(__file__), "static")
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/app.css": ("app.css", "text/css; charset=utf-8"),
         "/logo.svg": ("logo.svg", "image/svg+xml"),
         # Public, so a server can fetch them with only the agent token: they're code, not data.
         "/whatleaves-agent.py": ("whatleaves-agent.py", "text/x-python; charset=utf-8"),
         "/install-agent.sh": ("install-agent.sh", "text/x-shellscript; charset=utf-8")}
OPEN_API = {"/api/session", "/api/setup", "/api/login"}
MAX_BODY = 65536
MAX_INGEST = 8 * 1024 * 1024  # one agent report
MAX_CONNECTIONS = 64          # requests handled at once; more wait for the OS backlog
TIMEOUT = 20                  # seconds a client may take to send its request
# Names a home network uses for its own machines. A web page elsewhere can point
# its own domain at this machine (DNS rebinding), but it can't use these.
HOME_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost")


def host_allowed(host_header, extra=()):
    """Is the Host header one this app should answer to? IP addresses, localhost,
    single-label names (raspberrypi), home suffixes, and WL_ALLOWED_HOSTS."""
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else ""
    elif h.count(":") == 1:
        h = h.split(":")[0]
    h = h.rstrip(".")
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if h == "localhost" or "." not in h or h.endswith(HOME_SUFFIXES):
        return True
    return any(h == a or (a.startswith(".") and h.endswith(a)) for a in extra)


class App:
    """Everything a request handler needs."""

    def __init__(self, store, status, auth, owners=None, site_names=None, ingest_token="",
                 allowed_hosts=(), trusted_proxies=(), token_fixed=False):
        self.store, self.status, self.auth, self.owners, self.site_names = store, status, auth, owners, site_names
        self.ingest_token, self.token_fixed = ingest_token, token_fixed
        self.allowed_hosts = tuple(h.strip().lower() for h in allowed_hosts if h.strip())
        self.trusted_proxies = [ipaddress.ip_network(p.strip(), strict=False) for p in trusted_proxies if p.strip()]
        self.holder, self.wake = None, None  # set by __main__: the running source, and a poke to poll now


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "WhatLeavesHome"
        timeout = TIMEOUT  # a client that stops sending mid-request is dropped

        def log_message(self, *args):
            pass  # no access log: the page itself is about privacy

        # ----- plumbing

        def _send(self, code, body, ctype, cookie=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'none'")
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200, cookie=None):
            self._send(code, json.dumps(obj).encode(), "application/json", cookie)

        def _token(self):
            c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c[COOKIE].value if COOKIE in c else ""

        def _cookie(self, token, max_age=SESSION_DAYS * 86400):
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "") == "https" else ""
            return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

        def _body(self, limit=MAX_BODY):
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("JSON only")  # also stops cross-site form posts
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > limit:
                raise ValueError("bad length")
            return json.loads(self.rfile.read(n) or b"{}")

        def _remote(self):
            """The client's address. X-Forwarded-For only counts when it comes from a
            proxy listed in WL_TRUSTED_PROXIES; anyone else could write anything there."""
            peer = self.client_address[0]
            try:
                trusted = any(ipaddress.ip_address(peer) in n for n in app.trusted_proxies)
            except ValueError:
                trusted = False
            if trusted:
                hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
                if hops:
                    return hops[-1]  # the one the trusted proxy added
            return peer

        def _refuse_host(self):
            """True (and answered) if this request's Host isn't one we serve."""
            if host_allowed(self.headers.get("Host", ""), app.allowed_hosts):
                return False
            msg = ("What Leaves Home doesn't answer to this address. If you opened it by a name "
                   "of your own, add that name to WL_ALLOWED_HOSTS.\n")
            self._send(421, msg.encode(), "text/plain; charset=utf-8")
            return True

        def _cross_origin(self):
            """A POST whose Origin isn't this page. Browsers send Origin on POSTs."""
            origin = self.headers.get("Origin")
            if not origin:
                return False
            mine = {self.headers.get(h, "").lower() for h in ("Host", "X-Forwarded-Host")} - {""}
            return urllib.parse.urlparse(origin).netloc.lower() not in mine

        # ----- GET

        def do_GET(self):
            if self._refuse_host():
                return
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if url.path in FILES:
                name, ctype = FILES[url.path]
                with open(os.path.join(STATIC, name), "rb") as f:
                    return self._send(200, f.read(), ctype)
            if url.path == "/healthz":
                return self._send(200, b"ok\n", "text/plain")
            if not url.path.startswith("/api/"):
                return self._json({"error": "not found"}, 404)
            if url.path == "/api/session":
                if not app.auth.enabled:
                    return self._json({"auth": "off"})
                if app.auth.needs_setup():
                    return self._json({"auth": "setup"})
                ok = app.auth.check(self._token())
                return self._json({"auth": "ok" if ok else "login", "user": app.auth.username() if ok else ""})
            if not app.auth.check(self._token()):
                return self._json({"error": "sign in first"}, 401)
            s, o, n = app.store, app.owners, app.site_names
            if url.path == "/api/overview":
                return self._json(analysis.overview(s, o, n))
            if url.path == "/api/device" and q.get("client"):
                return self._json(analysis.device_view(s, o, q["client"][0], n, router=analysis.router_client(s)))
            if url.path == "/api/agent":
                return self._json({"token": app.ingest_token, "token_fixed": app.token_fixed,
                                   "agents": agent_summary(s), "suggestions": analysis.suggest_hosts(s)})
            if url.path == "/api/app":
                return self._json({"status": app.status, "summary": s.own_call_summary(), "calls": s.own_calls(200),
                                   "owners": {"enabled": bool(o and o.enabled), "ready": bool(o and o.ready),
                                              "error": o.error if o else None}})
            if url.path == "/api/status":
                return self._json({**app.status, "wizard_done": s.get_meta("wizard_done") == "1"})
            if url.path == "/api/new-clients" and q.get("since"):
                try:
                    found = s.new_clients(q["since"][0])
                except ValueError:
                    return self._json({"error": "since must be a time"}, 400)
                router = analysis.router_client(s)
                return self._json([c for c in found if not router or c["client"] != router["client"]])
            return self._json({"error": "not found"}, 404)

        # ----- POST

        def do_POST(self):
            if self._refuse_host():
                return
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/ingest":
                return self._ingest()
            if self._cross_origin():
                return self._json({"error": "this request came from another site"}, 403)
            try:
                body = self._body()
            except ValueError:
                return self._json({"error": "send JSON"}, 400)
            if path == "/api/setup":
                if not app.auth.needs_setup():
                    return self._json({"error": "already set up"}, 409)
                try:
                    created = app.auth.create_first(str(body.get("user", "")), str(body.get("password", "")),
                                                    str(body.get("code", "")))
                except PermissionError as e:
                    return self._json({"error": str(e)}, 403)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                if not created:
                    return self._json({"error": "already set up"}, 409)
                return self._json({"ok": True}, cookie=self._cookie(app.auth.new_session(app.auth.username())))
            if path == "/api/login":
                token = app.auth.login(body.get("user", ""), body.get("password", ""), self._remote())
                if not token:
                    return self._json({"error": "That username and password don't match."}, 401)
                return self._json({"ok": True}, cookie=self._cookie(token))
            if not app.auth.check(self._token()):
                return self._json({"error": "sign in first"}, 401)
            if path == "/api/logout":
                app.auth.logout(self._token())
                return self._json({"ok": True}, cookie=self._cookie("", 0))
            if path == "/api/password":
                if not app.auth.login(app.auth.username(), body.get("current", ""), self._remote()):
                    return self._json({"error": "The current password is wrong."}, 403)
                try:
                    app.auth.set_login(app.auth.username(), body.get("password", ""))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"ok": True}, cookie=self._cookie(app.auth.new_session(app.auth.username())))
            if path == "/api/agent/rotate":
                if app.token_fixed:
                    return self._json({"error": "The token is set by WL_INGEST_TOKEN, so change it there."}, 409)
                app.ingest_token = secrets.token_urlsafe(32)
                app.store.set_meta("ingest_token", app.ingest_token)
                return self._json({"ok": True, "token": app.ingest_token})
            if path in ("/api/connect/test", "/api/connect/save"):
                return self._connect(body, save=path.endswith("save"))
            if path == "/api/wizard":
                app.store.set_meta("wizard_done", "1" if body.get("done") else "")
                return self._json({"ok": True})
            if path == "/api/name":
                client, name = str(body.get("client", "")), str(body.get("name", "")).strip()[:80]
                if not client:
                    return self._json({"error": "which device?"}, 400)
                app.store.set_names({client: name})
                return self._json({"ok": True})
            return self._json({"error": "not found"}, 404)

        def _connect(self, body, save):
            """Test (and optionally save) an AdGuard Home connection from the setup page."""
            if not app.status.get("configurable"):
                return self._json({"ok": False, "message": "The source is set by environment settings (.env), "
                                   "so it can't be changed here."}, 409)
            url = str(body.get("url", "")).strip().rstrip("/")
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            user, password = str(body.get("user", "")), str(body.get("password", ""))
            pihole = body.get("type") == "pihole"
            result = test_pihole(url, password) if pihole else test_adguard(url, user, password)
            if save and result["ok"] and app.holder:
                app.store.set_meta("adguard_config", json.dumps({"type": "pihole" if pihole else "adguard",
                                                                 "url": url, "user": user, "password": password}))
                if app.holder.kind.startswith("demo"):
                    app.store.clear_data()  # the demo's made-up devices go
                    app.site_names = None
                    if app.owners:
                        app.owners.extra = []
                app.holder.source = PiholeSource(url, password) if pihole else AdGuardSource(url, user, password)
                app.status.update(source=app.holder.kind, adguard_url=url, last_error=None)
                if app.wake:
                    app.wake.set()
                result["saved"] = True
            return self._json(result)

        def _ingest(self):
            """An agent's report. Its own token, not a login: agents are scripts."""
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not app.ingest_token or not hmac.compare_digest(given.encode(), app.ingest_token.encode()):
                return self._json({"error": "bad token"}, 401)
            try:
                rep = self._body(MAX_INGEST)
                if not isinstance(rep.get("host"), str) or not isinstance(rep.get("conns", []), list):
                    raise ValueError("not a report")
                added = app.store.add_report(rep)
            except (ValueError, KeyError, TypeError) as e:
                return self._json({"error": f"bad report: {e}"}, 400)
            return self._json({"ok": True, "added": added})

    return Handler


def agent_summary(store):
    hosts = {}
    for s in store.services():
        h = hosts.setdefault(s["host"], {"host": s["host"], "services": 0, "last_seen": s["last_seen"]})
        h["services"] += 1
        h["last_seen"] = max(h["last_seen"], s["last_seen"])
    return sorted(hosts.values(), key=lambda h: h["host"])


class BoundedServer(ThreadingHTTPServer):
    """At most MAX_CONNECTIONS requests at once, so a flood can't start unlimited threads."""
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(timeout=TIMEOUT):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def serve(app, host, port):
    return BoundedServer((host, port), make_handler(app))
