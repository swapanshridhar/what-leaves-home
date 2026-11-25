"""The web server: the page, its JSON API, and the login around both."""

import http.cookies
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import analysis
from .auth import COOKIE, SESSION_DAYS

STATIC = os.path.join(os.path.dirname(__file__), "static")
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/app.css": ("app.css", "text/css; charset=utf-8"),
         "/logo.svg": ("logo.svg", "image/svg+xml")}
OPEN_API = {"/api/session", "/api/setup", "/api/login"}


class App:
    """Everything a request handler needs."""

    def __init__(self, store, status, auth, owners=None, site_names=None):
        self.store, self.status, self.auth, self.owners, self.site_names = store, status, auth, owners, site_names


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "WhatLeavesHome"

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

        def _body(self):
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ValueError("JSON only")  # also stops cross-site form posts
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(min(n, 65536)) or b"{}")

        def _remote(self):
            return self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]

        # ----- GET

        def do_GET(self):
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
                return self._json(analysis.device_view(s, o, q["client"][0], n))
            if url.path == "/api/app":
                return self._json({"status": app.status, "summary": s.own_call_summary(), "calls": s.own_calls(200),
                                   "owners": {"enabled": bool(o and o.enabled), "ready": bool(o and o.ready),
                                              "error": o.error if o else None}})
            if url.path == "/api/status":
                return self._json(app.status)
            return self._json({"error": "not found"}, 404)

        # ----- POST

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            try:
                body = self._body()
            except ValueError:
                return self._json({"error": "send JSON"}, 400)
            if path == "/api/setup":
                if not app.auth.needs_setup():
                    return self._json({"error": "already set up"}, 409)
                try:
                    app.auth.set_login(body.get("user", ""), body.get("password", ""))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
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
            if path == "/api/name":
                client, name = str(body.get("client", "")), str(body.get("name", "")).strip()[:80]
                if not client:
                    return self._json({"error": "which device?"}, 400)
                app.store.set_names({client: name})
                return self._json({"ok": True})
            return self._json({"error": "not found"}, 404)

    return Handler


def serve(app, host, port):
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    return httpd
