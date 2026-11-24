"""A small read-only web server: the page, and the JSON it draws from."""

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC = os.path.join(os.path.dirname(__file__), "static")


def make_handler(store, status):
    class Handler(BaseHTTPRequestHandler):
        server_version = "WhatLeavesHome"

        def log_message(self, *args):
            pass  # no access log: the page itself is about privacy

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if url.path == "/":
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path == "/app.js":
                with open(os.path.join(STATIC, "app.js"), "rb") as f:
                    return self._send(200, f.read(), "text/javascript; charset=utf-8")
            if url.path == "/api/status":
                return self._json(status)
            if url.path == "/api/devices":
                return self._json(store.devices())
            if url.path == "/api/device" and q.get("client"):
                return self._json(store.device(q["client"][0]))
            if url.path == "/healthz":
                return self._send(200, b"ok\n", "text/plain")
            self._json({"error": "not found"}, 404)

    return Handler


def serve(store, status, host, port):
    httpd = ThreadingHTTPServer((host, port), make_handler(store, status))
    httpd.daemon_threads = True
    return httpd
