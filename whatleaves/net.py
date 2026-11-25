"""Every network request What Leaves Home makes goes through fetch(), which
records it: when, where, why, how much, and whether it worked. The "This app"
page shows that record, so you can check the tool isn't doing what it shows
other devices doing. Nothing else in the code opens a connection.
"""

import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import __version__
from .store import is_private

# Some servers refuse Python's default identification; say plainly what we are.
USER_AGENT = f"WhatLeavesHome/{__version__} (self-hosted; no telemetry)"

_recorder = None


def set_recorder(fn):
    """fn(row) stores one record; the app wires this to the store at start."""
    global _recorder
    _recorder = fn


def _is_local(host):
    import socket
    try:
        return is_private(host) or host in ("localhost",) or all(
            is_private(info[4][0]) for info in socket.getaddrinfo(host, None))
    except OSError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are not followed. Following one would carry the AdGuard or Pi-hole
    login to another host, and would reach a place this record never names."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirected to {newurl}; use that address instead",
                                     headers, fp)


_opener = urllib.request.build_opener(_NoRedirect)


def fetch(url, purpose, headers=None, data=None, timeout=30):
    """GET (or POST with data) url; returns the body as bytes. Recorded either way."""
    host = urllib.parse.urlparse(url).hostname or ""
    row = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": host,
           "url": url.split("?")[0], "purpose": purpose, "method": "POST" if data else "GET",
           "local": _is_local(host), "bytes": 0, "status": ""}
    try:
        req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
        with _opener.open(req, timeout=timeout) as r:
            body = r.read()
            row.update(bytes=len(body), status=str(r.status))
            return body
    except urllib.error.HTTPError as e:
        row["status"] = str(e.code)
        raise
    except Exception as e:
        row["status"] = type(e).__name__
        raise
    finally:
        if _recorder:
            try:
                _recorder(row)
            except Exception:
                pass


def tcp_open(ip, port, timeout=0.6):
    """True if something accepts a TCP connection at ip:port. Not recorded one by
    one (a scan makes thousands); the scanner records one summary per scan."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def record(purpose, host, local, count=0, status="200"):
    """A summary record for work that isn't a single request, such as a scan."""
    if _recorder:
        _recorder({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": host, "url": "",
                   "purpose": purpose, "method": "SCAN", "local": local, "bytes": count, "status": status})
