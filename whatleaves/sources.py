"""Where the data comes from. Each source has poll(store), called on a timer.

- AdGuardSource: any AdGuard Home, through its web API (the usual setup).
- FilesSource:   a folder of JSON-lines files, as written by a collector that
                 copies AdGuard's query log file and a router's connection
                 table (see docs/collector.md).
- DemoSource:    made-up devices, so a fresh install shows something at once.
"""

import base64
import json
import os
import random
import urllib.parse
from datetime import datetime, timedelta, timezone

from . import dnswire
from .net import fetch


class AdGuardSource:
    kind = "adguard"
    PAGE = 500

    def __init__(self, url, user="", password="", clients=None):
        self.url = url.rstrip("/")
        self.headers = {"Accept": "application/json"}
        if user:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.clients = set(clients or [])

    def _get(self, path, params=None, purpose="Read AdGuard Home's query log"):
        q = f"?{urllib.parse.urlencode(params)}" if params else ""
        return json.loads(fetch(f"{self.url}{path}{q}", purpose, headers=self.headers))

    def _names(self):
        """Client names AdGuard already knows: ones you set, then ones it found."""
        names = {}
        data = self._get("/control/clients", purpose="Read device names from AdGuard Home")
        for c in data.get("auto_clients") or []:
            if c.get("name") and c.get("ip"):
                names[c["ip"]] = c["name"]
        for c in data.get("clients") or []:
            for ident in c.get("ids") or []:
                names[ident] = c.get("name", "")
        return names

    def poll(self, store):
        since = store.get_meta("adguard_last")
        rows, older, newest = [], "", since
        while True:
            params = {"limit": self.PAGE, **({"older_than": older} if older else {})}
            page = self._get("/control/querylog", params)
            data = page.get("data") or []
            stop = False
            for e in data:
                if since and e["time"] <= since:
                    stop = True
                    break
                newest = max(newest or e["time"], e["time"])
                if self.clients and e.get("client") not in self.clients:
                    continue
                q = e.get("question") or {}
                rows.append({"time": e["time"], "client": e.get("client", ""), "name": q.get("name", ""),
                             "qtype": q.get("type", ""), "upstream": e.get("upstream", ""),
                             "answers": [a.get("value", "") for a in e.get("answer") or []],
                             "blocked": str(e.get("reason", "")).startswith("Filtered")})
            older = page.get("oldest") or ""
            if stop or not data or not older:
                break
        added = store.add_lookups(rows)
        if newest:
            store.set_meta("adguard_last", newest)
        try:
            store.set_names(self._names(), overwrite=False)
        except Exception:
            pass  # names are a nicety; the lookups matter
        return added


class FilesSource:
    """Reads *.jsonl (AdGuard query-log lines: T, IP, QH, QT, Answer, Upstream,
    Result) and conn-*.jsonl (t, client, proto, dst, sport, dport, out_bytes,
    in_bytes) from a folder, remembering how far it got in each file."""
    kind = "files"

    def __init__(self, folder):
        self.folder = folder

    def poll(self, store):
        offsets = json.loads(store.get_meta("file_offsets", "{}"))
        lookups, conns = [], []
        for f in sorted(os.listdir(self.folder)):
            if not f.endswith(".jsonl"):
                continue
            path = os.path.join(self.folder, f)
            start = offsets.get(f, 0)
            if os.path.getsize(path) < start:
                start = 0  # the file was replaced
            with open(path, "rb") as fh:
                fh.seek(start)
                chunk = fh.read()
            end = start + chunk.rfind(b"\n") + 1  # only whole lines
            for line in chunk[:end - start].splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if f.startswith("conn-"):
                    conns.append({"time": e["t"], **{k: e[k] for k in
                                  ("client", "proto", "dst", "sport", "dport", "out_bytes", "in_bytes")}})
                elif "QH" in e:
                    result = e.get("Result") or {}
                    lookups.append({"time": e["T"], "client": e.get("IP", ""), "name": e["QH"],
                                    "qtype": e.get("QT", ""), "upstream": e.get("Upstream", ""),
                                    "answers": dnswire.answers(e.get("Answer")),
                                    "blocked": bool(result.get("IsFiltered"))})
            offsets[f] = end
        offsets = {f: o for f, o in offsets.items() if os.path.exists(os.path.join(self.folder, f))}
        added = store.add_lookups(lookups) + store.add_conns(conns)
        store.set_meta("file_offsets", json.dumps(offsets))
        return added


class DemoSource:
    """A day of made-up traffic from five imaginary devices, chosen to show
    every verdict. Names use the reserved .example domain and addresses come
    from the documentation ranges, so nothing here is a real company."""
    kind = "demo"
    SITE_NAMES = {
        "tv-maker.example": "TV Maker Co.", "adnetwork.example": "AdNetwork (ads)",
        "viewing-data.example": "ViewingData (what you watch)", "streaming.example": "Streaming Co.",
        "camera-cloud.example": "Camera Co.", "camera-relay.example": "RelayNet",
        "speaker-cloud.example": "Speaker Co.", "plug-cloud.example": "Plug Co.",
        "vacuum-cloud.example": "Vacuum Co.", "metrics-vendor.example": "MetricsVendor",
        "media-metadata.example": "MediaMetadata", "weather-data.example": "WeatherData",
        "media-index.example": "MediaIndex", "analytics-vendor.example": "AnalyticsVendor (tracking)",
    }
    OWNER_RANGES = [("203.0.113.0/26", "Example Cloud Hosting", "US"),
                    ("203.0.113.64/26", "Example CDN", "DE"),
                    ("198.51.100.0/24", "Unknown Hosting Ltd", "CN")]
    # client: (name, [(host, lookups per day, address, port, MB sent per day, blocked)])
    DEVICES = {
        "192.168.1.21": ("Living room TV", [
            ("api.tv-maker.example", 120, "203.0.113.10", 443, 4, False),
            ("firmware.tv-maker.example", 6, "203.0.113.12", 80, 1, False),
            ("ads.adnetwork.example", 300, "203.0.113.20", 443, 0, True),
            ("acr.viewing-data.example", 400, "203.0.113.30", 443, 0, True),
            ("cdn.streaming.example", 60, "203.0.113.70", 443, 2, False)]),
        "192.168.1.34": ("Kitchen speaker", [
            ("voice.speaker-cloud.example", 90, "203.0.113.40", 443, 6, False),
            ("time.speaker-cloud.example", 24, "203.0.113.41", 443, 0.01, False),
            ("music.streaming.example", 40, "203.0.113.71", 443, 0.5, False)]),
        "192.168.1.47": ("Doorbell camera", [
            ("upload.camera-cloud.example", 72, "203.0.113.50", 443, 40, False),
            ("p2p.camera-relay.example", 144, "198.51.100.20", 9000, 12, False)]),
        "192.168.1.58": ("Smart plug", [
            ("mqtt.plug-cloud.example", 24, "203.0.113.60", 8883, 0.2, False)]),
        "192.168.1.63": ("Robot vacuum", [
            ("api.vacuum-cloud.example", 48, "203.0.113.55", 443, 3, False),
            ("maps.vacuum-cloud.example", 4, "203.0.113.56", 443, 220, False),
            ("collect.metrics-vendor.example", 96, "203.0.113.80", 443, 1, False)]),
    }

    def poll(self, store):
        if store.get_meta("demo_loaded"):
            return 0
        rnd = random.Random(7)
        now = datetime.now(timezone.utc)
        lookups, conns = [], []
        for client, (_name, dests) in self.DEVICES.items():
            for host, per_day, addr, port, mb, blocked in dests:
                for _ in range(per_day):
                    t = now - timedelta(seconds=rnd.uniform(0, 86400))
                    lookups.append({"time": t.isoformat(), "client": client, "name": host, "qtype": "A",
                                    "answers": ["0.0.0.0"] if blocked else [addr], "upstream": "demo",
                                    "blocked": blocked})
                if blocked:
                    continue
                # One long connection, sampled every 20 minutes for a day.
                sport, total, sent = rnd.randint(40000, 60000), mb * 1e6, 0
                for k in range(1, 73):
                    t = now - timedelta(minutes=20 * (72 - k))
                    busy = 1.4 if 7 <= t.hour <= 23 else 0.3  # quieter at night
                    sent += int(total / 72 * busy * rnd.uniform(0.5, 1.5))  # a running total, as conntrack reports
                    conns.append({"time": t.isoformat(), "client": client, "proto": "tcp", "dst": addr,
                                  "sport": sport, "dport": port, "out_bytes": sent, "in_bytes": sent // 3})
        # A fixed-address connection with no lookup at all, to show that finding.
        for k in range(1, 73):
            t = now - timedelta(minutes=20 * (72 - k))
            conns.append({"time": t.isoformat(), "client": "192.168.1.47", "proto": "udp", "dst": "198.51.100.9",
                          "sport": 51515, "dport": 10001, "out_bytes": 9000 * k, "in_bytes": 400 * k})
        store.add_lookups(lookups)
        store.add_conns(conns)
        store.set_names({c: n for c, (n, _d) in self.DEVICES.items()}, overwrite=False)
        added = len(lookups) + len(conns) + self._services(store, rnd, now)
        store.set_meta("demo_loaded", "1")
        return added

    # A home server running services, reported by an agent, and what a scan found listening.
    SERVER = ("homeserver", "192.168.1.10")
    SERVICES = {
        "jellyfin": ("jellyfin/jellyfin:10.10", ["8096/tcp"], [("api.media-metadata.example", "203.0.113.90", 443, 40)]),
        "homeassistant": ("ghcr.io/home-assistant/home-assistant:2026.11", ["8123/tcp"], [
            ("cloud.speaker-cloud.example", "203.0.113.40", 443, 2), ("api.weather-data.example", "203.0.113.91", 443, 1)]),
        "sonarr": ("linuxserver/sonarr:4", ["8989/tcp"], [("indexer.media-index.example", "198.51.100.40", 443, 15)]),
        "photo-backup": ("example/photo-backup:1.2", ["2342/tcp"], [
            ("telemetry.analytics-vendor.example", "203.0.113.95", 443, 0.5),
            ("ads.adnetwork.example", "203.0.113.20", 443, 0)]),
    }

    def _services(self, store, rnd, now):
        host, ip = self.SERVER
        lookups, conns = [], []
        for name, (_image, _ports, dests) in self.SERVICES.items():
            for dhost, addr, port, mb in dests:
                blocked = dhost.startswith("ads.")
                for _ in range(rnd.randint(6, 30)):
                    t = now - timedelta(seconds=rnd.uniform(0, 86400))
                    lookups.append({"time": t.isoformat(), "client": ip, "name": dhost, "qtype": "A",
                                    "answers": ["0.0.0.0"] if blocked else [addr], "blocked": blocked})
                if blocked:
                    continue
                sport, sent = rnd.randint(40000, 60000), 0
                for k in range(1, 73):
                    t = now - timedelta(minutes=20 * (72 - k))
                    sent += int(mb * 1e6 / 72 * rnd.uniform(0.5, 1.5))
                    conns.append({"time": t.isoformat(), "service": name, "proto": "tcp", "dst": addr,
                                  "sport": sport, "dport": port, "out_bytes": sent, "in_bytes": sent * 4})
        store.add_lookups(lookups)
        store.set_names({ip: "Home server (all its services)"}, overwrite=False)
        store.add_report({"host": host, "host_ips": [ip], "time": now.isoformat(),
                          "services": [{"name": n, "image": i, "ports": p, "network": "bridge"}
                                       for n, (i, p, _d) in self.SERVICES.items()], "conns": conns})
        # A second machine with no agent yet, so "Set up services" has something to suggest.
        nas = "192.168.1.12"
        store.set_names({nas: "NAS"}, overwrite=False)
        store.add_lookups([{"time": (now - timedelta(minutes=m)).isoformat(), "client": nas, "name": n,
                            "answers": ["203.0.113.99"]} for m, n in enumerate(
                               ["registry-1.docker.io", "ghcr.io", "api.github.com", "api.themoviedb.org"] * 6)])
        when = now.isoformat(timespec="seconds")
        store.set_scan([(nas, 445, "File sharing (SMB)", ""), (nas, 8080, "Web app", "NAS admin"),
                        (nas, 32400, "Plex", "Plex"), (ip, 8096, "Jellyfin", "Jellyfin"), (ip, 8123, "Home Assistant", "Home Assistant"),
                        (ip, 8989, "Sonarr", "Sonarr"), (ip, 22, "SSH", ""),
                        ("192.168.1.21", 8008, "Google Cast", ""), ("192.168.1.47", 554, "Video stream (RTSP)", ""),
                        ("192.168.1.47", 80, "Web page", "Camera login")], when)
        return len(lookups) + len(conns)
