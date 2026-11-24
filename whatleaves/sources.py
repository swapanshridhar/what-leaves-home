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
import urllib.request
from datetime import datetime, timedelta, timezone

from . import dnswire


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

    def _get(self, path, params=None):
        q = f"?{urllib.parse.urlencode(params)}" if params else ""
        req = urllib.request.Request(f"{self.url}{path}{q}", headers=self.headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def _names(self):
        """Client names AdGuard already knows: ones you set, then ones it found."""
        names = {}
        data = self._get("/control/clients")
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
    """Three days of made-up traffic from four imaginary devices. Names and
    addresses are reserved for examples (.example, 203.0.113.0/24)."""
    kind = "demo"
    DEVICES = {
        "192.168.1.21": ("Living room TV", [
            ("api.tv-maker.example", 120, "203.0.113.10", 443),
            ("ads.adnetwork.example", 300, "203.0.113.20", 443),
            ("metrics.tv-maker.example", 200, "203.0.113.11", 443),
            ("acr.viewing-data.example", 400, "203.0.113.30", 443),
            ("cdn.streaming.example", 60, "203.0.113.40", 443)]),
        "192.168.1.34": ("Kitchen speaker", [
            ("voice.speaker-cloud.example", 90, "203.0.113.50", 443),
            ("time.speaker-cloud.example", 24, "203.0.113.51", 123),
            ("telemetry.speaker-cloud.example", 48, "203.0.113.52", 443)]),
        "192.168.1.47": ("Doorbell camera", [
            ("p2p.camera-relay.example", 144, "203.0.113.60", 9000),
            ("upload.camera-cloud.example", 72, "203.0.113.61", 443)]),
        "192.168.1.58": ("Smart plug", [
            ("mqtt.plug-cloud.example", 24, "203.0.113.70", 8883)]),
    }

    def poll(self, store):
        if store.get_meta("demo_loaded"):
            return 0
        rnd = random.Random(7)
        now = datetime.now(timezone.utc)
        lookups, conns = [], []
        for client, (_name, dests) in self.DEVICES.items():
            for host, per_day, addr, port in dests:
                for i in range(per_day * 3):
                    t = now - timedelta(seconds=rnd.uniform(0, 3 * 86400))
                    lookups.append({"time": t.isoformat(), "client": client, "name": host, "qtype": "A",
                                    "answers": [addr], "upstream": "demo",
                                    "blocked": host.startswith(("ads.", "acr."))})
                if not host.startswith(("ads.", "acr.")):
                    sport = rnd.randint(40000, 60000)
                    total_out = rnd.randint(20_000, 4_000_000)
                    for k in range(12):
                        t = now - timedelta(minutes=5 * (12 - k))
                        conns.append({"time": t.isoformat(), "client": client, "proto": "tcp", "dst": addr,
                                      "sport": sport, "dport": port, "out_bytes": total_out * (k + 1) // 12,
                                      "in_bytes": total_out * (k + 1) // 30})
        # One fixed-address connection with no lookup, to show that flag.
        conns.append({"time": now.isoformat(), "client": "192.168.1.47", "proto": "udp", "dst": "198.51.100.9",
                      "sport": 51515, "dport": 10001, "out_bytes": 880_000, "in_bytes": 12_000})
        store.add_lookups(lookups)
        store.add_conns(conns)
        store.set_names({c: n for c, (n, _d) in self.DEVICES.items()}, overwrite=False)
        store.set_meta("demo_loaded", "1")
        return len(lookups) + len(conns)
