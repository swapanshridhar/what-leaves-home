import base64
import glob
import gzip
import ipaddress
import json
import os
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from whatleaves import analysis, dnswire, net
from whatleaves.auth import Auth, check_password, hash_password
from whatleaves.enrich import Owners, site
from whatleaves.server import App, serve
from whatleaves.sources import AdGuardSource, DemoSource, FilesSource
from whatleaves.store import Store, utc

PKG = os.path.join(os.path.dirname(__file__), "..", "whatleaves")


def dns_response(name, ips, cname=None):
    """A minimal DNS response: one question, an optional CNAME, then A records."""
    def qname(n):
        return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"
    answers = []
    if cname:
        answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(qname(cname))) + qname(cname))
    for ip in ips:
        answers.append(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split(".")))
    msg = struct.pack("!HHHHHH", 1, 0x8180, 1, len(answers), 0, 0) + qname(name) + struct.pack("!HH", 1, 1)
    return base64.b64encode(msg + b"".join(answers)).decode()


def demo_store():
    store = Store(":memory:")
    DemoSource().poll(store)
    owners = Owners("/nonexistent", enabled=False, extra_ranges=DemoSource.OWNER_RANGES)
    return store, owners


class Basics(unittest.TestCase):
    def test_dns_answers(self):
        b64 = dns_response("cloud.vendor.com", ["203.0.113.5", "203.0.113.6"], cname="edge.cdn.net")
        self.assertEqual(dnswire.answers(b64), ["edge.cdn.net", "203.0.113.5", "203.0.113.6"])
        self.assertEqual(dnswire.answers("not base64!"), [])

    def test_site_and_time(self):
        self.assertEqual(site("cloud-mqtt-cluster-1.vesync.com"), "vesync.com")
        self.assertEqual(site("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(utc("2026-11-24T13:35:15.123456789-08:00"), "2026-11-24T21:35:15.123456Z")

    def test_only_net_py_opens_connections(self):
        """The "This app" page is only honest if every request goes through net.fetch."""
        for path in glob.glob(os.path.join(PKG, "*.py")):
            if path.endswith("net.py"):
                continue
            src = open(path).read()
            for needle in ("urlopen", "urllib.request", "http.client", "socket.create_connection", "urlretrieve",
                           "socket.socket"):
                self.assertNotIn(needle, src, f"{os.path.basename(path)} uses {needle}; go through net.fetch")


class Analysis(unittest.TestCase):
    def test_demo_shows_every_verdict(self):
        store, owners = demo_store()
        o = analysis.overview(store, owners, DemoSource.SITE_NAMES)
        c = o["counts"]
        self.assertEqual((c["devices"], c["services"]), (7, 4))
        self.assertTrue(c["good"] and c["check"] and c["concern"])
        self.assertEqual(o["finding"]["device"], "Living room TV")
        by = {d["name"]: d for d in o["devices"]}
        self.assertEqual(by["Kitchen speaker"]["maker"], "Speaker Co.")  # a vendor's time server doesn't hide the vendor
        self.assertTrue(any("never looked up" in r["text"] for r in by["Doorbell camera"]["reasons"]))
        self.assertTrue(any("unencrypted" in r["text"] for r in by["Living room TV"]["reasons"]))
        # An address with no lookup is named for its host, and isn't also counted as another company.
        cam = analysis.device_view(store, owners, by["Doorbell camera"]["client"], DemoSource.SITE_NAMES)
        self.assertIn("Device relay on Unknown Hosting Ltd", [c["company"] for c in cam["companies"]])
        self.assertFalse(any("Device relay" in r["text"] for r in cam["reasons"] if "besides" in r["text"]))

    def test_actions_and_home_block_list(self):
        store, owners = demo_store()
        o = analysis.overview(store, owners, DemoSource.SITE_NAMES)
        tv = analysis.device_view(store, owners, "192.168.1.21", DemoSource.SITE_NAMES)
        titles = [a["title"] for a in tv["actions"]]
        self.assertIn("Check for a firmware update", titles)  # it used plain HTTP
        block = next(a for a in tv["actions"] if a["title"] == "Block its ad and tracking services")
        self.assertEqual(block["rules"], ["||viewing-data.example^"])  # the ad network was already blocked
        self.assertTrue(any("blocked every one" in r["text"] for r in tv["reasons"]))
        rules = {r["rule"] for r in o["block_rules"]}
        self.assertTrue({"||analytics-vendor.example^", "||viewing-data.example^"} <= rules)

    def test_running_totals_are_not_double_counted(self):
        store = Store(":memory:")
        for t, ob in (("2026-11-24T11:00:00Z", 100), ("2026-11-24T11:05:00Z", 300)):
            store.add_conns([{"time": t, "client": "10.0.0.5", "proto": "tcp", "dst": "203.0.113.5",
                              "sport": 5000, "dport": 443, "out_bytes": ob, "in_bytes": 0}])
        self.assertEqual(store.device("10.0.0.5")["connections"][0]["bytes_out"], 300)

    def test_owner_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            with gzip.open(os.path.join(d, "ip2asn-v4-u32.tsv.gz"), "wt") as f:
                f.write("872415232\t872546303\t16509\tUS\tAMAZON-02 - Amazon.com, Inc.\n")  # 52.0.0.0/15
            o = Owners(d)
            o._load()  # fresh file on disk, so no download
            self.assertEqual(o.lookup("52.1.2.3"), ("Amazon Web Services", "US"))
            self.assertEqual(o.lookup("8.8.8.8"), ("", ""))


class Sources(unittest.TestCase):
    def test_files_read_new_lines_once(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "2026-11-24.jsonl"), "w") as f:
                f.write(json.dumps({"T": "2026-11-24T13:35:15.1-08:00", "IP": "192.168.1.38", "QH": "cloud.vendor.com",
                                    "QT": "A", "Answer": dns_response("cloud.vendor.com", ["203.0.113.7"])}) + "\n")
                f.write('{"T": "partial')  # a line still being written
            with open(os.path.join(d, "conn-2026-11-24.jsonl"), "w") as f:
                f.write(json.dumps({"t": "2026-11-24T22:00:00+00:00", "client": "192.168.1.38", "proto": "tcp",
                                    "dst": "203.0.113.7", "sport": 1, "dport": 8883, "out_bytes": 5, "in_bytes": 6}) + "\n")
            store, src = Store(":memory:"), FilesSource(d)
            self.assertEqual(src.poll(store), 2)
            self.assertEqual(src.poll(store), 0)
            self.assertEqual(store.device("192.168.1.38")["connections"][0]["names"], ["cloud.vendor.com"])


class AdGuardLog(unittest.TestCase):
    def test_keeps_only_listed_clients_and_follows_rotation(self):
        from whatleaves.sources import AdGuardLogSource
        line = lambda ip, name, t: json.dumps({"T": t, "IP": ip, "QH": name, "QT": "A"}) + "\n"
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "querylog.json")
            with open(log, "w") as f:
                f.write(line("192.168.1.10", "api.server.example", "2026-11-24T10:00:00Z"))
                f.write(line("192.168.1.66", "someones-browsing.example", "2026-11-24T10:00:01Z"))
            store, src = Store(":memory:"), AdGuardLogSource(log, ["192.168.1.10"])
            self.assertEqual(src.poll(store), 1)
            self.assertEqual([d["client"] for d in store.devices()], ["192.168.1.10"])  # nobody else stored
            os.rename(log, log + ".1")  # AdGuard rotates
            with open(log, "w") as f:
                f.write(line("192.168.1.10", "update.server.example", "2026-11-24T11:00:00Z"))
            self.assertEqual(src.poll(store), 1)
            self.assertEqual(src.poll(store), 0)
        self.assertTrue(AdGuardLogSource("/nonexistent/querylog.json").waiting())


class FakeAdGuard(BaseHTTPRequestHandler):
    log = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(b"u:p").decode():
            self.send_response(401)
            self.end_headers()
            return
        url = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/control/clients":
            body = {"clients": [{"name": "TV", "ids": ["10.0.0.9"]}], "auto_clients": []}
        elif url.path == "/control/status":
            body = {"version": "v0.107.79"}
        else:
            rows = [e for e in self.log if not q.get("older_than") or e["time"] < q["older_than"]][: int(q["limit"])]
            body = {"data": rows, "oldest": rows[-1]["time"] if rows else ""}
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


class AdGuard(unittest.TestCase):
    def test_pages_resumes_and_records_its_own_calls(self):
        FakeAdGuard.log = [{"time": f"2026-11-24T10:{59 - i // 60:02d}:{59 - i % 60:02d}.000000001Z",
                            "client": "10.0.0.9", "question": {"name": f"n{i}.example.com", "type": "A"},
                            "answer": [{"value": "203.0.113.1"}], "reason": "NotFilteredNotFound"}
                           for i in range(1200)]
        srv = HTTPServer(("127.0.0.1", 0), FakeAdGuard)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        store = Store(":memory:")
        net.set_recorder(store.add_own_call)
        try:
            src = AdGuardSource(f"http://127.0.0.1:{srv.server_port}", "u", "p")
            self.assertEqual(src.poll(store), 1200)
            FakeAdGuard.log.insert(0, {"time": "2026-11-24T11:00:00Z", "client": "10.0.0.9",
                                       "question": {"name": "new.example.com", "type": "A"}, "reason": "FilteredBlackList"})
            self.assertEqual(src.poll(store), 1)
            [d] = store.devices()
            self.assertEqual(d["name"], "TV")
            summary = {r["purpose"]: r for r in store.own_call_summary()}
            self.assertIn("Read AdGuard Home's query log", summary)
            self.assertTrue(all(r["local"] for r in summary.values()))
        finally:
            net.set_recorder(None)
            srv.shutdown()


class Services(unittest.TestCase):
    def test_report_names_connections_from_the_servers_lookups(self):
        store = Store(":memory:")
        store.add_lookups([{"time": "2026-11-24T10:00:00Z", "client": "192.168.1.10", "name": "api.media.example",
                            "answers": ["203.0.113.9"]}])
        store.add_report({"host": "box", "host_ips": ["192.168.1.10"], "time": "2026-11-24T10:01:00Z",
                          "services": [{"name": "jellyfin", "image": "jellyfin/jellyfin", "ports": ["8096/tcp"]}],
                          "conns": [{"service": "jellyfin", "proto": "tcp", "dst": "203.0.113.9", "sport": 4000,
                                     "dport": 443, "out_bytes": 10, "in_bytes": 20}]})
        self.assertEqual([d["client"] for d in store.devices()], ["192.168.1.10"])  # services aren't devices
        v = analysis.device_view(store, None, "svc:box/jellyfin")
        self.assertEqual((v["kind"], v["service"]["host"]), ("media", "box"))
        self.assertEqual(v["connections"][0]["names"], ["api.media.example"])

    def test_scan_refuses_the_internet(self):
        from whatleaves import scan
        self.assertEqual(len(scan.targets("192.168.1.0/30")), 2)
        for bad in ("8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/8"):
            with self.assertRaises(ValueError):
                scan.targets(bad)


class Router(unittest.TestCase):
    def test_spots_a_router_answering_for_everyone(self):
        from datetime import datetime, timezone
        store = Store(":memory:")
        now = datetime.now(timezone.utc)
        store.add_lookups([{"time": now.replace(microsecond=i).isoformat(), "client": "192.168.1.1" if i % 10 else "192.168.1.40",
                            "name": f"n{i}.example.com"} for i in range(300)])
        r = analysis.router_client(store)
        self.assertEqual((r["client"], r["share"]), ("192.168.1.1", 0.9))
        v = analysis.device_view(store, None, "192.168.1.1", router=r)
        self.assertEqual((v["kind"], v["name"]), ("router", "Everything behind your router"))
        self.assertIsNone(analysis.router_client(Store(":memory:")))


class FirstDevice(unittest.TestCase):
    def test_new_clients_are_the_ones_seen_since(self):
        store = Store(":memory:")
        store.add_lookups([{"time": "2026-11-24T10:00:00Z", "client": "192.168.1.5", "name": "old.example"},
                           {"time": "2026-11-24T12:00:00Z", "client": "192.168.1.9", "name": "a.example"},
                           {"time": "2026-11-24T12:01:00Z", "client": "192.168.1.9", "name": "b.example"}])
        found = store.new_clients("2026-11-24T11:00:00Z")
        self.assertEqual([(c["client"], c["lookups"]) for c in found], [("192.168.1.9", 2)])


class Connect(unittest.TestCase):
    def test_spots_a_router_answering_for_everyone(self):
        from whatleaves.sources import test_adguard
        FakeAdGuard.log = [{"time": f"2026-11-24T10:00:{i % 60:02d}Z", "client": "192.168.1.1" if i % 10 else "192.168.1.9",
                            "question": {"name": "x.example", "type": "A"}} for i in range(200)]
        srv = HTTPServer(("127.0.0.1", 0), FakeAdGuard)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}"
            ok = test_adguard(url, "u", "p")
            self.assertTrue(ok["ok"] and ok["router_suspect"])
            self.assertEqual(ok["top_client"], "192.168.1.1")
            bad = test_adguard(url, "u", "wrong")
            self.assertFalse(bad["ok"])
            self.assertIn("refused", bad["message"])
        finally:
            srv.shutdown()


class FakePihole(BaseHTTPRequestHandler):
    queries = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ok = body.get("password") == "app-pw"
        self._send(200 if ok else 401, {"session": {"valid": ok, "sid": "sid123" if ok else None}})

    def do_GET(self):
        if self.headers.get("X-FTL-SID") != "sid123":
            return self._send(401, {"error": {"key": "unauthorized"}})
        url = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/api/info/version":
            return self._send(200, {"version": {"core": {"local": {"version": "v6.3"}}}})
        rows = [e for e in self.queries if float(q["from"]) <= e["time"] <= float(q["until"])]
        start, length = int(q.get("start", 0)), int(q["length"])
        self._send(200, {"queries": rows[start:start + length]})


class Pihole(unittest.TestCase):
    def test_reads_queries_names_and_blocks(self):
        from whatleaves.sources import PiholeSource, test_pihole
        import time
        now = time.time()
        FakePihole.queries = [{"time": now - 60 + i * 0.01, "type": "A", "domain": f"n{i}.example.com",
                               "status": "GRAVITY" if i % 5 == 0 else "FORWARDED",
                               "client": {"ip": "192.168.1.40", "name": "living-room-tv"}} for i in range(1500)]
        srv = HTTPServer(("127.0.0.1", 0), FakePihole)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}"
            store = Store(":memory:")
            src = PiholeSource(url, "app-pw")
            self.assertEqual(src.poll(store), 1500)  # two pages
            self.assertEqual(src.poll(store), 0)
            [d] = store.devices()
            self.assertEqual(d["name"], "living-room-tv")
            self.assertEqual(sum(l["blocked"] for l in store.device("192.168.1.40")["lookups"]), 300)
            self.assertTrue(test_pihole(url, "app-pw")["ok"])
            self.assertFalse(test_pihole(url, "wrong")["ok"])
        finally:
            srv.shutdown()


class Login(unittest.TestCase):
    def test_hashing(self):
        h = hash_password("correct horse")
        self.assertTrue(check_password("correct horse", h))
        self.assertFalse(check_password("wrong", h))

    def test_first_visit_sets_the_login(self):
        auth = Auth(Store(":memory:"))
        self.assertTrue(auth.needs_setup())
        with self.assertRaises(ValueError):
            auth.set_login("admin", "short")
        auth.set_login("admin", "long enough")
        self.assertFalse(auth.needs_setup())
        self.assertIsNone(auth.login("admin", "nope", "1.2.3.4"))
        token = auth.login("admin", "long enough", "1.2.3.4")
        self.assertTrue(auth.check(token))
        auth.logout(token)
        self.assertFalse(auth.check(token))

    def test_preset_and_off(self):
        self.assertFalse(Auth(Store(":memory:"), preset_user="me", preset_password="preset pw").needs_setup())
        self.assertTrue(Auth(Store(":memory:"), enabled=False).check(""))


class Web(unittest.TestCase):
    def setUp(self):
        self.store, owners = demo_store()
        self.status = {"version": "t", "source": "demo", "keep_days": 30, "poll_seconds": 300, "auth": True}
        self.app = App(self.store, self.status, Auth(self.store), owners, DemoSource.SITE_NAMES, "agent-token")
        self.httpd = serve(self.app, "127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.cookie = ""

    def tearDown(self):
        self.httpd.shutdown()

    def call(self, path, body=None, ctype="application/json"):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": ctype, "Cookie": self.cookie})
        try:
            with urllib.request.urlopen(req) as r:
                if r.headers.get("Set-Cookie"):
                    self.cookie = r.headers["Set-Cookie"].split(";")[0]
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_agent_reports_need_the_token(self):
        rep = {"host": "nas", "host_ips": ["192.168.1.5"], "time": "2026-11-24T10:00:00Z",
               "services": [{"name": "backup"}], "conns": []}
        req = lambda tok: urllib.request.Request(self.base + "/api/ingest", data=json.dumps(rep).encode(),
                                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"})
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req("wrong"))
        self.assertEqual(e.exception.code, 401)
        self.assertEqual(json.load(urllib.request.urlopen(req("agent-token")))["ok"], True)
        self.assertIn("svc:nas/backup", [s["id"] for s in self.store.services()])

    def test_saving_a_connection_replaces_the_demo(self):
        from whatleaves.sources import SourceHolder
        FakeAdGuard.log = [{"time": "2026-11-24T10:00:00Z", "client": "192.168.1.30", "question": {"name": "a.example", "type": "A"}}]
        srv = HTTPServer(("127.0.0.1", 0), FakeAdGuard)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.call("/api/setup", {"user": "admin", "password": "a good password", "code": self.app.auth.setup_code})
            self.status["configurable"] = True
            self.app.holder = SourceHolder(DemoSource())
            code, r = self.call("/api/connect/save", {"url": f"127.0.0.1:{srv.server_port}", "user": "u", "password": "p"})
            self.assertEqual((code, r["ok"], r.get("saved")), (200, True, True))
            self.assertEqual(self.app.holder.kind, "adguard")
            self.assertEqual(self.store.devices(), [])  # the demo's devices are gone
            self.app.holder.poll(self.store)
            self.assertEqual([d["client"] for d in self.store.devices()], ["192.168.1.30"])
            self.status["configurable"] = False
            self.assertEqual(self.call("/api/connect/test", {"url": "x"})[0], 409)  # .env decides
        finally:
            srv.shutdown()

    def test_signed_out_sees_nothing(self):
        self.assertEqual(self.call("/api/session")[1]["auth"], "setup")
        self.assertEqual(self.call("/api/overview")[0], 401)
        self.assertEqual(self.call("/api/device?client=192.168.1.21")[0], 401)

    def test_setup_then_use(self):
        code = self.app.auth.setup_code
        self.assertEqual(self.call("/api/setup", {"user": "admin", "password": "a good password", "code": "0000-0000"})[0], 403)
        self.assertEqual(self.call("/api/setup", {"user": "admin", "password": "a good password", "code": code})[0], 200)
        self.assertEqual(self.call("/api/setup", {"user": "x", "password": "another password", "code": code})[0], 409)
        status, o = self.call("/api/overview")
        self.assertEqual((status, o["counts"]["total"]), (200, 11))
        status, d = self.call("/api/device?client=192.168.1.21")
        self.assertEqual(d["grade"], "F")
        self.assertEqual(self.call("/api/name", {"client": "192.168.1.21", "name": "Den TV"})[0], 200)
        self.assertEqual(self.call("/api/device?client=192.168.1.21")[1]["name"], "Den TV")
        self.assertEqual(self.call("/api/name", {"client": "x"}, ctype="text/plain")[0], 400)  # no cross-site form posts
        self.assertEqual(self.call("/api/app")[0], 200)
        page = urllib.request.urlopen(self.base + "/").read().decode()
        self.assertIn("What Leaves Home", page)
        self.call("/api/logout", {})
        self.assertEqual(self.call("/api/session")[1]["auth"], "login")

    def test_racing_setups_make_one_login(self):
        code, results = self.app.auth.setup_code, []
        def claim(i):
            results.append(self.app.auth.create_first(f"user{i}", "a good password", code))
        threads = [threading.Thread(target=claim, args=(i,)) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(results.count(True), 1)
        self.assertEqual(len(self.store.q("SELECT * FROM users")), 1)

    def raw(self, request_bytes, timeout=5):
        import socket
        with socket.create_connection(("127.0.0.1", self.httpd.server_address[1]), timeout=timeout) as s:
            s.sendall(request_bytes)
            return s.recv(200).decode(errors="replace")

    def test_bad_lengths_and_hosts_are_refused(self):
        body = b'{"user":"a","password":"b"}'
        neg = self.raw(b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                       b"Content-Length: -1\r\n\r\n" + body)
        self.assertIn(" 400 ", neg.splitlines()[0])
        rebind = self.raw(b"GET /api/session HTTP/1.1\r\nHost: rebind.attacker.example\r\n\r\n")
        self.assertIn(" 421 ", rebind.splitlines()[0])
        for ok in ("raspberrypi:8080", "nas.local", "192.168.1.5:8080", "[::1]:8080", "localhost"):
            self.assertIn(" 200 ", self.raw(f"GET /healthz HTTP/1.1\r\nHost: {ok}\r\n\r\n".encode()).splitlines()[0], ok)
        self.app.allowed_hosts = ("whatleaves.example.org",)
        self.assertIn(" 200 ", self.raw(b"GET /healthz HTTP/1.1\r\nHost: whatleaves.example.org\r\n\r\n").splitlines()[0])

    def test_posts_from_other_sites_are_refused(self):
        req = urllib.request.Request(self.base + "/api/login", data=b"{}", headers={
            "Content-Type": "application/json", "Origin": "https://evil.example"})
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        self.assertEqual(e.exception.code, 403)

    def test_forwarded_for_is_ignored_unless_trusted(self):
        from whatleaves.server import make_handler
        Handler = make_handler(self.app)
        h = Handler.__new__(Handler)
        h.client_address, h.headers = ("192.168.1.9", 1), {"X-Forwarded-For": "10.9.9.9"}
        self.assertEqual(h._remote(), "192.168.1.9")
        self.app.trusted_proxies = [ipaddress.ip_network("192.168.1.9/32")]
        self.assertEqual(h._remote(), "10.9.9.9")

    def test_token_rotates(self):
        self.call("/api/setup", {"user": "admin", "password": "a good password", "code": self.app.auth.setup_code})
        code, r = self.call("/api/agent/rotate", {})
        self.assertEqual(code, 200)
        self.assertNotEqual(r["token"], "agent-token")
        self.assertEqual(self.store.get_meta("ingest_token"), r["token"])


class Agent(unittest.TestCase):
    def test_installer_checksum_matches_the_agent(self):
        import hashlib, re
        from whatleaves import REPO, __version__
        static = os.path.join(os.path.dirname(__file__), "..", "whatleaves", "static")
        agent = hashlib.sha256(open(os.path.join(static, "whatleaves-agent.py"), "rb").read()).hexdigest()
        sh = open(os.path.join(static, "install-agent.sh")).read()
        self.assertEqual(re.search(r"AGENT_SHA256=(\w+)", sh).group(1), agent,
                         "the agent changed: put its new sha256sum in install-agent.sh")
        self.assertIn(f"AGENT_VERSION={__version__}\n", sh)
        self.assertIn(f"githubusercontent.com/{REPO}/", sh)


class Limits(unittest.TestCase):
    def test_store_refuses_junk_rows(self):
        store = Store(":memory:")
        good = {"time": "2026-11-24T10:00:00Z", "client": "192.168.1.5", "proto": "tcp", "dst": "203.0.113.9",
                "sport": 5000, "dport": 443}
        bad = [dict(good, client="x" * 100_000), dict(good, dst="not-an-ip"), dict(good, proto="icmp"),
               dict(good, dport=70000)]
        self.assertEqual(store.add_conns([good] + bad), 1)

    def test_block_rules_are_plain_domains(self):
        from whatleaves.analysis import RULE_SAFE
        self.assertTrue(RULE_SAFE.match("acr.viewing-data.example"))
        for bad in ("x.example^$important", "a.example,b", "nodot", "ex ample.com"):
            self.assertFalse(RULE_SAFE.match(bad), bad)

    def test_scans_stay_in_home_ranges(self):
        from whatleaves import scan
        self.assertEqual(len(scan.targets("192.168.1.0/30")), 2)
        for bad in ("100.64.0.0/24", "127.0.0.0/30", "224.0.0.0/30", "8.8.8.0/30"):
            with self.assertRaises(ValueError):
                scan.targets(bad)

    def test_redirects_are_not_followed(self):
        from whatleaves import net

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://localhost:9/elsewhere")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as e:
                net.fetch(f"http://127.0.0.1:{srv.server_port}/", "test", headers={"Authorization": "Basic x"})
            self.assertIn("redirected", str(e.exception))
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
