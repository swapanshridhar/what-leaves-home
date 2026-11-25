import base64
import glob
import gzip
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
        self.assertIn("Unknown service on Unknown Hosting Ltd", [c["company"] for c in cam["companies"]])
        self.assertFalse(any("Unknown service" in r["text"] for r in cam["reasons"] if "besides" in r["text"]))

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
        with self.assertRaises(ValueError):
            AdGuardLogSource("/x", [])


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
            self.call("/api/setup", {"user": "admin", "password": "a good password"})
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
        self.assertEqual(self.call("/api/setup", {"user": "admin", "password": "a good password"})[0], 200)
        self.assertEqual(self.call("/api/setup", {"user": "x", "password": "another password"})[0], 409)
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


if __name__ == "__main__":
    unittest.main()
