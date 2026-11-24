import base64
import json
import os
import struct
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from whatleaves import dnswire
from whatleaves.server import serve
from whatleaves.sources import AdGuardSource, DemoSource, FilesSource
from whatleaves.store import Store, site, utc


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


class DnsWire(unittest.TestCase):
    def test_reads_a_and_cname(self):
        b64 = dns_response("cloud.vendor.com", ["203.0.113.5", "203.0.113.6"], cname="edge.cdn.net")
        self.assertEqual(dnswire.answers(b64), ["edge.cdn.net", "203.0.113.5", "203.0.113.6"])

    def test_garbage_gives_nothing(self):
        self.assertEqual(dnswire.answers("not base64!"), [])
        self.assertEqual(dnswire.answers(""), [])


class Helpers(unittest.TestCase):
    def test_site(self):
        self.assertEqual(site("cloud-mqtt-cluster-1.vesync.com"), "vesync.com")
        self.assertEqual(site("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(site("localhost"), "localhost")

    def test_utc_handles_nanoseconds_and_offsets(self):
        self.assertEqual(utc("2026-11-24T13:35:15.123456789-08:00"), "2026-11-24T21:35:15.123456Z")
        self.assertEqual(utc("2026-11-24T21:35:15Z"), "2026-11-24T21:35:15.000000Z")


class StoreSummaries(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.add_lookups([
            {"time": "2026-11-24T10:00:00Z", "client": "10.0.0.5", "name": "api.vendor.com",
             "answers": ["203.0.113.5"], "blocked": False},
            {"time": "2026-11-24T11:00:00Z", "client": "10.0.0.5", "name": "api.vendor.com",
             "answers": ["203.0.113.5"], "blocked": False},
            {"time": "2026-11-24T11:00:01Z", "client": "10.0.0.5", "name": "ads.tracker.net",
             "answers": ["0.0.0.0"], "blocked": True},
        ])
        # Two samples of one connection (running totals), plus one unexplained address.
        self.store.add_conns([
            {"time": "2026-11-24T11:00:00Z", "client": "10.0.0.5", "proto": "tcp", "dst": "203.0.113.5",
             "sport": 5000, "dport": 443, "out_bytes": 100, "in_bytes": 50},
            {"time": "2026-11-24T11:05:00Z", "client": "10.0.0.5", "proto": "tcp", "dst": "203.0.113.5",
             "sport": 5000, "dport": 443, "out_bytes": 300, "in_bytes": 80},
            {"time": "2026-11-24T11:05:00Z", "client": "10.0.0.5", "proto": "udp", "dst": "198.51.100.9",
             "sport": 6000, "dport": 9000, "out_bytes": 10, "in_bytes": 0},
        ])

    def test_device_list(self):
        [d] = self.store.devices()
        self.assertEqual((d["lookups"], d["blocked"], d["sites"], d["destinations"]), (3, 1, 2, 2))
        self.assertEqual((d["bytes_out"], d["bytes_in"]), (310, 80))  # max per connection, not the sum of samples

    def test_device_detail_matches_addresses_to_names(self):
        d = self.store.device("10.0.0.5")
        by_dst = {c["dst"]: c for c in d["connections"]}
        self.assertEqual(by_dst["203.0.113.5"]["names"], ["api.vendor.com"])
        self.assertEqual(by_dst["198.51.100.9"]["names"], [])
        self.assertEqual(len(d["flags"]), 2)

    def test_duplicates_are_ignored(self):
        self.store.add_lookups([{"time": "2026-11-24T10:00:00Z", "client": "10.0.0.5", "name": "api.vendor.com"}])
        self.assertEqual(self.store.devices()[0]["lookups"], 3)


class Files(unittest.TestCase):
    def test_reads_new_lines_once(self):
        with tempfile.TemporaryDirectory() as d:
            q = os.path.join(d, "2026-11-24.jsonl")
            with open(q, "w") as f:
                f.write(json.dumps({"T": "2026-11-24T13:35:15.1-08:00", "IP": "192.168.1.38",
                                    "QH": "cloud.vendor.com", "QT": "A", "Upstream": "192.168.1.2:53",
                                    "Answer": dns_response("cloud.vendor.com", ["203.0.113.7"])}) + "\n")
                f.write('{"T": "partial')  # a line still being written
            with open(os.path.join(d, "conn-2026-11-24.jsonl"), "w") as f:
                f.write(json.dumps({"t": "2026-11-24T22:00:00+00:00", "client": "192.168.1.38", "proto": "tcp",
                                    "dst": "203.0.113.7", "sport": 1, "dport": 8883, "out_bytes": 5,
                                    "in_bytes": 6}) + "\n")
            store, src = Store(":memory:"), FilesSource(d)
            self.assertEqual(src.poll(store), 2)
            self.assertEqual(src.poll(store), 0)
            with open(q, "a") as f:
                f.write('", "IP": "192.168.1.38", "QH": "time.vendor.com", "QT": "A"}\n')
            self.assertEqual(src.poll(store), 0)  # the completed line is malformed JSON overall; skipped
            detail = store.device("192.168.1.38")
            self.assertEqual(detail["connections"][0]["names"], ["cloud.vendor.com"])


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
        else:
            rows = [e for e in self.log if not q.get("older_than") or e["time"] < q["older_than"]][: int(q["limit"])]
            body = {"data": rows, "oldest": rows[-1]["time"] if rows else ""}
        out = json.dumps(body).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(out)


class AdGuard(unittest.TestCase):
    def test_pages_through_and_resumes(self):
        FakeAdGuard.log = [{"time": f"2026-11-24T10:{59 - i // 60:02d}:{59 - i % 60:02d}.000000001Z",
                            "client": "10.0.0.9", "question": {"name": f"n{i}.example.com", "type": "A"},
                            "answer": [{"value": "203.0.113.1"}], "reason": "NotFilteredNotFound"}
                           for i in range(1200)]
        srv = HTTPServer(("127.0.0.1", 0), FakeAdGuard)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            store = Store(":memory:")
            src = AdGuardSource(f"http://127.0.0.1:{srv.server_port}", "u", "p")
            self.assertEqual(src.poll(store), 1200)
            FakeAdGuard.log.insert(0, {"time": "2026-11-24T11:00:00Z", "client": "10.0.0.9",
                                       "question": {"name": "new.example.com", "type": "A"},
                                       "reason": "FilteredBlackList"})
            self.assertEqual(src.poll(store), 1)
            [d] = store.devices()
            self.assertEqual((d["name"], d["lookups"], d["blocked"]), ("TV", 1201, 1))
        finally:
            srv.shutdown()


class Web(unittest.TestCase):
    def test_demo_end_to_end(self):
        store = Store(":memory:")
        DemoSource().poll(store)
        status = {"source": "demo", "keep_days": 30}
        httpd = serve(store, status, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            page = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("What Leaves Home", page)
            devices = json.load(urllib.request.urlopen(base + "/api/devices"))
            self.assertEqual(len(devices), 4)
            cam = next(d for d in devices if d["name"] == "Doorbell camera")
            detail = json.load(urllib.request.urlopen(base + "/api/device?client=" + cam["client"]))
            self.assertTrue(any("without a matching lookup" in f for f in detail["flags"]))
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(base + "/nope")
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
