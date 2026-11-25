"""The local SQLite store: what was seen, the app's own network calls, and the login."""

import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .enrich import site

SCHEMA = """
CREATE TABLE IF NOT EXISTS lookups (
    time TEXT, client TEXT, name TEXT, qtype TEXT,
    answers TEXT, upstream TEXT, blocked INTEGER,
    PRIMARY KEY (time, client, name, qtype));
CREATE TABLE IF NOT EXISTS conns (
    time TEXT, client TEXT, proto TEXT, dst TEXT, sport INTEGER, dport INTEGER,
    out_bytes INTEGER, in_bytes INTEGER,
    PRIMARY KEY (time, client, proto, dst, sport, dport));
CREATE TABLE IF NOT EXISTS names (client TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS own_calls (
    time TEXT, host TEXT, url TEXT, purpose TEXT, method TEXT, local INTEGER, bytes INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY, host TEXT, name TEXT, image TEXT, ports TEXT, network TEXT, host_ips TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS scan (
    ip TEXT, port INTEGER, guess TEXT, title TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY (ip, port));
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, pwhash TEXT);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT, expires TEXT);
CREATE INDEX IF NOT EXISTS lookups_client ON lookups (client, time);
CREATE INDEX IF NOT EXISTS conns_client ON conns (client, time);
CREATE INDEX IF NOT EXISTS own_calls_time ON own_calls (time);
"""

_FRACTION = re.compile(r"\.(\d+)")
ISO = "%Y-%m-%dT%H:%M:%S.%fZ"

LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def utc(ts):
    """Any RFC 3339 time (nanoseconds, Z or an offset) -> UTC ISO with microseconds."""
    ts = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), ts.strip(), count=1)
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO)


def is_private(addr):
    """On the home network (or loopback, link-local, multicast, CGNAT/Tailscale).
    Not ipaddress.is_private, which also counts documentation ranges."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in LOCAL_NETS)


def service_id(host, name):
    return f"svc:{host}/{name}"


MAX_CLIENT = 220            # an address, or svc:<host>/<service>
MAX_SERVICES = 500          # per agent report
MAX_REPORT_CONNS = 20_000   # per agent report


def _short(value, limit):
    """A string field from outside, refused (not cut) when too long, so junk can't pile up."""
    value = str(value)
    if len(value) > limit:
        raise ValueError("field too long")
    return value


def _proto(value):
    value = str(value).lower()
    if value not in ("tcp", "udp"):
        raise ValueError("protocol")
    return value


def _port(value):
    value = int(value)
    if not 0 <= value <= 65535:
        raise ValueError("port")
    return value


class Store:
    def __init__(self, path):
        self._home_names, self._home_names_at = {}, 0.0
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)

    def q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        with self.lock, self.db:
            return self.db.execute(sql, args).rowcount

    # ----- writing

    @staticmethod
    def _valid(rows, make):
        """Rows turned into tuples by make(); rows with a bad time or field are skipped."""
        out = []
        for r in rows:
            try:
                out.append(make(r))
            except (KeyError, ValueError, TypeError, AttributeError):
                pass
        return out

    def add_lookups(self, rows):
        """rows: dicts with time, client, name, qtype, answers (list), upstream, blocked."""
        values = self._valid(rows, lambda r: (
            utc(r["time"]), _short(r["client"], MAX_CLIENT), _short(r["name"].rstrip(".").lower(), 253),
            _short(r.get("qtype", ""), 16), json.dumps([str(a)[:64] for a in (r.get("answers") or [])][:32]),
            _short(r.get("upstream", ""), 128), int(bool(r.get("blocked")))))
        with self.lock, self.db:
            return self.db.executemany("INSERT OR IGNORE INTO lookups VALUES (?,?,?,?,?,?,?)", values).rowcount

    def add_conns(self, rows):
        """rows: dicts with time, client, proto, dst, sport, dport, out_bytes, in_bytes
        (byte counts so far for that connection, as a connection table reports them)."""
        values = self._valid(rows, lambda r: (
            utc(r["time"]), _short(r["client"], MAX_CLIENT), _proto(r["proto"]), str(ipaddress.ip_address(r["dst"])),
            _port(r["sport"]), _port(r["dport"]), max(0, int(r.get("out_bytes", 0))), max(0, int(r.get("in_bytes", 0)))))
        with self.lock, self.db:
            return self.db.executemany("INSERT OR IGNORE INTO conns VALUES (?,?,?,?,?,?,?,?)", values).rowcount

    def add_own_call(self, row):
        self.x("INSERT INTO own_calls VALUES (?,?,?,?,?,?,?,?)",
               (row["time"], row["host"], row["url"], row["purpose"], row["method"],
                int(row["local"]), row["bytes"], row["status"]))

    def add_report(self, rep):
        """One agent report: its services, and their connections as clients svc:<host>/<service>."""
        host, when = str(rep["host"])[:80], utc(rep["time"])
        ips = json.dumps([str(i)[:45] for i in rep.get("host_ips") or []][:32])
        services = [s for s in (rep.get("services") or [])[:MAX_SERVICES] if isinstance(s, dict) and s.get("name")]
        rows = [(service_id(host, str(s["name"])[:120]), host, str(s["name"])[:120], str(s.get("image", ""))[:200],
                 json.dumps([str(p)[:20] for p in s.get("ports") or []][:50]), str(s.get("network", ""))[:40], ips, when)
                for s in services]
        with self.lock, self.db:
            self.db.executemany("INSERT OR REPLACE INTO services VALUES (?,?,?,?,?,?,?,?)", rows)
        conns = (rep.get("conns") or [])[:MAX_REPORT_CONNS]
        return self.add_conns([{"time": rep["time"], **c, "client": service_id(host, str(c["service"])[:120])}
                               for c in conns if isinstance(c, dict) and c.get("service")])

    def clear_data(self):
        """Forget everything seen (used when switching from the demo to a real source).
        Keeps the login, the ingest token and the app's own call record."""
        with self.lock, self.db:
            for t in ("lookups", "conns", "names", "services", "scan"):
                self.db.execute(f"DELETE FROM {t}")
            self.db.execute("""DELETE FROM meta WHERE key IN
                ('demo_loaded', 'adguard_last', 'file_offsets', 'adguard_log_inodes')""")

    def new_clients(self, since):
        """Clients whose first lookup kept is after `since`: devices that just started
        asking this AdGuard (the wizard watches for the user's first device)."""
        names = dict(self.q("SELECT client, name FROM names"))
        rows = self.q("""SELECT client, MIN(time), COUNT(*) FROM lookups GROUP BY client
                         HAVING MIN(time) >= ? ORDER BY MIN(time) DESC LIMIT 10""", (utc(since),))
        return [{"client": c, "name": names.get(c, ""), "first": f, "lookups": n} for c, f, n in rows]

    def services(self):
        cols = ("id", "host", "name", "image", "ports", "network", "host_ips", "last_seen")
        out = [dict(zip(cols, r)) for r in self.q(f"SELECT {', '.join(cols)} FROM services ORDER BY host, name")]
        for s in out:
            s["ports"], s["host_ips"] = json.loads(s["ports"] or "[]"), json.loads(s["host_ips"] or "[]")
        return out

    def set_scan(self, found, when):
        """found: [(ip, port, guess, title)] from one scan."""
        with self.lock, self.db:
            for ip, port, guess, title in found:
                self.db.execute("""INSERT INTO scan VALUES (?,?,?,?,?,?) ON CONFLICT (ip, port) DO UPDATE
                                   SET guess=excluded.guess, title=excluded.title, last_seen=excluded.last_seen""",
                                (ip, port, guess, title, when, when))

    def scan_results(self):
        cols = ("ip", "port", "guess", "title", "first_seen", "last_seen")
        return [dict(zip(cols, r)) for r in self.q(f"SELECT {', '.join(cols)} FROM scan ORDER BY ip, port")]

    def set_names(self, names, overwrite=True):
        verb = "INSERT OR REPLACE" if overwrite else "INSERT OR IGNORE"
        with self.lock, self.db:
            self.db.executemany(f"{verb} INTO names VALUES (?,?)", list(names.items()))

    def get_meta(self, key, default=""):
        row = self.q("SELECT value FROM meta WHERE key=?", (key,))
        return row[0][0] if row else default

    def set_meta(self, key, value):
        self.x("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))

    def prune(self, keep_days):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime(ISO)
        with self.lock, self.db:
            self.db.execute("DELETE FROM lookups WHERE time < ?", (cutoff,))
            self.db.execute("DELETE FROM conns WHERE time < ?", (cutoff,))
            self.db.execute("DELETE FROM own_calls WHERE time < ?", (cutoff,))
            self.db.execute("DELETE FROM sessions WHERE expires < ?", (datetime.now(timezone.utc).strftime(ISO),))

    # ----- reading

    def _conn_totals(self, client=None):
        """Per connection (client, proto, dst, dport, sport): the largest byte
        counts seen, since samples of one connection are running totals."""
        where, args = ("WHERE client=?", (client,)) if client else ("", ())
        return self.q(f"""
            SELECT client, proto, dst, dport, MAX(out_bytes), MAX(in_bytes), MIN(time), MAX(time)
            FROM conns {where} GROUP BY client, proto, dst, dport, sport""", args)

    def devices(self):
        """Every client seen, with its name."""
        names = dict(self.q("SELECT client, name FROM names"))
        clients = {c for (c,) in self.q("SELECT DISTINCT client FROM lookups")}
        clients |= {c for (c,) in self.q("SELECT DISTINCT client FROM conns") if not c.startswith("svc:")}
        return sorted(({"client": c, "name": names.get(c, "")} for c in clients),
                      key=lambda d: (d["name"].lower() or "~", d["client"]))

    def home_names(self, max_age=60):
        """Address -> names, from every lookup anyone in the home made (cached for a minute).
        Names a connection whose own device's lookup is older than the data kept, or went
        through another resolver."""
        import time as _t
        if _t.time() - self._home_names_at > max_age:
            idx = {}
            for qname, answers in self.q("SELECT name, answers FROM lookups WHERE answers != '[]' GROUP BY name, answers"):
                try:
                    for a in json.loads(answers):
                        if a[:1].isdigit() or ":" in a:
                            idx.setdefault(a, set()).add(qname)
                except ValueError:
                    pass
            self._home_names, self._home_names_at = idx, _t.time()
        return self._home_names

    def device(self, client):
        """Raw material for one device: lookups by name, connections by destination."""
        name = (self.q("SELECT name FROM names WHERE client=?", (client,)) or [("",)])[0][0]
        lookup_clients, svc = [client], None
        if client.startswith("svc:"):
            # A service's own lookups reach DNS from its server's address, mixed with its neighbours',
            # so they only name its connections; they aren't listed as its lookups.
            svc = next((s for s in self.services() if s["id"] == client), None)
            lookup_clients = svc["host_ips"] if svc else []
            name = name or (svc["name"] if svc else client)
        marks = ",".join("?" * len(lookup_clients)) or "''"
        rows = self.q(f"""SELECT name, COUNT(*), SUM(blocked), MIN(time), MAX(time), GROUP_CONCAT(answers, '|')
                          FROM lookups WHERE client IN ({marks}) GROUP BY name""", tuple(lookup_clients))
        lookups, by_addr, first, last = [], {}, None, None
        for qname, n, blocked, f, l, answers_concat in rows:
            addrs = set()
            for chunk in (answers_concat or "").split("|"):
                try:
                    addrs.update(a for a in json.loads(chunk) if a[:1].isdigit() or ":" in a)
                except ValueError:
                    pass
            for a in addrs:
                by_addr.setdefault(a, set()).add(qname)
            lookups.append({"name": qname, "site": site(qname), "count": n, "blocked": blocked or 0,
                            "first": f, "last": l, "addresses": sorted(addrs)[:8]})
            first, last = min(first or f, f), max(last or l, l)
        conns = {}
        # Home devices reached over IPv6 use the ISP's public prefix, so "private" isn't enough:
        # anything in the same /64 as the server is at home too.
        home64 = {ipaddress.ip_network(f"{h}/64", strict=False) for h in (svc["host_ips"] if svc else [])
                  if ":" in h and not h.startswith("fe80")}
        local = lambda a: is_private(a) or (":" in a and any(ipaddress.ip_address(a) in n for n in home64))
        for _c, proto, dst, dport, ob, ib, f, l in self._conn_totals(client):
            c = conns.setdefault((proto, dst, dport), {
                "proto": proto, "dst": dst, "dport": dport, "connections": 0, "bytes_out": 0, "bytes_in": 0,
                "first": f, "last": l, "local": local(dst), "names": sorted(by_addr.get(dst, ()))})
            c["connections"] += 1
            c["bytes_out"] += ob
            c["bytes_in"] += ib
            c["first"], c["last"] = min(c["first"], f), max(c["last"], l)
            first, last = min(first or f, f), max(last or l, l)
        home = None
        for c in conns.values():
            if not c["names"] and not c["local"]:
                home = home if home is not None else self.home_names()
                if c["dst"] in home:
                    c["names"], c["named_by_home"] = sorted(home[c["dst"]])[:5], True
        if svc:
            # Keep only the host's lookups that explain this service's connections.
            used = {n for c in conns.values() for n in c["names"]}
            lookups = [l for l in lookups if l["name"] in used]
            first = min((c["first"] for c in conns.values()), default=None)
            last = max((c["last"] for c in conns.values()), default=None)
        return {"client": client, "name": name, "first": first, "last": last, "service": svc,
                "lookups": sorted(lookups, key=lambda x: -x["count"]),
                "connections": sorted(conns.values(), key=lambda c: -(c["bytes_out"] + c["bytes_in"]))}

    def hourly(self, client, hours=24):
        """Lookups and bytes sent per hour for the last `hours` hours, oldest first."""
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        slots = [{"hour": (start + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z"), "lookups": 0, "bytes_out": 0}
                 for i in range(hours)]
        index = {s["hour"][:13]: s for s in slots}
        for (h, n) in self.q("""SELECT substr(time, 1, 13), COUNT(*) FROM lookups
                                WHERE client=? AND time >= ? GROUP BY 1""", (client, start.strftime(ISO))):
            if h in index:
                index[h]["lookups"] = n
        prev = {}
        for t, proto, dst, sport, dport, ob in self.q(
                """SELECT time, proto, dst, sport, dport, out_bytes FROM conns
                   WHERE client=? AND time >= ? ORDER BY time""",
                (client, (start - timedelta(hours=1)).strftime(ISO))):
            key = (proto, dst, sport, dport)
            delta = ob - prev.get(key, ob)  # a connection's first sample sets its baseline
            prev[key] = ob
            if t[:13] in index and delta > 0:
                index[t[:13]]["bytes_out"] += delta
        return slots

    def own_calls(self, limit=500):
        cols = ("time", "host", "url", "purpose", "method", "local", "bytes", "status")
        return [dict(zip(cols, r)) for r in self.q(
            "SELECT time, host, url, purpose, method, local, bytes, status FROM own_calls ORDER BY time DESC LIMIT ?",
            (limit,))]

    def own_call_summary(self):
        cols = ("host", "purpose", "local", "calls", "bytes", "last", "failures")
        return [dict(zip(cols, r)) for r in self.q(
            """SELECT host, purpose, local, COUNT(*), SUM(bytes), MAX(time),
                      SUM(CASE WHEN status LIKE '2%' THEN 0 ELSE 1 END)
               FROM own_calls GROUP BY host, purpose ORDER BY local, MAX(time) DESC""")]
