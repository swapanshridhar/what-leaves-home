"""The local SQLite store and the summaries the web page shows."""

import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

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
CREATE INDEX IF NOT EXISTS lookups_client ON lookups (client, time);
CREATE INDEX IF NOT EXISTS conns_client ON conns (client, time);
"""

# Two-label public suffixes common enough to matter for grouping by site.
TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "co.kr", "com.br", "com.cn", "com.tw", "com.hk",
    "co.in", "net.in", "com.mx", "com.sg", "co.za", "com.tr",
}

_FRACTION = re.compile(r"\.(\d+)")


def utc(ts):
    """Any RFC 3339 time (nanoseconds, Z or an offset) -> UTC ISO with microseconds."""
    ts = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), ts.strip(), count=1)
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def site(name):
    """The registrable part of a name, roughly: cloud.vendor.com -> vendor.com."""
    labels = name.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-n:])


LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def is_private(addr):
    """On the home network (or loopback, link-local, multicast, CGNAT/Tailscale).
    Not ipaddress.is_private, which also counts documentation ranges."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in LOCAL_NETS)


class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)

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
            utc(r["time"]), r["client"], r["name"].rstrip(".").lower(), r.get("qtype", ""),
            json.dumps(r.get("answers") or []), r.get("upstream", ""), int(bool(r.get("blocked")))))
        with self.lock, self.db:
            return self.db.executemany("INSERT OR IGNORE INTO lookups VALUES (?,?,?,?,?,?,?)", values).rowcount

    def add_conns(self, rows):
        """rows: dicts with time, client, proto, dst, sport, dport, out_bytes, in_bytes
        (byte counts so far for that connection, as a connection table reports them)."""
        values = self._valid(rows, lambda r: (
            utc(r["time"]), r["client"], r["proto"], r["dst"], int(r["sport"]), int(r["dport"]),
            int(r.get("out_bytes", 0)), int(r.get("in_bytes", 0))))
        with self.lock, self.db:
            return self.db.executemany("INSERT OR IGNORE INTO conns VALUES (?,?,?,?,?,?,?,?)", values).rowcount

    def set_names(self, names, overwrite=True):
        verb = "INSERT OR REPLACE" if overwrite else "INSERT OR IGNORE"
        with self.lock, self.db:
            self.db.executemany(f"{verb} INTO names VALUES (?,?)", list(names.items()))

    def get_meta(self, key, default=""):
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))

    def prune(self, keep_days):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self.lock, self.db:
            self.db.execute("DELETE FROM lookups WHERE time < ?", (cutoff,))
            self.db.execute("DELETE FROM conns WHERE time < ?", (cutoff,))

    # ----- reading

    def _q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def _conn_totals(self, client=None):
        """Per connection (client, proto, dst, dport, sport): the largest byte
        counts seen, since samples of one connection are running totals."""
        where, args = ("WHERE client=?", (client,)) if client else ("", ())
        return self._q(f"""
            SELECT client, proto, dst, dport, MAX(out_bytes), MAX(in_bytes), MIN(time), MAX(time)
            FROM conns {where} GROUP BY client, proto, dst, dport, sport""", args)

    def devices(self):
        names = dict(self._q("SELECT client, name FROM names"))
        out = {}

        def dev(client, first, last):
            d = out.setdefault(client, {"client": client, "name": names.get(client, ""), "lookups": 0,
                                        "blocked": 0, "sites": set(), "destinations": set(),
                                        "bytes_out": 0, "bytes_in": 0, "first": first, "last": last})
            d["first"], d["last"] = min(d["first"], first), max(d["last"], last)
            return d

        for client, name, n, blocked, first, last in self._q(
                "SELECT client, name, COUNT(*), SUM(blocked), MIN(time), MAX(time) FROM lookups GROUP BY client, name"):
            d = dev(client, first, last)
            d["lookups"] += n
            d["blocked"] += blocked or 0
            d["sites"].add(site(name))
        for client, proto, dst, dport, ob, ib, first, last in self._conn_totals():
            d = dev(client, first, last)
            d["bytes_out"] += ob
            d["bytes_in"] += ib
            if not is_private(dst):
                d["destinations"].add((proto, dst, dport))
        for d in out.values():
            d["sites"], d["destinations"] = len(d["sites"]), len(d["destinations"])
        return sorted(out.values(), key=lambda d: (d["name"] or "~", d["client"]))

    def device(self, client):
        names = dict(self._q("SELECT client, name FROM names"))
        rows = self._q("""SELECT name, COUNT(*), SUM(blocked), MIN(time), MAX(time), GROUP_CONCAT(answers, '|')
                          FROM lookups WHERE client=? GROUP BY name""", (client,))
        lookups, by_addr, sites = [], {}, {}
        for name, n, blocked, first, last, answers_concat in rows:
            addrs = set()
            for chunk in (answers_concat or "").split("|"):
                try:
                    addrs.update(a for a in json.loads(chunk) if a[:1].isdigit() or ":" in a)
                except ValueError:
                    pass
            for a in addrs:
                by_addr.setdefault(a, set()).add(name)
            lookups.append({"name": name, "site": site(name), "count": n, "blocked": blocked or 0,
                            "first": first, "last": last, "addresses": sorted(addrs)[:8]})
            s = sites.setdefault(site(name), {"site": site(name), "names": 0, "count": 0, "blocked": 0,
                                              "first": first, "last": last})
            s["names"] += 1
            s["count"] += n
            s["blocked"] += blocked or 0
            s["first"], s["last"] = min(s["first"], first), max(s["last"], last)
        conns = {}
        for _c, proto, dst, dport, ob, ib, first, last in self._conn_totals(client):
            k = (proto, dst, dport)
            c = conns.setdefault(k, {"proto": proto, "dst": dst, "dport": dport, "connections": 0,
                                     "bytes_out": 0, "bytes_in": 0, "first": first, "last": last,
                                     "local": is_private(dst), "names": sorted(by_addr.get(dst, ()))})
            c["connections"] += 1
            c["bytes_out"] += ob
            c["bytes_in"] += ib
            c["first"], c["last"] = min(c["first"], first), max(c["last"], last)
        connections = sorted(conns.values(), key=lambda c: -(c["bytes_out"] + c["bytes_in"]))
        unexplained = [c for c in connections if not c["local"] and not c["names"]]
        flags = []
        blocked = sum(x["blocked"] for x in lookups)
        if blocked:
            flags.append(f"{plural(blocked, 'lookup')} blocked by your DNS filter (ads, tracking or similar)")
        if unexplained:
            flags.append(f"{plural(len(unexplained), 'destination')} reached without a matching lookup "
                         "(a fixed address, or a lookup older than the data kept)")
        return {"client": client, "name": names.get(client, ""), "flags": flags,
                "sites": sorted(sites.values(), key=lambda s: -s["count"]),
                "lookups": sorted(lookups, key=lambda x: -x["count"]),
                "connections": connections}
