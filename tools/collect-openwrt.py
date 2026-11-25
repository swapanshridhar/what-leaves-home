#!/usr/bin/env python3
"""Copy chosen devices' DNS lookups and connections off an OpenWrt router.

Writes the files What Leaves Home reads with WL_FILES_DIR (see docs/collector.md):

    collect-openwrt.py dns    appends new AdGuard query-log lines to YYYY-MM-DD.jsonl
    collect-openwrt.py conn   appends one sample of open connections to conn-YYYY-MM-DD.jsonl

Run `dns` every hour and `conn` every 5 minutes, from cron or a systemd timer, on
any machine that can reach the router over SSH. It uses only Python's standard
library and the `ssh` command. `grep` runs on the router, so only the chosen
devices' lines ever leave it.

Settings come from the environment:

    WLC_ROUTER       router address (required)
    WLC_PORT         SSH port (default 22)
    WLC_USER         SSH user (default root)
    WLC_KEY          SSH private key made for this alone (required)
    WLC_KNOWN_HOSTS  known_hosts file holding the router's host key (required)
    WLC_CLIENTS      the devices to keep: comma-separated IPv4 addresses (required)
    WLC_OUT          folder to write to (default ./collector-data)
    WLC_LOG          AdGuard's query log on the router
                     (default /opt/AdGuardHome/data/querylog.json; the previous
                     file, with .1 added, is read too)
    WLC_KEEP_DAYS    delete files older than this many days (default 30)

AdGuard Home must store its query log in a file (querylog.file_enabled: true).
Some router builds keep it in memory only; see docs/collector.md.
"""
import json, os, re, subprocess, sys
from datetime import datetime, timedelta, timezone

IP_OK = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def setting(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        sys.exit(f"{name} is not set (see the top of this file)")
    return value


def router(cmd):
    r = subprocess.run(
        ["ssh", "-i", setting("WLC_KEY"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + setting("WLC_KNOWN_HOSTS"),
         "-o", "StrictHostKeyChecking=yes", "-p", setting("WLC_PORT", "22"),
         f"{setting('WLC_USER', 'root')}@{setting('WLC_ROUTER')}", cmd],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise OSError(f"ssh exited {r.returncode}: {r.stderr.strip()[:200]}")
    return r.stdout.splitlines()


def alternation(clients):
    return "|".join(c.replace(".", "\\.") for c in clients)


def parse_conn(line):
    """One nf_conntrack line -> dict, or None. The first tuple is the device's
    side (original direction), the second the reply."""
    t = line.split()
    kv = [x.split("=", 1) for x in t if "=" in x]
    orig, reply = {}, {}
    for k, v in kv:
        (reply if k in orig else orig)[k] = v
    if not {"src", "dst", "sport", "dport"} <= orig.keys():
        return None
    proto = next((x for x in t if x in ("tcp", "udp")), None)
    if not proto:
        return None
    num = lambda d, k: int(d.get(k, 0))
    return {"client": orig["src"], "proto": proto, "dst": orig["dst"],
            "sport": int(orig["sport"]), "dport": int(orig["dport"]),
            "out_pkts": num(orig, "packets"), "out_bytes": num(orig, "bytes"),
            "in_pkts": num(reply, "packets"), "in_bytes": num(reply, "bytes")}


def collect_conns(clients, out):
    pattern = f"src=({alternation(clients)}) "
    # /proc/net/nf_conntrack on most builds; the conntrack tool where /proc lacks it.
    lines = router(f"(cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L -o extended 2>/dev/null) "
                   f"| grep -E '{pattern}'; true")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [dict(t=now, **c) for c in map(parse_conn, lines) if c and c["client"] in clients]
    if rows:
        with open(os.path.join(out, f"conn-{now[:10]}.jsonl"), "a") as f:
            f.write("\n".join(json.dumps(r, separators=(",", ":")) for r in rows) + "\n")
    print(f"connections sampled: {len(rows)}")


def collect_dns(clients, out):
    state_file = os.path.join(out, "state.json")
    try:
        last = json.load(open(state_file))
    except (FileNotFoundError, ValueError):
        last = {}
    log = setting("WLC_LOG", "/opt/AdGuardHome/data/querylog.json")
    pattern = f'"IP":"({alternation(clients)})"'
    lines = router(f"grep -h -E '{pattern}' '{log}.1' '{log}' 2>/dev/null; true")
    new = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        c = e.get("IP")
        if c in clients and e.get("T", "") > last.get(c, ""):
            new.append(e)
    by_day = {}
    for e in sorted(new, key=lambda e: e["T"]):
        by_day.setdefault(e["T"][:10], []).append(json.dumps(e, separators=(",", ":")))
        last[e["IP"]] = max(last.get(e["IP"], ""), e["T"])
    for day, rows in by_day.items():
        with open(os.path.join(out, f"{day}.jsonl"), "a") as f:
            f.write("\n".join(rows) + "\n")
    tmp = state_file + ".tmp"
    json.dump(last, open(tmp, "w"))
    os.replace(tmp, state_file)
    print(f"new lookups: {len(new)}")


def prune(out):
    days = int(setting("WLC_KEEP_DAYS", "30"))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    for f in os.listdir(out):
        if f.endswith(".jsonl") and f.removeprefix("conn-")[:10] < cutoff:
            os.remove(os.path.join(out, f))


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in ("dns", "conn"):
        sys.exit("usage: collect-openwrt.py dns|conn")
    clients = [c.strip() for c in setting("WLC_CLIENTS").split(",") if c.strip()]
    bad = [c for c in clients if not IP_OK.match(c)]
    if not clients or bad:
        sys.exit(f"WLC_CLIENTS must be IPv4 addresses, got: {bad or 'nothing'}")
    out = setting("WLC_OUT", "collector-data")
    os.makedirs(out, exist_ok=True)
    try:
        (collect_dns if mode == "dns" else collect_conns)(clients, out)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"read failed: {exc}", file=sys.stderr)
        return 1
    prune(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
