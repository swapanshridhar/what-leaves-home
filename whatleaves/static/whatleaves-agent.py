#!/usr/bin/env python3
"""What Leaves Home agent: which service on this server opened each connection.

Run it on a home server (as root, since the connection table and other
processes' sockets need it). Every few minutes it:

1. reads the kernel's connection table (/proc/net/nf_conntrack),
2. works out which service owns each connection:
   - a Docker container on its own network, by the container's address
   - anything on the host's own address (host-network containers, system
     services), by the socket's process, then that process's container or
     systemd unit,
3. sends the result to What Leaves Home's /api/ingest with a token.

It reads only; it changes nothing. Python 3.9+ standard library, one file.

  WL_URL=http://192.168.1.10:8080 WL_TOKEN=... python3 whatleaves-agent.py
  (What Leaves Home's Services page shows this filled in, plus a Docker one-liner and an installer.)
  (WL_TOKEN_FILE instead of WL_TOKEN; WL_INTERVAL seconds, default 300;
   WL_HOST_NAME, default this machine's name; WL_INCLUDE_LOCAL=1 to also report
   connections to other machines at home; --once to send one report)

For byte counts the kernel must count them:  sysctl net.netfilter.nf_conntrack_acct=1
"""

import http.client
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import ipaddress
from datetime import datetime, timezone

VERSION = "0.3.0"
CONNTRACK = "/proc/net/nf_conntrack"
DOCKER_SOCK = "/var/run/docker.sock"


# ----- what is on this machine

def host_addresses():
    """This machine's own addresses, from /proc (no `ip` command needed, so it runs on Alpine too)."""
    out = set()
    try:  # IPv4: the LOCAL entries of the routing trie
        prev = None
        for line in open("/proc/net/fib_trie"):
            m = re.search(r"\|-- ([0-9.]+)", line)
            if m:
                prev = m.group(1)
            elif prev and "/32 host LOCAL" in line:
                out.add(prev)
    except OSError:
        pass
    try:  # IPv6
        for line in open("/proc/net/if_inet6"):
            h = line.split()[0]
            out.add(str(ipaddress.IPv6Address(bytes.fromhex(h))))
    except OSError:
        pass
    return out - {"127.0.0.1", "::1"}


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.path)


def containers():
    """[{id, name, image, ips, network, ports}] from the local Docker daemon, or [] without Docker."""
    if not os.path.exists(DOCKER_SOCK):
        return []
    try:
        c = UnixHTTP(DOCKER_SOCK)
        c.request("GET", "/containers/json")
        data = json.loads(c.getresponse().read())
    except OSError:
        return []
    out = []
    for d in data:
        nets = (d.get("NetworkSettings") or {}).get("Networks") or {}
        out.append({
            "id": d["Id"], "name": (d.get("Names") or ["?"])[0].lstrip("/"), "image": d.get("Image", ""),
            "ips": [n.get("IPAddress") for n in nets.values() if n.get("IPAddress")],
            "network": (d.get("HostConfig") or {}).get("NetworkMode", ""),
            "ports": sorted({f"{p['PrivatePort']}/{p['Type']}" for p in d.get("Ports") or []}),
        })
    return out


# ----- who owns a socket on the host's own address

def _hex_addr(h):
    ip, port = h.split(":")
    if len(ip) == 8:
        return socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip)[::-1]), int(port, 16)
    raw = bytes.fromhex(ip)
    return socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))), int(port, 16)


def socket_inodes():
    """(proto, local port) -> inode, for this machine's sockets."""
    out = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = open(f"/proc/net/{proto}").read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            p = line.split()
            _ip, port = _hex_addr(p[1])
            out[(proto.rstrip("6"), port)] = p[9]
    return out


def inode_owners():
    """inode -> pid, by walking /proc/*/fd."""
    out = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
                if target.startswith("socket:["):
                    out[target[8:-1]] = pid
        except OSError:
            continue
    return out


def pid_service(pid, by_container_id):
    """A container name, a systemd unit, or the program name, for one process."""
    try:
        cgroup = open(f"/proc/{pid}/cgroup").read()
    except OSError:
        return None
    m = re.search(r"(?:docker[-/]|containerd/|cri-containerd-)([0-9a-f]{64})", cgroup)
    if m and m.group(1) in by_container_id:
        return by_container_id[m.group(1)]
    m = re.search(r"/([^/\n]+)\.service", cgroup)
    if m:
        return f"{m.group(1)} (system service)"
    try:
        return open(f"/proc/{pid}/comm").read().strip() + " (program)"
    except OSError:
        return None


# ----- the connection table

def conntrack_rows():
    with open(CONNTRACK) as f:
        for line in f:
            t = line.split()
            orig, reply = {}, {}
            for x in t:
                if "=" in x:
                    k, v = x.split("=", 1)
                    (reply if k in orig else orig)[k] = v
            if {"src", "dst", "sport", "dport"} <= orig.keys() and t[2] in ("tcp", "udp"):
                yield {"proto": t[2], "src": orig["src"], "dst": orig["dst"], "sport": int(orig["sport"]),
                       "dport": int(orig["dport"]), "out_bytes": int(orig.get("bytes", 0)),
                       "in_bytes": int(reply.get("bytes", 0))}


def is_local(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip in ipaddress.ip_network("100.64.0.0/10")


def report(host_name, include_local=False):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    mine = host_addresses()
    ctrs = containers()
    by_ip = {ip: c["name"] for c in ctrs for ip in c["ips"]}
    by_id = {c["id"]: c["name"] for c in ctrs}
    inodes, owners = socket_inodes(), None
    conns, seen = [], set()
    for r in conntrack_rows():
        if r["dst"] in mine or r["dst"] in by_ip or r["dst"].startswith("127."):
            continue  # inbound to this machine, or between its own containers
        if not include_local and is_local(r["dst"]):
            continue  # traffic within the home isn't what leaves it (WL_INCLUDE_LOCAL=1 keeps it)
        if r["src"] in by_ip:
            service = by_ip[r["src"]]
        elif r["src"] in mine:
            if owners is None:
                owners = inode_owners()  # only walk /proc when needed
            pid = owners.get(inodes.get((r["proto"], r["sport"]), ""))
            service = (pid and pid_service(pid, by_id)) or "unknown (connection already closed)"
        else:
            continue  # forwarded traffic of other machines
        seen.add(service)
        conns.append({"time": now, "service": service, **{k: r[k] for k in
                      ("proto", "dst", "sport", "dport", "out_bytes", "in_bytes")}})
    services = [{"name": c["name"], "image": c["image"], "ports": c["ports"], "network": c["network"]} for c in ctrs]
    services += [{"name": s, "image": "", "ports": [], "network": "host"} for s in sorted(seen - set(by_id.values()))]
    return {"agent": VERSION, "host": host_name, "host_ips": sorted(mine), "time": now,
            "services": services, "conns": conns}


def send(url, token, body):
    req = urllib.request.Request(url.rstrip("/") + "/api/ingest", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                                          "User-Agent": f"WhatLeavesHome-agent/{VERSION}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def main():
    url = os.environ.get("WL_URL", "").strip()
    token = os.environ.get("WL_TOKEN", "").strip()
    if os.environ.get("WL_TOKEN_FILE"):
        token = open(os.environ["WL_TOKEN_FILE"]).read().strip()
    if not url or not token:
        sys.exit("Set WL_URL and WL_TOKEN (or WL_TOKEN_FILE). The token is on What Leaves Home's Settings page.")
    if not os.access(CONNTRACK, os.R_OK):
        sys.exit(f"Can't read {CONNTRACK}: run as root, with the nf_conntrack module loaded.")
    host_name = os.environ.get("WL_HOST_NAME") or socket.gethostname()
    every = int(os.environ.get("WL_INTERVAL", "300"))
    while True:
        try:
            body = report(host_name, os.environ.get("WL_INCLUDE_LOCAL") == "1")
            res = send(url, token, body)
            print(f"sent {len(body['conns'])} connections from {len(body['services'])} services: {res}", flush=True)
        except Exception as exc:
            print(f"report failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            if "--once" in sys.argv:
                return 1
        if "--once" in sys.argv:
            return 0
        time.sleep(every)


if __name__ == "__main__":
    sys.exit(main())
