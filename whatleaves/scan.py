"""Optional: find services listening on your own network (WL_SCAN_TARGETS).

Off unless you list what to scan, for example WL_SCAN_TARGETS=192.168.1.0/24.
Only private ranges are accepted, so it can't be pointed at the internet. It
tries a short list of common home-service ports once a day, reads the page
title of anything that answers on a web port, and records one summary of each
scan on the "This app" tab.
"""

import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import net

PORTS = {
    22: "SSH", 53: "DNS", 80: "Web page", 443: "Web page (HTTPS)", 445: "File sharing (SMB)", 554: "Video stream (RTSP)",
    631: "Printer (IPP)", 1883: "MQTT", 1400: "Sonos", 2049: "NFS", 3000: "Web app", 3001: "Uptime Kuma",
    5000: "Web app", 5055: "Overseerr / Jellyseerr", 5432: "PostgreSQL", 7878: "Radarr", 8008: "Google Cast",
    8080: "Web app", 8081: "Web app", 8083: "Web app", 8096: "Jellyfin", 8123: "Home Assistant", 8443: "Web app (HTTPS)",
    8883: "MQTT (TLS)", 8989: "Sonarr", 9000: "Web app", 9090: "Web app", 9443: "Portainer", 9696: "Prowlarr",
    11434: "Ollama", 32400: "Plex", 51413: "BitTorrent",
}
WEB_PORTS = {80, 3000, 3001, 5000, 5055, 7878, 8080, 8081, 8083, 8096, 8123, 8989, 9000, 9090, 9696}
MAX_HOSTS = 1024
HOME_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def targets(spec):
    """Private addresses from 'net, net, ...'; anything public is refused."""
    hosts = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        net_ = ipaddress.ip_network(part, strict=False)
        if net_.version != 4 or not any(net_.subnet_of(home) for home in HOME_RANGES):
            raise ValueError(f"{part}: only home ranges (10.x, 172.16-31.x, 192.168.x) can be scanned")
        if len(hosts) + net_.num_addresses > MAX_HOSTS + 2:  # check before listing: 10.0.0.0/8 is 16 million
            raise ValueError(f"{part}: scan at most {MAX_HOSTS} addresses (a /22) in all")
        hosts += [str(h) for h in (net_.hosts() if net_.num_addresses > 2 else net_)]
    return hosts


def title(ip, port):
    try:
        body = net.fetch(f"http://{ip}:{port}/", "Read the page title of a service found by the scan",
                         timeout=3)[:20000].decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r"<title[^>]*>([^<]{1,120})", body, re.I)
    return m.group(1).strip() if m else ""


def scan_once(store, hosts):
    pairs = [(h, p) for h in hosts for p in PORTS]
    with ThreadPoolExecutor(max_workers=64) as pool:
        open_ = [hp for hp, ok in zip(pairs, pool.map(lambda hp: net.tcp_open(*hp), pairs)) if ok]
    found = [(ip, port, PORTS[port], title(ip, port) if port in WEB_PORTS else "") for ip, port in open_]
    store.set_scan(found, datetime.now(timezone.utc).isoformat(timespec="seconds"))
    net.record(f"Scan {len(hosts)} home addresses for listening services (WL_SCAN_TARGETS)",
               f"{len(hosts)} addresses", True, len(found))
    return found


def start(store, spec, every=86400):
    hosts = targets(spec)

    def loop():
        while True:
            try:
                scan_once(store, hosts)
            except Exception as exc:
                net.record("Scan for listening services", "home network", True, 0, type(exc).__name__)
            time.sleep(every)

    threading.Thread(target=loop, daemon=True).start()
    return len(hosts)
