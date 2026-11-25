"""From raw lookups and connections to what a person wants to know: who each
device talks to (as companies and countries), a verdict with its reasons, and
the one finding worth looking at first.

Grading v0 is deliberately simple and always explained. Start at 100 and
take points off for each reason; the reasons are shown next to the grade.
"""

from datetime import datetime, timedelta, timezone

from .enrich import company_for_site, flag, is_time_service, is_tracking, site
from .store import is_private

PLAINTEXT_PORTS = {80: "web (HTTP)", 21: "FTP", 23: "Telnet", 554: "video (RTSP)"}

VERDICTS = [  # (lowest score, grade, verdict, label)
    (90, "A", "good", "Looks fine"),
    (75, "B", "check", "Worth a look"),
    (60, "C", "check", "Worth a look"),
    (45, "D", "concern", "Concern"),
    (0, "F", "concern", "Concern"),
]

KINDS = [  # (words in the name, kind) for the icon and the one-line summary
    (("tv", "television", "roku", "chromecast", "fire stick", "apple tv"), "tv"),
    (("camera", "cam", "doorbell", "reolink", "ring"), "camera"),
    (("speaker", "echo", "home mini", "nest audio", "sonos", "homepod"), "speaker"),
    (("fan",), "fan"), (("air conditioner", " ac", "hvac", "thermostat"), "climate"),
    (("humidifier", "purifier", "dehumidifier"), "air"),
    (("plug", "switch", "outlet"), "plug"), (("light", "lamp", "bulb"), "light"),
    (("vacuum", "roomba", "mop", "braava"), "vacuum"), (("printer",), "printer"),
    (("phone", "iphone", "pixel"), "phone"), (("laptop", "macbook", "air"), "laptop"),
    (("watch",), "watch"), (("garage", "myq", "door"), "door"),
]


SERVICE_KINDS = [  # (words in the image or name, kind)
    (("jellyfin", "plex", "emby", "navidrome", "music-assistant", "music_assistant"), "media"),
    (("home-assistant", "homeassistant", "hass", "zigbee2mqtt", "mosquitto", "zwave", "esphome"), "home"),
    (("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "qbittorrent", "transmission", "sabnzbd", "overseerr", "jellyseerr", "gluetun"), "download"),
    (("adguard", "pihole", "pi-hole", "unbound", "dnsmasq", "systemd-resolved"), "dns"),
    (("caddy", "nginx", "traefik", "haproxy", "cloudflared", "tailscale", "wireguard", "wg-easy"), "proxy"),
    (("ollama", "open-webui", "openwebui", "llama", "whisper", "piper"), "ai"),
    (("postgres", "mariadb", "mysql", "redis", "influx", "sqlite"), "db"),
    (("frigate", "scrypted", "go2rtc"), "camera"),
    (("uptime-kuma", "netalertx", "healthchecks", "grafana", "prometheus", "beszel", "glances", "speedtest"), "monitor"),
]


def is_unattributed(name):
    return (name or "").startswith(("unknown (", "unattributed"))


def service_kind(name, image=""):
    n = f"{name} {image}".lower()
    for words, kind in SERVICE_KINDS:
        if any(w in n for w in words):
            return kind
    return "service"


def kind_of(name):
    n = f" {name.lower()} "
    for words, kind in KINDS:
        if any(w in n for w in words):
            return kind
    return "device"


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def _span_days(first, last):
    if not first or not last:
        return 1 / 24
    f = datetime.fromisoformat(first.replace("Z", "+00:00"))
    l = datetime.fromisoformat(last.replace("Z", "+00:00"))
    return max((l - f).total_seconds() / 86400, 1 / 24)


def companies_for(raw, owners, site_names=None):
    """Group a device's lookups and connections by company."""
    comps = {}

    def entry(name):
        return comps.setdefault(name, {"company": name, "domains": {}, "lookups": 0, "bytes_out": 0,
                                       "bytes_in": 0, "connections": 0, "hosting": set(), "countries": set(),
                                       "tracking": False, "time": False, "addresses": set(),
                                       "unexplained": False})

    for l in raw["lookups"]:
        s = l["site"]
        e = entry(company_for_site(s, site_names))
        e["domains"][l["name"]] = e["domains"].get(l["name"], 0) + l["count"]
        e["lookups"] += l["count"]
        e["tracking"] |= is_tracking(s) or bool(l["blocked"])
    for c in raw["connections"]:
        if c["local"]:
            continue
        owner, cc = owners.lookup(c["dst"]) if owners else ("", "")
        if c["names"]:
            name = company_for_site(site(c["names"][0]), site_names)
        else:
            # No lookup: the owner of the address is only who hosts it, not who the service is.
            name = f"Unknown service on {owner}" if owner else "Unknown owner"
        e = entry(name)
        e["unexplained"] = not c["names"]
        e["bytes_out"] += c["bytes_out"]
        e["bytes_in"] += c["bytes_in"]
        e["connections"] += c["connections"]
        e["addresses"].add(c["dst"])
        if owner and owner != name:
            e["hosting"].add(owner)
        if cc:
            e["countries"].add(cc)
    out = []
    for e in comps.values():
        # A time service only if every name of this company is one (time.vendor.com alone doesn't make
        # the vendor a time service).
        e["time"] = bool(e["domains"]) and all(is_time_service(n) for n in e["domains"])
        e["domains"] = [{"name": k, "count": v} for k, v in sorted(e["domains"].items(), key=lambda kv: -kv[1])]
        e["hosting"] = sorted(e["hosting"])
        e["countries"] = [{"code": c, "flag": flag(c)} for c in sorted(e["countries"])]
        e["addresses"] = sorted(e["addresses"])
        out.append(e)
    return sorted(out, key=lambda e: -(e["bytes_out"] + e["bytes_in"] + e["lookups"] * 200))


def assess(raw, comps):
    """Score, grade, verdict and the reasons, good and bad."""
    score, reasons = 100, []
    tracking = [c for c in comps if c["tracking"]]
    # Unexplained destinations are counted once, below, not as extra companies.
    makers = [c for c in comps if not c["tracking"] and not c["time"] and not c["unexplained"]]
    maker = makers[0]["company"] if makers else ""
    others = [c for c in makers[1:]]
    unexplained = [c for c in raw["connections"] if not c["local"] and not c["names"]]
    plaintext = sorted({c["dport"] for c in raw["connections"]
                        if not c["local"] and c["proto"] == "tcp" and c["dport"] in PLAINTEXT_PORTS})
    remote = [c for c in raw["connections"] if not c["local"]]
    days = _span_days(min((c["first"] for c in remote), default=None), max((c["last"] for c in remote), default=None))
    per_day = sum(c["bytes_out"] for c in remote) / days

    if tracking:
        n = sum(c["lookups"] for c in tracking)
        score -= 35 if n >= 20 else 20
        names = ", ".join(c["company"] for c in tracking[:3])
        reasons.append({"level": "bad", "text": f"Contacted ad or tracking services {n} times ({names})"})
    if plaintext:
        score -= 20
        reasons.append({"level": "bad", "text": "Sent unencrypted " +
                        ", ".join(PLAINTEXT_PORTS[p] for p in plaintext) + " traffic to the internet"})
    if others:
        score -= min(8 * len(others), 24)
        reasons.append({"level": "warn", "text": f"Talks to {len(others)} other "
                        f"compan{'y' if len(others) == 1 else 'ies'} besides {maker or 'its maker'}: "
                        + ", ".join(c["company"] for c in others[:4])})
    if unexplained:
        score -= 10
        reasons.append({"level": "warn", "text": f"Connected to {len(unexplained)} "
                        f"address{'' if len(unexplained) == 1 else 'es'} it never looked up "
                        "(a fixed address, or a lookup older than the data kept)"})
    if per_day > 1e9:
        score -= 20
        reasons.append({"level": "bad", "text": f"Uploads about {human_bytes(per_day)} a day"})
    elif per_day > 1e8:
        score -= 10
        reasons.append({"level": "warn", "text": f"Uploads about {human_bytes(per_day)} a day"})

    if not tracking:
        reasons.append({"level": "good", "text": "No ad or tracking services seen"})
    if raw["connections"] and not plaintext:
        reasons.append({"level": "good", "text": "Every internet connection seen was on an encrypted port"})
    if maker and not others:
        reasons.append({"level": "good", "text": f"Talks only to {maker}"
                        + (" and a time service" if any(c["time"] for c in comps) else "")})
    for floor, grade, verdict, label in VERDICTS:
        if score >= floor:
            break
    return {"score": max(score, 0), "grade": grade, "verdict": verdict, "label": label,
            "maker": maker, "reasons": reasons, "per_day_out": per_day}


def summary_line(a, comps, per_day):
    parts = []
    if a["maker"]:
        hosts = sorted({h for c in comps if c["company"] == a["maker"] for h in c["hosting"]})
        parts.append(f"Talks to {a['maker']}" + (f" (on {hosts[0]})" if hosts else ""))
    others = len([c for c in comps if c["company"] != a["maker"]])
    if others:
        parts.append(f"{others} other{'s' if others != 1 else ''}")
    if per_day:
        parts.append(f"~{human_bytes(per_day)}/day out")
    return " · ".join(parts) or "No activity yet"


def device_view(store, owners, client, site_names=None, with_detail=True):
    raw = store.device(client)
    comps = companies_for(raw, owners, site_names)
    a = assess(raw, comps)
    if not raw["lookups"] and not raw["connections"]:
        # Nothing seen: no grade rather than a flattering A.
        a.update(score=100, grade="–", verdict="quiet", label="No traffic seen", reasons=[])
    svc = raw.get("service")
    kind = service_kind(svc["name"], svc["image"]) if svc else kind_of(raw["name"] or "")
    view = {"client": client, "name": raw["name"], "kind": kind,
            "service": {"host": svc["host"], "image": svc["image"], "ports": svc["ports"], "network": svc["network"]}
            if svc else None,
            "first": raw["first"], "last": raw["last"], "summary": summary_line(a, comps, a["per_day_out"]),
            **a,
            "companies_brief": [{"company": c["company"], "flags": [x["flag"] for x in c["countries"]],
                                 "tracking": c["tracking"]} for c in comps[:4]],
            "bytes_out": sum(c["bytes_out"] for c in comps), "bytes_in": sum(c["bytes_in"] for c in comps),
            "lookups": sum(l["count"] for l in raw["lookups"]), "company_count": len(comps),
            "activity": store.hourly(client)}
    if with_detail:
        view.update(companies=comps, lookups_detail=raw["lookups"], connections=raw["connections"])
    return view


def overview(store, owners, site_names=None):
    devices = [device_view(store, owners, d["client"], site_names, with_detail=False) for d in store.devices()]
    services = [device_view(store, owners, s["id"], site_names, with_detail=False) for s in store.services()]
    counts = {"total": len(devices) + len(services), "good": 0, "check": 0, "concern": 0, "quiet": 0,
              "devices": len(devices), "services": len(services)}
    for d in devices + services:
        counts[d["verdict"]] += 1
    # The finding to show first: the worst reason on the lowest-scoring device.
    finding = None
    for d in sorted(devices + services, key=lambda d: d["score"]):
        if is_unattributed(d["name"]):
            continue  # connections the agent couldn't tie to a program aren't the headline
        bad = [r for r in d["reasons"] if r["level"] in ("bad", "warn")]
        if bad:
            finding = {"client": d["client"], "device": d["name"] or d["client"], "verdict": d["verdict"],
                       "text": sorted(bad, key=lambda r: r["level"] != "bad")[0]["text"]}
            break
    # Where the data goes, across all devices, by company.
    flows = {}
    for d in devices + services:
        detail = companies_for(store.device(d["client"]), owners, site_names)
        for c in detail:
            f = flows.setdefault(c["company"], {"company": c["company"], "bytes_out": 0, "lookups": 0,
                                                "devices": [], "flags": set(), "tracking": False})
            f["bytes_out"] += c["bytes_out"]
            f["lookups"] += c["lookups"]
            f["devices"].append(d["name"] or d["client"])
            f["flags"].update(x["flag"] for x in c["countries"])
            f["tracking"] |= c["tracking"]
    companies = sorted(flows.values(), key=lambda f: (-f["bytes_out"], -f["lookups"]))
    for f in companies:
        f["flags"] = sorted(f["flags"])
    things = " and ".join(x for x in (
        f"{len(devices)} device{'s' if len(devices) != 1 else ''}" if devices or not services else "",
        f"{len(services)} service{'s' if len(services) != 1 else ''}" if services else "") if x)
    seen = counts["total"] - counts["quiet"]
    headline = (f"{things} watched. " +
                ("All look fine." if seen and counts["good"] == seen else
                 f"{counts['concern']} need{'s' if counts['concern'] == 1 else ''} attention, "
                 f"{counts['check']} worth a look." if counts["total"] else "Waiting for the first data."))
    return {"counts": counts, "headline": headline, "finding": finding, "devices": devices, "services": services,
            "companies": companies, "scan": store.scan_results()}


SERVER_PORTS = {8096: "Jellyfin", 8123: "Home Assistant", 8989: "Sonarr", 7878: "Radarr", 9696: "Prowlarr",
                5055: "Overseerr", 32400: "Plex", 11434: "Ollama", 9443: "Portainer", 3001: "Uptime Kuma",
                5432: "PostgreSQL", 2049: "NFS", 445: "file sharing", 3000: "a web app", 8080: "a web app",
                9000: "a web app", 5000: "a web app"}
DOCKER_SITES = {"docker.io", "docker.com", "ghcr.io", "quay.io", "lscr.io", "gcr.io", "k8s.io"}
SERVICE_SITES = {"themoviedb.org": "TMDB (Jellyfin, Plex, the *arr apps)", "thetvdb.com": "TheTVDB (Jellyfin, Sonarr)",
                 "musicbrainz.org": "MusicBrainz (music apps)", "home-assistant.io": "Home Assistant",
                 "nabucasa.com": "Home Assistant Cloud", "jellyfin.org": "Jellyfin", "plex.tv": "Plex",
                 "ollama.com": "Ollama", "github.com": "software updates (GitHub)", "pypi.org": "Python packages"}


def suggest_hosts(store):
    """Machines that look like servers running services, with the evidence, best first.
    Machines already sending agent reports are left out."""
    covered = {ip for s in store.services() for ip in s["host_ips"]}
    names = dict(store.q("SELECT client, name FROM names"))
    found = {}

    def entry(ip):
        return found.setdefault(ip, {"ip": ip, "name": names.get(ip, ""), "reasons": [], "score": 0, "docker": False})

    by_ip = {}
    for r in store.scan_results():
        if r["port"] in SERVER_PORTS:
            by_ip.setdefault(r["ip"], []).append(f"{SERVER_PORTS[r['port']]} ({r['port']})")
    for ip, apps in by_ip.items():
        e = entry(ip)
        e["reasons"].append("Listening here: " + ", ".join(apps[:5]))
        e["score"] += 3 * len(apps)
    for ip, qnames in _names_by_client(store).items():
        sites = {site(n) for n in qnames}
        if sites & DOCKER_SITES:
            e = entry(ip)
            e["docker"] = True
            e["score"] += 5
            e["reasons"].append("Downloads container images, so it runs Docker")
        hints = [SERVICE_SITES[s] for s in sorted(sites) if s in SERVICE_SITES]
        if hints:
            e = entry(ip)
            e["score"] += 2 * len(hints)
            e["reasons"].append("Looks up " + ", ".join(hints[:4]))
        if len(sites) >= 25:
            e = entry(ip)
            e["score"] += 2
            e["reasons"].append(f"Looks up {len(sites)} different sites, like a machine running several apps")
    out = [e for ip, e in found.items() if ip not in covered and e["score"] >= 4 and is_private(ip)]
    return sorted(out, key=lambda e: -e["score"])[:12]


def _names_by_client(store):
    out = {}
    for client, name in store.q("SELECT DISTINCT client, name FROM lookups"):
        out.setdefault(client, set()).add(name)
    return out
