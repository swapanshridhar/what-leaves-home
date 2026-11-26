"""From raw lookups and connections to what a person wants to know: who each
device talks to (as companies and countries), a verdict with its reasons, and
the one finding worth looking at first.

Grading v0 is deliberately simple and always explained. Start at 100 and
take points off for each reason; the reasons are shown next to the grade.
"""

import re
from datetime import datetime, timedelta, timezone

from .enrich import company_for_site, flag, is_cert_check, is_local_name, is_time_service, is_tracking, site
from .store import is_private

# A name from a device's lookups, safe to paste into a block list: letters, digits,
# dots and hyphens only, so a crafted name can't add filter options to the rule.
RULE_SAFE = re.compile(r"^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$")

PLAINTEXT_PORTS = {80: "web (HTTP)", 21: "FTP", 23: "Telnet", 554: "video (RTSP)"}
# Clouds that host other companies' services: reaching one says little on its own.
CLOUD_PLATFORMS = {"Amazon Web Services", "Akamai", "Cloudflare", "Microsoft Azure", "Google Cloud", "Fastly",
                   "DigitalOcean", "OVHcloud", "Hetzner", "Oracle Cloud", "Alibaba Cloud", "Tencent Cloud"}
# Encrypted DNS services a device can use to skip the DNS your network hands out.
DOH_NAMES = ("dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "doh.opendns.com",
             "dns.nextdns.io", "doh.dns.apple.com", "mozilla.cloudflare-dns.com")


def plaintext_conns(raw):
    """Unencrypted connections to the internet (web, FTP, Telnet, video). Certificate checks
    (OCSP, CRL) use plain HTTP by design, on every device, so they don't count."""
    return [c for c in raw["connections"] if not c["local"] and c["proto"] == "tcp" and c["dport"] in PLAINTEXT_PORTS
            and not (c["names"] and all(is_cert_check(n) for n in c["names"]))]


def outside_dns(raw):
    """Connections where a device asks a DNS server on the internet itself, going around the
    DNS filter: plain DNS (53), DNS over TLS (853), or a known DNS-over-HTTPS service.
    A DNS server's own upstream queries are its job, so those don't count."""
    svc = raw.get("service") or {}
    if any(w in f"{svc.get('name', '')} {svc.get('image', '')}".lower() for w in ("adguard", "pihole", "unbound", "dnsmasq", "coredns")):
        return []
    return [c for c in raw["connections"] if not c["local"] and
            (c["dport"] in (53, 853) or any(n.rstrip(".").lower() in DOH_NAMES for n in c["names"]))]

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


def plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


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


# What a connection is for, when nothing named it: from its protocol and port.
PURPOSES = {
    ("tcp", 443): "Secure web (HTTPS)", ("udp", 443): "Secure web (QUIC)", ("tcp", 80): "Plain web (HTTP)",
    ("udp", 123): "Time (NTP)", ("udp", 3478): "Connection setup (STUN)", ("udp", 19302): "Connection setup (STUN)",
    ("udp", 41641): "Peer-to-peer (Tailscale)", ("udp", 51820): "VPN (WireGuard)", ("udp", 1194): "VPN (OpenVPN)",
    ("tcp", 8883): "Encrypted messaging (MQTT)", ("tcp", 1883): "Messaging (MQTT)", ("tcp", 853): "Encrypted DNS",
    ("tcp", 53): "DNS", ("udp", 53): "DNS", ("tcp", 22): "SSH", ("tcp", 5228): "Google push notifications",
    ("tcp", 5223): "Apple push notifications", ("udp", 10001): "Device relay", ("tcp", 9000): "Device relay",
}


def purpose(proto, port):
    return PURPOSES.get((proto, port), f"Port {port}/{proto}")


def unexplained_name(c, owner, svc):
    """A meaningful name for a destination nothing looked up: what the service is known to do,
    else what kind of traffic it is and whose network it's on."""
    sname = f"{svc['name']} {svc.get('image', '')}".lower() if svc else ""
    if "tailscale" in sname:
        return "Tailscale: your other devices and relays"
    if any(w in sname for w in ("gluetun", "openvpn", "wireguard", "wg-easy")):
        return "Your VPN provider" if "gluetun" in sname or "openvpn" in sname else "VPN peers"
    if any(w in sname for w in ("adguard", "pihole", "unbound")) and c["dport"] in (443, 853, 53):
        return f"DNS upstream ({owner})" if owner else "DNS upstream"
    what = purpose(c["proto"], c["dport"])
    return f"{what} on {owner}" if owner else f"{what}, network unknown"


def companies_for(raw, owners, site_names=None):
    """Group a device's lookups and connections by company."""
    comps = {}
    svc = raw.get("service")

    def entry(name):
        return comps.setdefault(name, {"company": name, "domains": {}, "lookups": 0, "bytes_out": 0,
                                       "bytes_in": 0, "connections": 0, "hosting": set(), "countries": set(),
                                       "tracking": False, "time": False, "addresses": set(),
                                       "unexplained": False, "listed": False, "track": 0, "through": 0})

    for l in raw["lookups"]:
        if is_local_name(l["name"]):
            continue  # wpad.lan, printer.local: questions about the home network, not the internet
        s = l["site"]
        e = entry(company_for_site(s, site_names))
        e["domains"][l["name"]] = e["domains"].get(l["name"], 0) + l["count"]
        e["lookups"] += l["count"]
        # Ad or tracking names: on the built-in list, or blocked by a DNS filter. "through" counts
        # the lookups of those names that weren't blocked, so got an answer.
        if is_tracking(s) or l["blocked"]:
            e["track"] += l["count"]
            e["through"] += l["count"] - min(l["blocked"], l["count"])
        e["listed"] |= is_tracking(s)
    for c in raw["connections"]:
        if c["local"]:
            continue
        owner, cc = owners.lookup(c["dst"]) if owners else ("", "")
        if c["names"]:
            name = company_for_site(site(c["names"][0]), site_names)
        else:
            # No lookup: the owner of the address is only who hosts it, not who the service is.
            name = unexplained_name(c, owner, svc)
        e = entry(name)
        e["unexplained"] = not c["names"]
        e["owner"] = owner
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
        # A tracking company: on the built-in list, or every lookup of it blocked. A company with
        # only some names blocked (a streaming app's logging) stays itself; the blocked names count
        # as blocked attempts, not as the whole company.
        e["tracking"] = e["listed"] or (e["lookups"] > 0 and e["track"] >= e["lookups"])
        # A time service only if every name of this company is one (time.vendor.com alone doesn't make
        # the vendor a time service).
        e["time"] = bool(e["domains"]) and all(is_time_service(n) for n in e["domains"])
        e["cert"] = bool(e["domains"]) and all(is_cert_check(n) for n in e["domains"])
        e["domains"] = [{"name": k, "count": v} for k, v in sorted(e["domains"].items(), key=lambda kv: -kv[1])]
        e["hosting"] = sorted(e["hosting"])
        e["countries"] = [{"code": c, "flag": flag(c)} for c in sorted(e["countries"])]
        e["addresses"] = sorted(e["addresses"])
        out.append(e)
    return sorted(out, key=lambda e: -(e["bytes_out"] + e["bytes_in"] + e["lookups"] * 200))


UPLOAD_SHARE = 0.25  # out/in above this is real uploading; streaming sends a few percent back as acknowledgements


# Products named after themselves, not their maker.
PRODUCT_MAKERS = {"roomba": "irobot", "braava": "irobot", "chromecast": "google", "nest": "google", "pixel": "google",
                  "echo": "amazon", "kindle": "amazon", "firetv": "amazon", "ring": "ring", "webos": "lg",
                  "thinq": "lg", "bravia": "sony", "homepod": "apple", "iphone": "apple", "ipad": "apple"}
# Services a device uses but that never made it: never picked as the maker (still counted as others).
NOT_MAKERS = {"Sentry", "Google (Crashlytics)", "Google Analytics", "NTP Pool (volunteer time servers)"}


def _maker_hint(comps, name):
    """The company whose name the device is called by ("Samsung TV" -> Samsung), if any."""
    words = {w for w in re.split(r"[^a-z0-9]+", (name or "").lower()) if len(w) >= 2}
    words |= {PRODUCT_MAKERS[w] for w in words if w in PRODUCT_MAKERS}
    for c in comps:
        first = re.split(r"[^a-z0-9]+", c["company"].lower())[0]
        if first and first in words:
            return c
    return None


def assess(raw, comps, server=False):
    """Score, grade, verdict and the reasons, good and bad. A server (a machine whose services
    report through an agent) isn't marked down for talking to many companies: its services are."""
    score, reasons = 100, []
    tried = [c for c in comps if c["track"] and not c["through"]]
    tracking = [c for c in comps if c["through"]]
    # Unexplained destinations are counted once, below, not as extra companies.
    makers = [c for c in comps if not c["tracking"] and not c["time"] and not c["cert"] and not c["unexplained"]]
    # A device maker's servers often run on a cloud platform (iRobot on AWS). The maker is the
    # first company that isn't a platform; platforms it also reaches aren't counted as others.
    own = [c for c in makers if c["company"] not in CLOUD_PLATFORMS and c["company"] not in NOT_MAKERS]
    makers = own + [c for c in makers if c not in own] if own else makers
    # A TV's biggest company by data is whatever it streams; the name it goes by is a better guide.
    hint = _maker_hint(makers, raw.get("name"))
    if hint:
        makers = [hint] + [c for c in makers if c is not hint]
    maker = makers[0]["company"] if makers else ""
    others = [c for c in makers[1:] if not (own and c["company"] in CLOUD_PLATFORMS)]
    bypass = outside_dns(raw)
    unexplained = [c for c in raw["connections"] if not c["local"] and not c["names"] and c not in bypass]
    plain = plaintext_conns(raw)
    plaintext = sorted({c["dport"] for c in plain})
    remote = [c for c in raw["connections"] if not c["local"]]
    days = _span_days(min((c["first"] for c in remote), default=None), max((c["last"] for c in remote), default=None))
    per_day = sum(c["bytes_out"] for c in remote) / days
    in_day = sum(c["bytes_in"] for c in remote) / days
    uploading = per_day > UPLOAD_SHARE * in_day  # not just acknowledging a download

    if tracking:
        n = sum(c["through"] for c in tracking)
        score -= 35 if n >= 20 else 20
        names = ", ".join(c["company"] for c in tracking[:3])
        reasons.append({"level": "bad", "text": f"Looked up ad or tracking services {plural(n, 'time')}: {names}"})
    if tried:
        n = sum(c["track"] for c in tried)
        score -= 5
        reasons.append({"level": "warn", "text": f"Tried to reach ad, tracking or other blocked services {plural(n, 'time')}, "
                        f"and your DNS filter blocked every one: {', '.join(c['company'] for c in tried[:3])}"
                        + (f" and {len(tried) - 3} more" if len(tried) > 3 else "")})
    if plaintext:
        # What it was for matters: logos or an update download are a weakness, not data about you.
        score -= 10
        where = sorted({c["names"][0] if c["names"] else c["dst"] for c in plain})
        reasons.append({"level": "warn", "text": "Used unencrypted " + ", ".join(PLAINTEXT_PORTS[p] for p in plaintext)
                        + " with " + ", ".join(where[:3]) + (f" and {len(where) - 3} more" if len(where) > 3 else "")
                        + ": anyone along the way could read or change it"})
    if others and not server:
        score -= min(8 * len(others), 24)
        reasons.append({"level": "warn", "text": f"Talks to {len(others)} other "
                        f"compan{'y' if len(others) == 1 else 'ies'} besides {maker or 'its maker'}: "
                        + ", ".join(c["company"] for c in others[:4])})
    if bypass:
        score -= 15
        where = sorted({c["names"][0] if c["names"] else c["dst"] for c in bypass})
        reasons.append({"level": "bad", "text": "Asks an outside DNS server directly (" + ", ".join(where[:3]) +
                        "), so your DNS filter can't see or block those lookups"})
    if unexplained:
        score -= 10
        reasons.append({"level": "warn", "text": f"Connected to {len(unexplained)} "
                        f"address{'' if len(unexplained) == 1 else 'es'} it never looked up "
                        "(a fixed address, or a lookup older than the data kept)"})
    if per_day > 1e9 and uploading:
        score -= 20
        reasons.append({"level": "bad", "text": f"Uploads about {human_bytes(per_day)} a day"})
    elif per_day > 1e8 and uploading:
        score -= 10
        reasons.append({"level": "warn", "text": f"Uploads about {human_bytes(per_day)} a day"})

    if not tracking and not tried:
        reasons.append({"level": "good", "text": "No ad or tracking services seen"})
    if raw["connections"] and not plaintext:
        reasons.append({"level": "good", "text": "Every internet connection seen was on an encrypted port"})
    if server:
        reasons.append({"level": "good", "text": "A server: what each of its apps sends is graded under Services"})
    elif maker and not others:
        reasons.append({"level": "good", "text": f"Talks only to {maker}"
                        + (" and a time service" if any(c["time"] for c in comps) else "")})
    for floor, grade, verdict, label in VERDICTS:
        if score >= floor:
            break
    return {"score": max(score, 0), "grade": grade, "verdict": verdict, "label": label,
            "maker": maker, "reasons": reasons, "per_day_out": per_day, "uploading": uploading}


def actions_for(raw, comps, a):
    """Concrete next steps for one device or service, each with a short why."""
    acts = []
    tracking_sites, already = {}, set()
    for l in raw["lookups"]:
        if is_tracking(l["site"]) or l["blocked"]:
            if l["blocked"] >= l["count"]:
                already.add(l["site"])
            else:
                tracking_sites.setdefault(l["site"], 0)
                tracking_sites[l["site"]] += l["count"] - l["blocked"]
    if tracking_sites:
        acts.append({"level": "bad", "title": "Block its ad and tracking services",
                     "text": "Paste these rules into AdGuard Home under Filters → Custom filtering rules. "
                             "Blocking can switch off some free extras, such as recommendations or "
                             "personalised ads. If something stops working, remove the line.",
                     "rules": [f"||{s}^" for s in sorted(tracking_sites, key=lambda s: -tracking_sites[s])
                               if RULE_SAFE.match(s)]})
    elif already:
        acts.append({"level": "good", "title": "Already blocked",
                     "text": "Your AdGuard is already refusing its ad and tracking lookups: "
                             + ", ".join(sorted(already)) + ".", "rules": []})
    remote = [c for c in raw["connections"] if not c["local"]]
    if plaintext_conns(raw):
        acts.append({"level": "warn", "title": "Check for a firmware update",
                     "text": "Some of its traffic isn't encrypted, so anyone along the way could read or change it. "
                             "Often it's an update check, logos or an old service. The names under Technical "
                             "details show what it was. Update its firmware; if it keeps happening, keep it on "
                             "a guest or IoT network.", "rules": []})
    if outside_dns(raw):
        acts.append({"level": "bad", "title": "Make it use your DNS filter",
                     "text": "It has its own DNS server built in, so some of its lookups skip AdGuard or Pi-hole and "
                             "never show up here. Many TVs and streaming sticks do this. On your router, block "
                             "outgoing DNS (ports 53 and 853) for this device: it then falls back to your filter. "
                             "If your router can't, AdGuard Home can't fix it alone.", "rules": []})
    if a["per_day_out"] > 1e8 and a.get("uploading", True):
        acts.append({"level": "warn", "title": "Check its cloud settings",
                     "text": f"It uploads about {human_bytes(a['per_day_out'])} a day. Cameras and vacuums do this "
                             "when cloud recording, backup or maps are on. Turn those off in its app if you "
                             "don't use them.", "rules": []})
    bypass = outside_dns(raw)
    if any(not c["names"] and c not in bypass for c in remote):
        acts.append({"level": "info", "title": "Addresses it never looked up: usually nothing to do",
                     "text": "Some devices connect to fixed addresses for time, relays or updates. AdGuard can't "
                             "block those (there's no lookup to refuse). To stop one, block the address in your "
                             "router's firewall.", "rules": []})
    return acts


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


def router_client(store, min_lookups=200, min_share=0.6):
    """The address most lookups come from, when it's most of them: a router answering
    DNS for every device (Google Wifi, Nest Wifi, eero and others do this)."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = store.q("SELECT client, COUNT(*) FROM lookups WHERE time >= ? GROUP BY client", (since,))
    total = sum(n for _c, n in rows)
    if total < min_lookups:
        return None
    client, n = max(rows, key=lambda r: r[1])
    return {"client": client, "share": round(n / total, 2)} if n / total >= min_share else None


def device_view(store, owners, client, site_names=None, with_detail=True, router=None):
    raw = store.device(client)
    comps = companies_for(raw, owners, site_names)
    server = not client.startswith("svc:") and any(client in s["host_ips"] for s in store.services())
    a = assess(raw, comps, server)
    if not raw["lookups"] and not raw["connections"]:
        # Nothing seen: no grade rather than a flattering A.
        a.update(score=100, grade="–", verdict="quiet", label="No traffic seen", reasons=[])
    svc = raw.get("service")
    unmatched = bool(svc) and is_unattributed(svc["name"])
    if unmatched and a["verdict"] != "quiet":
        # Connections that ended before the agent saw which program opened them. Shown, so
        # nothing is hidden, but not graded: a grade would blame no app in particular.
        a.update(score=100, grade="–", verdict="unmatched", label="Not graded: no app identified", reasons=[
            {"level": "info", "text": "These connections ended before the agent could see which program opened "
                                      "them: usually quick checks such as updates or the time. Who they went to is "
                                      "listed below. They aren't graded, because no app can be blamed for them."}])
    kind = service_kind(svc["name"], svc["image"]) if svc else kind_of(raw["name"] or "")
    is_router = bool(router and router["client"] == client)
    if is_router:
        kind = "router"
    name = raw["name"] or ("Everything behind your router" if is_router else "")
    if unmatched:
        name = "Short-lived connections (app not identified)"
    view = {"client": client, "name": name,
            "kind": kind, "router": is_router,
            "service": {"host": svc["host"], "image": svc["image"], "ports": svc["ports"], "network": svc["network"]}
            if svc else None,
            "first": raw["first"], "last": raw["last"], "summary": summary_line(a, comps, a["per_day_out"]),
            **a,
            "companies_brief": [{"company": c["company"], "flags": [x["flag"] for x in c["countries"]],
                                 "tracking": c["tracking"]} for c in comps[:4]],
            "bytes_out": sum(c["bytes_out"] for c in comps), "bytes_in": sum(c["bytes_in"] for c in comps),
            "lookups": sum(l["count"] for l in raw["lookups"]), "company_count": len(comps),
            "activity": store.hourly(client)}
    view["actions"] = actions_for(raw, comps, a) if view["verdict"] not in ("quiet", "unmatched") else []
    if with_detail:
        view.update(companies=comps, lookups_detail=raw["lookups"], connections=raw["connections"])
    return view


def overview(store, owners, site_names=None):
    router = router_client(store)
    devices = [device_view(store, owners, d["client"], site_names, with_detail=False, router=router)
               for d in store.devices()]
    services = [device_view(store, owners, s["id"], site_names, with_detail=False) for s in store.services()]
    counts = {"total": len(devices) + len(services), "good": 0, "check": 0, "concern": 0, "quiet": 0, "unmatched": 0,
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
                                                "devices": [], "flags": set(), "tracking": False,
                                                "unexplained": c["unexplained"], "owner": c.get("owner", ""),
                                                "addresses": 0})
            f["addresses"] += len(c["addresses"])
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
    # One block list for the whole home: every ad or tracking rule any device or service needs.
    rules = {}
    for d in devices + services:
        for act in d["actions"]:
            for r in act["rules"]:
                rules.setdefault(r, []).append(d["name"] or d["client"])
    block = [{"rule": r, "used_by": sorted(set(v))} for r, v in sorted(rules.items(), key=lambda kv: -len(kv[1]))]
    return {"counts": counts, "headline": headline, "finding": finding, "devices": devices, "services": services,
            "companies": companies, "scan": store.scan_results(), "block_rules": block, "router": router}


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
