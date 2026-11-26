"""Turning names and addresses into companies and countries, offline.

- Who a name belongs to: a short built-in list of sites (lgthinq.com is LG).
- Who an address belongs to: the network that announces it, from iptoasn.com's
  public-domain table (PDDL), downloaded once into the data folder and
  refreshed monthly. Nothing is looked up online per address.
- Whether a name is an ad or tracking service, or a time service.
"""

import bisect
import gzip
import ipaddress
import os
import threading
import time
from array import array

ASN_URL = "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz"
ASN6_URL = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
ASN_MAX_AGE = 30 * 86400

# Big networks under the names people know.
ASN_NAMES = {
    16509: "Amazon Web Services", 14618: "Amazon Web Services", 8987: "Amazon Web Services",
    15169: "Google", 396982: "Google Cloud", 19527: "Google", 36040: "YouTube (Google)",
    8075: "Microsoft", 8068: "Microsoft", 13335: "Cloudflare", 209242: "Cloudflare",
    54113: "Fastly", 20940: "Akamai", 16625: "Akamai", 32787: "Akamai", 32934: "Meta",
    714: "Apple", 6185: "Apple", 2906: "Netflix", 40027: "Netflix", 46489: "Twitch",
    14061: "DigitalOcean", 16276: "OVHcloud", 24940: "Hetzner", 63949: "Akamai (Linode)",
    31898: "Oracle Cloud", 45102: "Alibaba Cloud", 37963: "Alibaba Cloud", 132203: "Tencent Cloud",
    45090: "Tencent Cloud", 7018: "AT&T", 7922: "Comcast", 701: "Verizon",
}

# Who runs a site, for the sites appliances talk to most. Site = registrable domain.
SITE_COMPANIES = {
    "lgthinq.com": "LG", "lge.com": "LG", "lgtvcommon.com": "LG", "lgsmartad.com": "LG Ads",
    "lgtvsdp.com": "LG", "lgappstv.com": "LG", "lgtviot.com": "LG", "lgeapi.com": "LG", "lgthinq.net": "LG",
    "vesync.com": "VeSync (Levoit)", "dreo-cloud.com": "Dreo", "dreo.com": "Dreo",
    "windows.com": "Microsoft", "microsoft.com": "Microsoft", "msftncsi.com": "Microsoft",
    "msftconnecttest.com": "Microsoft", "live.com": "Microsoft", "azure.com": "Microsoft",
    "google.com": "Google", "googleapis.com": "Google", "gstatic.com": "Google", "1e100.net": "Google",
    "googlevideo.com": "Google", "youtube.com": "Google", "ytimg.com": "Google", "nest.com": "Google",
    "doubleclick.net": "Google Ads", "googlesyndication.com": "Google Ads", "app-measurement.com": "Google Analytics",
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Analytics",
    "amazon.com": "Amazon", "amazonaws.com": "Amazon Web Services", "a2z.com": "Amazon",
    "amazon-adsystem.com": "Amazon Ads", "ring.com": "Ring (Amazon)", "amazonvideo.com": "Amazon",
    "apple.com": "Apple", "icloud.com": "Apple", "mzstatic.com": "Apple", "apple-dns.net": "Apple",
    "samsung.com": "Samsung", "samsungcloudsolution.com": "Samsung", "samsungcloudsolution.net": "Samsung",
    "samsungads.com": "Samsung Ads", "samsungacr.com": "Samsung ACR", "samsungqbe.com": "Samsung",
    "roku.com": "Roku", "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nflxso.net": "Netflix",
    "nflximg.com": "Netflix", "nflximg.net": "Netflix", "nflxext.com": "Netflix", "netflix.net": "Netflix",
    "nflxsearch.net": "Netflix", "primevideo.com": "Amazon", "media-amazon.com": "Amazon", "amazonalexa.com": "Amazon",
    "aiv-cdn.net": "Amazon", "aiv-delivery.net": "Amazon", "disneyplus.com": "Disney+", "bamgrid.com": "Disney+",
    "hulu.com": "Hulu", "hulustream.com": "Hulu", "max.com": "Max", "hbomax.com": "Max", "plex.tv": "Plex",
    "samsungosp.com": "Samsung", "samsungcloud.tv": "Samsung", "samsungcloudcdn.com": "Samsung",
    "adgrx.com": "Samsung Ads (AdGear)", "wurl.com": "Wurl (free TV channels)", "transmit.live": "Wurl (free TV channels)",
    "digicert.com": "DigiCert (certificate checks)", "lencr.org": "Let's Encrypt (certificate checks)",
    "sectigo.com": "Sectigo (certificate checks)", "globalsign.com": "GlobalSign (certificate checks)",
    "usertrust.com": "Sectigo (certificate checks)", "pki.goog": "Google (certificate checks)",
    "amazontrust.com": "Amazon (certificate checks)", "samsungotn.net": "Samsung", "samsungrm.net": "Samsung",
    "samsungcloud.com": "Samsung", "samsungelectronics.com": "Samsung", "samsungiotcloud.com": "Samsung",
    "smartthings.com": "Samsung SmartThings", "aaplimg.com": "Apple", "cdn-apple.com": "Apple",
    "apple-cloudkit.com": "Apple", "apple.news": "Apple",
    "googleusercontent.com": "Google", "ggpht.com": "Google", "gvt1.com": "Google", "gvt2.com": "Google",
    "googleadservices.com": "Google Ads", "dns.google": "Google DNS", "irobotapi.com": "iRobot",
    "akamaized.net": "Akamai", "akadns.net": "Akamai", "akamaitechnologies.com": "Akamai", "akamaiedge.net": "Akamai", "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "tuya.com": "Tuya", "tuyaus.com": "Tuya", "tuyaeu.com": "Tuya", "reolink.com": "Reolink",
    "irobot.com": "iRobot", "sonos.com": "Sonos", "xiaomi.com": "Xiaomi", "mi.com": "Xiaomi",
    "xiaomi.net": "Xiaomi", "miui.com": "Xiaomi", "tplinkcloud.com": "TP-Link", "tp-link.com": "TP-Link",
    "wyze.com": "Wyze", "ecobee.com": "ecobee", "chamberlain.com": "Chamberlain (myQ)", "myq-cloud.com": "Chamberlain (myQ)",
    "govee.com": "Govee", "philips-hue.com": "Philips Hue", "meethue.com": "Philips Hue",
    "facebook.com": "Meta", "facebook.net": "Meta", "fbcdn.net": "Meta", "spotify.com": "Spotify",
    "scdn.co": "Spotify", "cloudflare.com": "Cloudflare", "akamaihd.net": "Akamai", "akamai.net": "Akamai",
    "ntp.org": "NTP Pool (volunteer time servers)", "nist.gov": "NIST time service",
    "alphonso.tv": "Alphonso (TV viewing data)", "samba.tv": "Samba TV (viewing data)",
    "scorecardresearch.com": "Comscore", "branch.io": "Branch", "adjust.com": "Adjust", "appsflyer.com": "AppsFlyer",
    "crashlytics.com": "Google (Crashlytics)", "sentry.io": "Sentry",
    # Common on home servers.
    "docker.io": "Docker Hub", "docker.com": "Docker Hub", "ghcr.io": "GitHub (Microsoft)",
    "github.com": "GitHub (Microsoft)", "githubusercontent.com": "GitHub (Microsoft)", "quay.io": "Red Hat Quay",
    "lscr.io": "LinuxServer.io", "themoviedb.org": "TMDB (film and TV data)", "tmdb.org": "TMDB (film and TV data)",
    "thetvdb.com": "TheTVDB", "musicbrainz.org": "MusicBrainz", "tailscale.com": "Tailscale",
    "tailscale.io": "Tailscale", "hc-ping.com": "Healthchecks.io", "healthchecks.io": "Healthchecks.io",
    "duckdns.org": "Duck DNS", "icanhazip.com": "icanhazip (your public address)", "ipify.org": "ipify (your public address)",
    "debian.org": "Debian", "ubuntu.com": "Canonical (Ubuntu)", "pypi.org": "Python Package Index",
    "pythonhosted.org": "Python Package Index", "npmjs.org": "npm", "home-assistant.io": "Home Assistant",
    "nabucasa.com": "Home Assistant Cloud", "jellyfin.org": "Jellyfin", "plex.tv": "Plex", "ollama.com": "Ollama",
    "letsencrypt.org": "Let's Encrypt", "quad9.net": "Quad9 (DNS)", "cloudflare-dns.com": "Cloudflare (DNS)",
    "openai.com": "OpenAI", "anthropic.com": "Anthropic", "proxmox.com": "Proxmox",
}

# Known ad, tracking and viewing-data sites, flagged even with no DNS filter.
TRACKING_SITES = {
    "doubleclick.net", "googlesyndication.com", "app-measurement.com", "google-analytics.com",
    "googletagmanager.com", "amazon-adsystem.com", "samsungads.com", "samsungacr.com", "lgsmartad.com", "adgrx.com",
    "alphonso.tv", "samba.tv", "scorecardresearch.com", "branch.io", "adjust.com", "appsflyer.com",
    "facebook.net", "analytics-vendor.example", "viewing-data.example",
}

TIME_HINTS = ("time.", "ntp.", "pool.ntp.org", "time-", "clock.")

TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "co.kr", "com.br", "com.cn", "com.tw", "com.hk",
    "co.in", "net.in", "com.mx", "com.sg", "co.za", "com.tr",
}


# Names a home network keeps to itself: never a company on the internet.
LOCAL_SUFFIXES = (".lan", ".local", ".home", ".home.arpa", ".internal", ".localdomain", ".localhost", ".arpa")


def is_local_name(name):
    n = name.rstrip(".").lower()
    return "." not in n or n.endswith(LOCAL_SUFFIXES)


def site(name):
    """The registrable part of a name, roughly: cloud.vendor.com -> vendor.com."""
    labels = name.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-n:])


def company_for_site(s, extra=None):
    if extra and s in extra:
        return extra[s]
    if s in SITE_COMPANIES:
        return SITE_COMPANIES[s]
    return s


def is_tracking(s):
    return s in TRACKING_SITES


# Certificate checks (OCSP, CRL): a device asking whether a certificate is still valid. Routine,
# and says nothing about what the device does, so it doesn't count as another company.
CERT_SITES = {"digicert.com", "lencr.org", "sectigo.com", "globalsign.com", "usertrust.com", "pki.goog",
              "amazontrust.com", "entrust.net", "comodoca.com", "verisign.com", "identrust.com"}


def is_cert_check(name):
    n = name.rstrip(".").lower()
    return n.startswith(("ocsp.", "ocsp2.", "crl.", "crl3.", "crl4.")) or site(n) in CERT_SITES


def is_time_service(name):
    n = name.lower()
    return n.startswith(TIME_HINTS) or n.endswith("pool.ntp.org")


def flag(cc):
    """US -> the US flag emoji; anything else unusable -> ''."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def clean_asn_name(asn, desc):
    if asn in ASN_NAMES:
        return ASN_NAMES[asn]
    # "AMAZON-02 - Amazon.com, Inc." -> "Amazon.com, Inc."
    return desc.split(" - ", 1)[1].strip() if " - " in desc else desc.strip()


class Owners:
    """Who owns an address, from the iptoasn tables (IPv4 and IPv6). Thread-safe; loads in
    the background so the page works (without owners) before it's ready."""

    def __init__(self, folder, enabled=True, extra_ranges=None):
        # enabled=False (WL_OFFLINE=1): never download; company names then come
        # only from the built-in site list.
        self.path = os.path.join(folder, "ip2asn-v4-u32.tsv.gz")
        self.path6 = os.path.join(folder, "ip2asn-v6.tsv.gz")
        self.starts6, self.ends6, self.idx6 = [], [], []  # 128-bit ints: Python lists, not arrays
        self.enabled = enabled
        self.starts, self.ends, self.idx = array("I"), array("I"), array("I")
        self.names, self.ccs = [], []
        self.extra = []  # (network, name, cc) checked first: demo data, local overrides
        for net, name, cc in extra_ranges or []:
            self.extra.append((ipaddress.ip_network(net), name, cc))
        self.ready = False
        self.error = None
        self.lock = threading.Lock()

    def start(self):
        if self.enabled:
            threading.Thread(target=self._load, daemon=True).start()

    @staticmethod
    def _fetch_if_old(path, url, purpose):
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < ASN_MAX_AGE:
            return
        from .net import fetch
        body = fetch(url, purpose, timeout=120)
        tmp = path + ".part"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, path)

    def _load(self):
        try:
            self._fetch_if_old(self.path, ASN_URL, "Download the address-ownership list (iptoasn.com, monthly)")
            starts, ends, idx, names, ccs, seen = array("I"), array("I"), array("I"), [], [], {}
            with gzip.open(self.path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 5 or p[2] == "0":
                        continue
                    key = (int(p[2]), p[3])
                    if key not in seen:
                        seen[key] = len(names)
                        names.append(clean_asn_name(int(p[2]), p[4]))
                        ccs.append(p[3] if p[3] != "None" else "")
                    starts.append(int(p[0]))
                    ends.append(int(p[1]))
                    idx.append(seen[key])
            with self.lock:
                self.starts, self.ends, self.idx, self.names, self.ccs = starts, ends, idx, names, ccs
                self.ready, self.error = True, None
        except Exception as exc:  # no internet, disk full: the page still works without owners
            self.error = f"{type(exc).__name__}: {exc}"
            return
        try:
            self._fetch_if_old(self.path6, ASN6_URL, "Download the IPv6 address-ownership list (iptoasn.com, monthly)")
            starts6, ends6, idx6 = [], [], []
            with gzip.open(self.path6, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 5 or p[2] == "0":
                        continue
                    try:
                        lo, hi = int(ipaddress.IPv6Address(p[0])), int(ipaddress.IPv6Address(p[1]))
                    except ValueError:
                        continue
                    key = (int(p[2]), p[3])
                    with self.lock:  # names are shared with the IPv4 table
                        if key not in seen:
                            seen[key] = len(self.names)
                            self.names.append(clean_asn_name(int(p[2]), p[4]))
                            self.ccs.append(p[3] if p[3] != "None" else "")
                    starts6.append(lo)
                    ends6.append(hi)
                    idx6.append(seen[key])
            order = sorted(range(len(starts6)), key=starts6.__getitem__)  # lookups bisect on start
            with self.lock:
                self.starts6 = [starts6[i] for i in order]
                self.ends6 = [ends6[i] for i in order]
                self.idx6 = [idx6[i] for i in order]
        except Exception as exc:  # IPv4 owners still work
            self.error = f"IPv6 list: {type(exc).__name__}: {exc}"

    def lookup(self, addr):
        """(owner, country code) or ("", "")."""
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return "", ""
        for net, name, cc in self.extra:
            if ip.version == net.version and ip in net:
                return name, cc
        if not self.ready:
            return "", ""
        n = int(ip)
        with self.lock:
            starts, ends, idx = (self.starts, self.ends, self.idx) if ip.version == 4 else \
                (self.starts6, self.ends6, self.idx6)
            i = bisect.bisect_right(starts, n) - 1
            if i >= 0 and n <= ends[i]:
                j = idx[i]
                return self.names[j], self.ccs[j]
        return "", ""
