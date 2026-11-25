#!/usr/bin/env python3
"""Build the live demo: the real page plus pre-made JSON from the demo data, as static
files that any static host (GitHub Pages) can serve. No server, nothing to install.

  python3 tools/build_demo.py --out site [--repo https://github.com/<owner>/<repo>]
"""
import argparse
import json
import os
import shutil
import sys
import urllib.parse
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from whatleaves import __version__, analysis  # noqa: E402
from whatleaves.enrich import Owners  # noqa: E402
from whatleaves.sources import DemoSource  # noqa: E402
from whatleaves.store import Store  # noqa: E402

STATIC = os.path.join(os.path.dirname(__file__), "..", "whatleaves", "static")


def file_for(client):
    """The same mapping the page uses: encodeURIComponent, with % made safe for a filename."""
    return urllib.parse.quote(client, safe="-_.!~*'()").replace("%", "~") + ".json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--repo", default="")
    args = ap.parse_args()
    out = args.out
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "api", "device"))

    store = Store(":memory:")
    DemoSource().poll(store)
    owners = Owners("/nonexistent", enabled=False, extra_ranges=DemoSource.OWNER_RANGES)
    names = DemoSource.SITE_NAMES
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def write(path, obj):
        with open(os.path.join(out, "api", path), "w") as f:
            json.dump(obj, f, separators=(",", ":"))

    overview = analysis.overview(store, owners, names)
    write("overview.json", overview)
    router = analysis.router_client(store)
    for d in overview["devices"] + overview["services"]:
        write(os.path.join("device", file_for(d["client"])), analysis.device_view(store, owners, d["client"], names, router=router))
    write("status.json", {"version": __version__, "source": "demo", "keep_days": 30, "poll_seconds": 300,
                          "offline": False, "auth": False, "configurable": False, "wizard_done": True,
                          "last_poll": now, "last_error": None, "adguard_url": "", "adguard_ui_port": ""})
    write("agent.json", {"token": "demo-token-not-real", "agents": [{"host": "homeserver", "services": 4, "last_seen": now}],
                         "suggestions": analysis.suggest_hosts(store)})
    write("app.json", {"status": {"version": __version__, "source": "demo", "keep_days": 30, "poll_seconds": 300,
                                  "offline": False, "auth": True},
                       "summary": [{"host": "iptoasn.com", "purpose": "Download the address-ownership list (iptoasn.com, monthly)",
                                    "local": 0, "calls": 1, "bytes": 9400000, "last": now, "failures": 0},
                                   {"host": "192.168.1.2", "purpose": "Read AdGuard Home's query log",
                                    "local": 1, "calls": 288, "bytes": 31200000, "last": now, "failures": 0}],
                       "calls": [{"time": now, "host": "192.168.1.2", "purpose": "Read AdGuard Home's query log",
                                  "bytes": 108000, "status": "200"}],
                       "owners": {"enabled": True, "ready": True, "error": None}})

    for name in os.listdir(STATIC):
        src = os.path.join(STATIC, name)
        if name != "index.html" and os.path.isfile(src):
            shutil.copy(src, out)
    with open(os.path.join(STATIC, "index.html")) as f:
        page = f.read()
    page = page.replace('<script src="app.js"></script>', '<script src="demo-mode.js"></script>\n<script src="app.js"></script>')
    with open(os.path.join(out, "index.html"), "w") as f:
        f.write(page)
    with open(os.path.join(out, "demo-mode.js"), "w") as f:
        f.write("window.WL_DEMO = " + json.dumps({"generated": now, "repo": args.repo}) + ";\n")
    with open(os.path.join(out, ".nojekyll"), "w"):
        pass
    n = len(os.listdir(os.path.join(out, "api", "device")))
    print(f"live demo built in {out}/: {n} device and service pages, generated {now}")


if __name__ == "__main__":
    main()
