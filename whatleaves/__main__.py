"""Start What Leaves Home. Every setting is an environment variable (see README):

  WL_ADGUARD_URL        AdGuard Home address, e.g. http://192.168.1.2:3000
  WL_ADGUARD_USER       its username
  WL_ADGUARD_PASSWORD   its password (or WL_ADGUARD_PASSWORD_FILE)
  WL_FILES_DIR          read collector files from this folder instead
  WL_DEMO=1             show made-up devices (the default when nothing is set)
  WL_CLIENTS            only these client addresses, comma-separated
  WL_NAMES              friendly names: 192.168.1.20=TV,192.168.1.21=Speaker
  WL_KEEP_DAYS          how long to keep data (default 30)
  WL_POLL_SECONDS       how often to read the source (default 300)
  WL_DB                 database file (default ./data/whatleaves.db)
  WL_HOST, WL_PORT      where to listen (default 0.0.0.0:8080)
"""

import os
import sys
import threading
import time
import traceback
from datetime import datetime, timezone

from . import __version__
from .server import serve
from .sources import AdGuardSource, DemoSource, FilesSource
from .store import Store


def env(name, default=""):
    return os.environ.get(name, default).strip()


def pick_source():
    if env("WL_DEMO") == "1":
        return DemoSource()
    if env("WL_FILES_DIR"):
        return FilesSource(env("WL_FILES_DIR"))
    if env("WL_ADGUARD_URL"):
        password = env("WL_ADGUARD_PASSWORD")
        if env("WL_ADGUARD_PASSWORD_FILE"):
            password = open(env("WL_ADGUARD_PASSWORD_FILE")).read().strip()
        clients = [c.strip() for c in env("WL_CLIENTS").split(",") if c.strip()]
        return AdGuardSource(env("WL_ADGUARD_URL"), env("WL_ADGUARD_USER"), password, clients)
    return DemoSource()


def parse_names(text):
    pairs = (p.split("=", 1) for p in text.split(",") if "=" in p)
    return {k.strip(): v.strip() for k, v in pairs if k.strip()}


def main():
    db = env("WL_DB", os.path.join("data", "whatleaves.db"))
    os.makedirs(os.path.dirname(db) or ".", exist_ok=True)
    store = Store(db)
    source = pick_source()
    keep_days = int(env("WL_KEEP_DAYS", "30"))
    every = int(env("WL_POLL_SECONDS", "300"))
    store.set_names(parse_names(env("WL_NAMES")))
    status = {"version": __version__, "source": source.kind, "keep_days": keep_days,
              "poll_seconds": every, "last_poll": None, "last_error": None}

    def poll_forever():
        while True:
            try:
                added = source.poll(store)
                store.prune(keep_days)
                status.update(last_poll=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              last_error=None, last_added=added)
            except Exception as exc:
                status["last_error"] = f"{type(exc).__name__}: {exc}"
                traceback.print_exc()
            time.sleep(every)

    threading.Thread(target=poll_forever, daemon=True).start()
    host, port = env("WL_HOST", "0.0.0.0"), int(env("WL_PORT", "8080"))
    httpd = serve(store, status, host, port)
    print(f"What Leaves Home {__version__}: source {source.kind}, listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
