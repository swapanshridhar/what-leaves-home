# Reading collector files instead of the API

Set `WL_FILES_DIR` to a folder and What Leaves Home reads JSON-lines files from it instead of calling AdGuard Home. Use this when:

- your AdGuard Home's API won't accept a login (some router builds, such as GL.iNet's, only accept the router's admin session), or
- you also want connections, not just lookups. AdGuard only knows lookups; a router's connection table knows what was actually connected.

Something else has to write the files. It can be a small script that copies them off a router every so often. What Leaves Home only reads them, picks up new lines as they appear, and remembers how far it got.

## Lookups: `*.jsonl`

One AdGuard Home query-log line per line, exactly as AdGuard writes its `querylog.json`. The fields used are:

| Field | Meaning |
|---|---|
| `T` | time, RFC 3339 |
| `IP` | the device's address |
| `QH` | the name looked up |
| `QT` | the record type, such as `A` |
| `Answer` | the DNS response, base64 |
| `Upstream` | the server that answered |
| `Result.IsFiltered` | true if AdGuard blocked it |

AdGuard Home writes this file only when the query log is set to be stored on disk (`querylog.file_enabled: true` in its config). Some router builds turn that off and keep the log in memory only.

## Connections: `conn-*.jsonl`

One sample of one open connection per line, for example from Linux's `/proc/net/nf_conntrack` on the router:

```json
{"t": "2026-11-24T22:59:37+00:00", "client": "192.168.1.20", "proto": "tcp", "dst": "203.0.113.10",
 "sport": 49156, "dport": 8883, "out_bytes": 9102, "in_bytes": 6635}
```

`out_bytes` and `in_bytes` are the totals so far for that connection, as a connection table reports them. Sample every few minutes. What Leaves Home takes the largest value seen for each connection, so repeated samples aren't double-counted.

## An example collector

[`tools/collect-openwrt.py`](../tools/collect-openwrt.py) writes both kinds of file for a router running OpenWrt, such as a GL.iNet router. Run `collect-openwrt.py dns` every hour and `collect-openwrt.py conn` every 5 minutes from cron or a systemd timer, on any machine that can reach the router over SSH. It connects with a key made for this alone and runs `grep` on the router for the devices you chose, so only their lines leave it. It uses only Python's standard library and `ssh`. Its settings are listed at the top of the file.

```sh
export WLC_ROUTER=192.168.1.1 WLC_KEY=$HOME/.ssh/wl_router WLC_KNOWN_HOSTS=$HOME/.ssh/wl_router_known_hosts
export WLC_CLIENTS=192.168.1.20,192.168.1.21 WLC_OUT=/srv/whatleaves-collector
python3 tools/collect-openwrt.py dns && python3 tools/collect-openwrt.py conn
```

Then set `WL_FILES_DIR` to the same folder.
