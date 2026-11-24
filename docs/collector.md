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

The project's own test setup runs a collector on a home server that, every hour and every 5 minutes, connects to a GL.iNet router over SSH with a key made for this alone, runs `grep` there for the devices being watched, and appends the matching lines to these files. Only those devices' lines leave the router. The script is short, uses only Python's standard library and `ssh`, and is a reasonable starting point for other routers running OpenWrt.
