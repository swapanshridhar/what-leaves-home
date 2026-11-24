# What Leaves Home

What Leaves Home shows what each device on your home network talks to on the internet: which names it looks up, which servers it connects to, and how much data it sends. It reads the logs you already have (AdGuard Home) and changes nothing on your network.

It runs on your own machine. Nothing is sent anywhere.

Status: early (0.1). Per-device grades are planned, not built yet.

## Try it in two minutes

You need Docker. On any machine on your network:

```bash
git clone <this repository's URL> what-leaves-home
cd what-leaves-home
docker compose up -d
```

Open `http://<that machine's address>:8080` in a browser. For example `http://192.168.1.10:8080`, or `http://localhost:8080` on the same machine.

With no settings it shows made-up demo devices, so you can see what the page does before connecting anything.

## See your own network

What Leaves Home reads AdGuard Home's query log through its web API.

1. Copy the example settings:

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and fill in three lines:

   ```
   WL_ADGUARD_URL=http://192.168.1.2:3000
   WL_ADGUARD_USER=your-adguard-username
   WL_ADGUARD_PASSWORD=your-adguard-password
   ```

   The URL is the address you open AdGuard Home's page at.

3. Restart it:

   ```bash
   docker compose up -d
   ```

The page fills in within a few minutes, then updates every 5 minutes. AdGuard Home usually keeps its own log for a limited time, so What Leaves Home keeps its own copy (30 days by default).

### Every device shows up as my router

This is the most common snag. Many home routers, Google Nest Wifi and Eero among them, hand out themselves as the DNS server and forward lookups to AdGuard. AdGuard then sees every lookup as coming from the router, and so does What Leaves Home.

Ways around it, easiest first:

- If your router lets you set the DNS server it hands out (DHCP settings), set it to AdGuard Home's address.
- Let AdGuard Home hand out addresses (Settings, DHCP settings) and turn off your router's DHCP, if the router allows that.
- Put the devices you want to watch behind a second router whose DHCP hands out AdGuard, or that runs AdGuard itself. A travel router works for a trial.

### AdGuard Home login is refused

Some routers ship their own build of AdGuard Home that only accepts the router's admin session, not a username and password (GL.iNet is one). In that case read its log files instead; see [docs/collector.md](docs/collector.md).

## Without Docker

Python 3.11 or newer, nothing to install:

```bash
WL_ADGUARD_URL=http://192.168.1.2:3000 WL_ADGUARD_USER=me WL_ADGUARD_PASSWORD=secret python3 -m whatleaves
```

or `WL_DEMO=1 python3 -m whatleaves` for the demo. It listens on port 8080 and keeps its data in `./data/`.

## Settings

All settings are environment variables, in `.env` when using Docker.

| Setting | What it does | Default |
|---|---|---|
| `WL_ADGUARD_URL` | AdGuard Home's address | |
| `WL_ADGUARD_USER`, `WL_ADGUARD_PASSWORD` | Its login. `WL_ADGUARD_PASSWORD_FILE` reads the password from a file instead | |
| `WL_FILES_DIR` | Read collector files from this folder instead of the API ([docs/collector.md](docs/collector.md)) | |
| `WL_DEMO` | `1` shows demo devices | on when nothing else is set |
| `WL_NAMES` | Friendly names, like `192.168.1.20=Living room TV,192.168.1.21=Speaker` | names AdGuard knows |
| `WL_CLIENTS` | Only these addresses, comma-separated | all |
| `WL_KEEP_DAYS` | Days of data to keep | 30 |
| `WL_POLL_SECONDS` | How often to read the source | 300 |
| `WL_PORT`, `WL_HOST` | Where to listen | 8080, all addresses |
| `WL_DB` | Database file | `/data/whatleaves.db` in Docker |

## What the page shows

For each device:

- **Sites**: the names it looked up, grouped by site (`cloud.vendor.com` and `api.vendor.com` are both `vendor.com`), with counts and when last seen. Lookups your AdGuard blocked are marked.
- **Connections**: the servers it actually connected to, the port, and the data sent and received. This needs a source that records connections, such as the collector in [docs/collector.md](docs/collector.md). AdGuard alone only knows lookups.
- **Flags**: blocked lookups, and connections to addresses the device never looked up. A device can connect to a fixed address without any DNS at all.

## Privacy

DNS logs are a record of what people and devices do. What Leaves Home:

- only reads; it changes nothing on your network or in AdGuard
- keeps its copy on the machine it runs on, for `WL_KEEP_DAYS` days
- keeps no access log and sends no telemetry
- has no login of its own. Keep it on your home network, or put it behind your own sign-in. Don't expose it to the internet.

If you only care about appliances, set `WL_CLIENTS` so it never stores phones' and laptops' lookups.

## Development

```bash
python3 -m unittest discover -s tests -t .
WL_DEMO=1 WL_DB=/tmp/wl.db python3 -m whatleaves
```

Standard library only. The page is `whatleaves/static/`, the summaries are `whatleaves/store.py`, the sources are `whatleaves/sources.py`.

## Planned

- A–F grade per device, with the reasons shown
- Recognising device types and known trackers
- Pi-hole as a source
