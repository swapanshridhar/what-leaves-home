# What Leaves Home

What Leaves Home shows what each device on your home network talks to on the internet: which names it looks up, which servers it connects to, and how much data it sends. It reads the logs you already have (AdGuard Home) and changes nothing on your network.

It runs on your own machine. Nothing is sent anywhere.

Status: early (0.2). Grades are a first version: simple rules, always shown with their reasons.

## Try it in two minutes

You need Docker. On any machine on your network:

```bash
git clone <this repository's URL> what-leaves-home
cd what-leaves-home
docker compose up -d
```

Open `http://<that machine's address>:8080` in a browser. For example `http://192.168.1.10:8080`, or `http://localhost:8080` on the same machine.

The first visit asks you to create the login for the page (there is no default password). With no other settings it shows made-up demo devices, so you can see what it does before connecting anything.

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
| `WL_USER`, `WL_PASSWORD` | Set the login in advance | the first visitor creates it |
| `WL_AUTH` | `off` turns the login off (only behind your own sign-in) | on |
| `WL_OFFLINE` | `1`: never contact the internet (no ownership list) | off |
| `WL_KEEP_DAYS` | Days of data to keep | 30 |
| `WL_POLL_SECONDS` | How often to read the source | 300 |
| `WL_PORT`, `WL_HOST` | Where to listen | 8080, all addresses |
| `WL_DB` | Database file | `/data/whatleaves.db` in Docker |

## What the page shows

- **Overview**: how many devices look fine, are worth a look, or are a concern, the single biggest finding, a tile per device, and where your data goes by company.
- **Devices**: every device with its grade, searchable and filterable. Each device page has:
  - its grade (A to F) and **why**, in plain bullets, good points included
  - who it talks to, **by company and country** ("LG, hosted on Amazon Web Services, US"), with the exact names and addresses one click away
  - data sent and received, and a 24-hour activity chart
  - the raw lookups and connections under Technical details
- **Companies**: everyone your devices talk to, and which devices.
- **This app**: every network request What Leaves Home itself has made (see Privacy).

Connections and data volumes need a source that records them, such as the collector in [docs/collector.md](docs/collector.md). AdGuard alone only knows lookups.

### How grades work

Every device starts at 100. Points come off for: ad or tracking services (blocked by your filter, or on a built-in list), unencrypted web traffic to the internet, talking to companies other than its maker, connecting to addresses it never looked up, and uploading a lot. A is 90 and up and looks fine; B and C are worth a look; D and F are a concern. The reasons are always listed with the grade. This is a first version, and suggestions are welcome.

### Company names and countries

Names like `cloud.lgthinq.com` are matched to companies from a built-in list. Addresses are matched to the network that owns them using the free [iptoasn.com](https://iptoasn.com) table (public domain), downloaded once a month and kept on your machine. Nothing is looked up online per address. Set `WL_OFFLINE=1` to never download it.

## Privacy

DNS logs are a record of what people and devices do. What Leaves Home:

- only reads; it changes nothing on your network or in AdGuard
- keeps its copy on the machine it runs on, for `WL_KEEP_DAYS` days
- keeps no access log, sends no telemetry and never checks for updates
- loads nothing from outside in your browser: no fonts, scripts or images from elsewhere
- records **every network request it makes itself** and shows them on the **This app** tab. In normal use that's AdGuard on your network and the monthly ownership list. With `WL_OFFLINE=1` it never contacts the internet at all.

### Login

The first person to open the page creates the login, the way Home Assistant and Uptime Kuma do. Set it in advance with `WL_USER` and `WL_PASSWORD` instead, if you prefer. Change the password under Settings. If something in front of it already handles sign-in (a reverse proxy with SSO), turn the login off with `WL_AUTH=off`. Either way, don't expose it to the internet.

If you only care about appliances, set `WL_CLIENTS` so it never stores phones' and laptops' lookups.

## Development

```bash
python3 -m unittest discover -s tests -t .
WL_DEMO=1 WL_DB=/tmp/wl.db python3 -m whatleaves
```

Standard library only. The page is `whatleaves/static/`; the grading is `whatleaves/analysis.py`; companies and countries are `whatleaves/enrich.py`; every outbound request goes through `whatleaves/net.py`, and a test checks that nothing else opens a connection.

## Planned

- Better grades: device types, known trackers per device type, DNS that bypasses your filter
- Pi-hole as a source
- A ready-made image on GitHub's container registry (the workflow is in `.github/workflows/`)
