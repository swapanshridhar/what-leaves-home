# What Leaves Home

**See what every device in your home sends out.**

What Leaves Home shows what each device, and each app on your home servers, talks to on the internet: which companies, from which countries, how much data, and whether any of it is ads or tracking. It works on top of the AdGuard Home or Pi-hole you already run, changes nothing on your network, and keeps everything on your own machine.

Status: early (0.8). Grades are a first version: simple rules, always shown with their reasons.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png">
  <img alt="The overview: devices graded A to F, with the biggest finding first. Here a TV contacted a viewing-data service 400 times." src="docs/screenshots/overview.png">
</picture>

<sub>Screenshots are from the live demo, with made-up devices.</sub>

## What you get

- **A verdict per device, in plain words.** An A to F grade with the reasons ("Contacted ad or tracking services 400 times", "Every connection was encrypted", "Talks only to LG"), and the one finding worth looking at first.
- **Companies and countries, not IP addresses.** "LG, hosted on Amazon Web Services, US", with the exact names and addresses one click away. Destinations nothing looked up are still labelled by what they are ("Time server", "Encrypted messaging", "Tailscale relays").
- **What to do about it.** Ready-to-paste block rules for AdGuard Home or Pi-hole for the trackers that got through, plus a firmware or settings nudge where it fits. The overview gathers one block list for the whole home.
- **Your home servers, app by app.** A small agent on each server tells apart which container or service phones home to whom: Jellyfin, Home Assistant, the media apps, anything in Docker or systemd.
- **Honesty about itself.** A "This app" page lists every network request What Leaves Home makes. In normal use that's your DNS filter and one monthly download of a public address-ownership list. No telemetry, no update checks, nothing loaded from outside.
- **Set-up that ends in a result.** A first-run guide ends with "point one device here" and shows it on screen as soon as it arrives. It spots when your router is hiding your devices, and explains the fix for your kind of router.

## How it's different

There are good tools near this space. What Leaves Home is built to be the layer they leave out:

- **Not another DNS dashboard.** DNS filter dashboards list raw lookups; this turns them into verdicts, companies and next steps, on top of the filter you already trust. It doesn't replace your DNS server.
- **Your traffic stays home.** Some tools in this area send what they collect to a server elsewhere for analysis. This one keeps everything on your machine, and shows you its own traffic to prove it.
- **No hardware to buy.** It runs on any always-on machine you already have (a Raspberry Pi, a NAS, an old PC, Home Assistant's host), unlike the paid boxes that do similar things.
- **Self-hosted apps, not just gadgets.** Per-service visibility on your own servers is the part people usually piece together from command-line tools. Here it's one command per server and a page per app.
- **Honest about limits.** DNS-based tools can't see devices that use hard-coded or encrypted DNS, or devices hidden behind a router that answers DNS for everyone. The app says when that's happening, and the agent's connection data fills some of the gap.

**Try the live demo in your browser:** made-up devices, nothing to install. The link appears here once the project is published (it's built from `tools/build_demo.py` by `.github/workflows/pages.yml`).

## Try it in two minutes

You need Docker. On any always-on machine on your network (a Raspberry Pi, a NAS, an old PC):

```bash
git clone <this repository's URL> what-leaves-home
cd what-leaves-home
docker compose up -d
```

Open `http://<that machine's address>:8080`. The first visit asks you to create the login for the page. There is no default password; instead it asks for a one-time setup code, which you get with `docker logs whatleaves`, so nobody else on your network can claim the page before you do. Then a short guide asks how you want to start: connect your AdGuard Home, or look around the demo first. Either way it ends with **"Point one device here"**: the address to enter and the steps for your phone, laptop or TV, and it shows that device as soon as its first lookups arrive.

## The goal: every device on its own line

What Leaves Home is at its best when each device (the TV, the speaker, each phone) shows up separately. That happens when each device asks your DNS filter, AdGuard Home, directly. How you get there depends on your router.

### Don't have AdGuard Home yet? Install both together

```bash
docker compose -f compose.with-adguard.yaml up -d
```

1. Open `http://<this machine>:3000` and finish AdGuard Home's short setup. Keep its web page on port 3000 and DNS on port 53.
2. Point your network's DNS at this machine (next section).
3. Open `http://<this machine>:8080`.

What Leaves Home reads AdGuard's log file directly, so there's no second login to enter. AdGuard saves its log in batches, so the first results can take a little while (it writes after about a thousand lookups).

If port 53 is already in use on a Debian or Ubuntu machine, the system's own DNS stub is holding it. AdGuard's documentation describes the fix ("Docker: port 53 is in use"): turn off `DNSStubListener` in systemd-resolved.

### Already have AdGuard Home or Pi-hole? Connect it

On the page, click **Connect** (or Settings → Data source), choose AdGuard Home or Pi-hole, enter its address (the one you open its web page at) and its login, press **Test**, then **Save**. For Pi-hole 6, use an app password from Settings → Web interface / API. (Pi-hole 5 isn't supported.) The test also warns you when nearly every lookup comes from one address, your router.

Or put it in a file: `cp .env.example .env`, fill in `WL_ADGUARD_URL`, `WL_ADGUARD_USER` and `WL_ADGUARD_PASSWORD` (or `WL_PIHOLE_URL` and `WL_PIHOLE_PASSWORD`), and `docker compose up -d`. Pi-hole's log doesn't include the addresses it answered, so with Pi-hole, connections from the agent or collector are named less often.

Some routers ship their own build of AdGuard Home that only accepts the router's admin session (GL.iNet is one). Read its log file instead: see [docs/collector.md](docs/collector.md).

### Point your devices at AdGuard: best first

1. **Change the DNS your router hands out.** In your router's DHCP or LAN settings, set the DNS server to the AdGuard machine's address. Every device picks it up as it reconnects, and each shows up separately. Many standalone routers allow this, and OpenWrt, OPNsense, pfSense and UniFi always do.
2. **Set DNS on individual devices.** Phones, computers, most TVs and streaming boxes, and game consoles have a manual DNS setting. The app's **See each device separately** page gives the steps for each kind. Smart plugs, fans and appliances don't have one.
3. **A small helper router** (a travel router, about $30 to $120) gives a few appliances their own Wi-Fi with AdGuard as DNS.
4. **A router that hands out AdGuard**, for every device permanently.

### If you have Google Wifi, Nest Wifi or eero

These mesh systems always hand out *themselves* as the DNS server and forward lookups on. Setting a custom DNS server in their app (Google Home app → Wi-Fi → Settings → Advanced networking → DNS) only changes where the router forwards to. So AdGuard sees one client, the router, and What Leaves Home shows it as **"Everything behind your router"**: a whole-home view, but not device by device. The app spots this and opens the step-by-step guide.

To see devices separately with one of these:

- **No new hardware:** set DNS on the devices that matter most (option 2: phones, computers, TVs, consoles). Also give them the address for IPv6, or turn IPv6 off in the router's app, or some lookups still go through the router.
- **For appliances:** a helper travel router (option 3) for the ones near it.
- **For everything:** something else has to be the router (option 4). These meshes can't keep their extra points once they stop being the router: bridge mode works with a single unit only. So plan for access points that mesh in access-point mode, alongside the new router.

The whole-home view is the fallback while you decide. It's still useful for what the house as a whole talks to.

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
| `WL_PIHOLE_URL`, `WL_PIHOLE_PASSWORD` | Pi-hole 6 instead (app password). `WL_PIHOLE_PASSWORD_FILE` reads it from a file | |
| `WL_FILES_DIR` | Read collector files from this folder instead of the API ([docs/collector.md](docs/collector.md)) | |
| `WL_DEMO` | `1` shows demo devices | on when nothing else is set |
| `WL_NAMES` | Friendly names, like `192.168.1.20=Living room TV,192.168.1.21=Speaker` | names AdGuard knows |
| `WL_CLIENTS` | Only these addresses, comma-separated | all |
| `WL_USER`, `WL_PASSWORD` | Set the login in advance | created on the first visit, with the setup code from the log |
| `WL_AUTH` | `off` turns the login off (only behind your own sign-in; see Login) | on |
| `WL_ALLOWED_HOSTS` | Names you open the page by, if not an IP address, a one-word name (`raspberrypi`) or a `.local`, `.lan` or `.home.arpa` name. For example `whatleaves.example.org` | |
| `WL_TRUSTED_PROXIES` | Your reverse proxy's address, so the visitor address it passes on is believed | |
| `WL_OFFLINE` | `1`: never contact the internet (no ownership list) | off |
| `WL_INGEST_TOKEN` | The token agents send | made once, shown on the Services page |
| `WL_SCAN_TARGETS` | Private ranges to scan daily for listening services | off |
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
- **What you can do**: on each device or service page, concrete next steps, such as ready-to-paste AdGuard rules for its ad and tracking services, or a nudge to update firmware. The overview collects every rule your home needs in one block list.
- **Companies**: everyone your devices talk to, and which devices.
- **This app**: every network request What Leaves Home itself has made (see Privacy).

![A device page: why the TV got an F, the AdGuard rule to block its viewing-data service, and who it talks to by company and country.](docs/screenshots/device-tv.png)

![The This app page: every request What Leaves Home itself has made. In the demo, one download of the address-ownership list and reads of the local AdGuard.](docs/screenshots/this-app.png)

Connections and data volumes need a source that records them, such as the collector in [docs/collector.md](docs/collector.md). AdGuard alone only knows lookups.

### How grades work

Every device starts at 100. Points come off for: ad or tracking services (blocked by your filter, or on a built-in list), unencrypted web traffic to the internet, talking to companies other than its maker, connecting to addresses it never looked up, and uploading a lot. A is 90 and up and looks fine; B and C are worth a look; D and F are a concern. The reasons are always listed with the grade. This is a first version, and suggestions are welcome.

### Company names and countries

Names like `cloud.lgthinq.com` are matched to companies from a built-in list. Addresses are matched to the network that owns them using the free [iptoasn.com](https://iptoasn.com) table (public domain), downloaded once a month and kept on your machine. Nothing is looked up online per address. Set `WL_OFFLINE=1` to never download it.

## Services on your home servers

Every app on one server shares its address, so the DNS log alone can't tell Jellyfin from Home Assistant. A small agent fixes that. Open **Devices & services → Services**: it suggests which machines look like servers, with the evidence (what's listening there, whether it downloads container images, which service sites it looks up), and shows one command to run on each, with your address and token filled in:

```bash
# With Docker: the published agent image, pinned to this version
docker run -d --name whatleaves-agent --restart unless-stopped --network host --pid host --cap-add SYS_PTRACE \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -e WL_URL=http://<this app> -e WL_TOKEN=<token> \
  ghcr.io/swapanshridhar/what-leaves-home-agent:0.8.0

# Or as a system service (needs python3)
curl -fsSL --proto '=https' https://raw.githubusercontent.com/swapanshridhar/what-leaves-home/v0.8.0/whatleaves/static/install-agent.sh \
  | sudo WL_URL=http://<this app> WL_TOKEN=<token> sh
```

The agent reads the server's connection table and which program or container opened each connection, and sends that here every 5 minutes. It changes nothing; the system-service installer only turns on the kernel's per-connection byte counts and says so. Its code is one file, [whatleaves-agent.py](whatleaves/static/whatleaves-agent.py).

The agent runs as root, so its code never comes over plain HTTP. The installer comes from GitHub over HTTPS, pinned to a release. It runs the agent only if its SHA-256 matches the one written in the installer. The system service keeps only the permissions it needs to read connections. If you open What Leaves Home over HTTPS (behind your own reverse proxy), the commands fetch from it instead, with the same check. The token in the commands works like a password: if it leaks, make a new one on the Services page.

On a server whose kernel has no `/proc/net/nf_conntrack` (Raspberry Pi OS, for one), use the system service: it installs the `conntrack` tool, which the Docker image leaves out.

### Finding services by scanning (optional, off by default)

Set `WL_SCAN_TARGETS=192.168.1.0/24` and the app checks once a day for services listening on common ports, and reads their page titles. Only home ranges (10.x, 172.16–31.x, 192.168.x) up to 1024 addresses are accepted, and each scan is listed on the This app tab.

## Privacy

DNS logs are a record of what people and devices do. What Leaves Home:

- only reads; it changes nothing on your network or in AdGuard
- keeps its copy on the machine it runs on, for `WL_KEEP_DAYS` days
- keeps no access log, sends no telemetry and never checks for updates
- loads nothing from outside in your browser: no fonts, scripts or images from elsewhere
- records **every network request it makes itself** and shows them on the **This app** tab. In normal use that's AdGuard on your network and the monthly ownership list. With `WL_OFFLINE=1` it never contacts the internet at all.

### Login

The first visit creates the login. It asks for a one-time setup code that the app prints to its log (`docker logs whatleaves`), so only whoever installed it can create the login, not some other device on the network that gets there first. Set the login in advance with `WL_USER` and `WL_PASSWORD` instead, if you prefer. Change the password under Settings. Don't expose it to the internet.

Behind a reverse proxy, add the name you open it by to `WL_ALLOWED_HOSTS`. The page only answers to addresses, one-word names and home names (`.local`, `.lan`, `.home.arpa`) by default, so a web page elsewhere can't reach it by pointing its own domain at your network. If the proxy already handles sign-in (with SSO), you can turn the login off with `WL_AUTH=off`. Then publish the port on `127.0.0.1` only (`"127.0.0.1:8080:8080"` in compose.yaml), so nobody can go around the proxy to reach it.

The database holds the login, the agent token and any AdGuard or Pi-hole password saved from the page, and only the app's own user can read it.

If you only care about appliances, set `WL_CLIENTS` so it never stores phones' and laptops' lookups.

## Development

```bash
python3 -m unittest discover -s tests -t .
WL_DEMO=1 WL_DB=/tmp/wl.db python3 -m whatleaves
```

Standard library only. The page is `whatleaves/static/`; the grading is `whatleaves/analysis.py`; companies and countries are `whatleaves/enrich.py`; every outbound request goes through `whatleaves/net.py`, and a test checks that nothing else opens a connection.

## Planned

- Better grades: device types, known trackers per device type, DNS that bypasses your filter
- A ready-made image on GitHub's container registry (the workflow is in `.github/workflows/`)

## How this was built

I designed What Leaves Home and ran it on my own home network while building it. Most of the code was written with Claude, an AI coding assistant, working to my direction. Every change is covered by the tests in this repository. Before the first public release, a separate AI review focused on security, and its findings were fixed. Bug reports and questions are welcome either way.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
