<p align="center"><img src="static/hazel.svg" width="96" alt=""></p>

# hazel

A live dashboard of where this Mac and the devices on the LAN are talking to, and who sees you.
hazel is the dashboard; `netlog` (the Rust recorder and CLI) and the `viewer/` server are the parts
underneath, and the repo keeps its original name, netmap.

- `netlog record` polls `lsof` every 2 s and sniffs DNS answers and TLS SNI for hostnames. No sudo
  needed; it sees every process running as your user.
- Geolocates IPs **offline** with the free DB-IP Lite databases, so your IPs aren't sent to a lookup service.
- Keeps history in `data/netmap.sqlite` so it builds up over time.
- The viewer (Bun) serves an overview, a world map, a LAN device dashboard and site dependency traces
  at http://127.0.0.1:8765. The pages make no outside requests: Leaflet 1.9.4 and the Natural Earth
  country shapes are vendored in `static/vendor`.

```sh
./setup.sh                                   # DB-IP Lite (~150 MB), cargo build, bun build
./install-agents.sh                          # launchd: recorder, resolver, viewer; start at login
open http://127.0.0.1:8765
```

## netlog (Rust CLI: recorder + analytics for people and AI agents)

```sh
cd netlog && cargo build --release && cd ..
netlog/target/release/netlog record &                 # records lsof + DNS/TLS hostnames

netlog/target/release/netlog status                   # is it running, how much data
netlog/target/release/netlog suggest                  # ranked findings + the command to dig in
netlog/target/release/netlog report                   # list reports: apps, domains, trackers, new, ...
netlog/target/release/netlog report app --app curl
netlog/target/release/netlog query "SELECT app, COUNT(DISTINCT ip) FROM connections GROUP BY app"
netlog/target/release/netlog tail                     # live log of connections as they open
netlog/target/release/netlog guide                    # instructions written for AI agents
```

Output is a table in a terminal and JSON when piped. Queries are read-only and can use
`since('1h')`, `base_domain(host)` and `is_tracker(host)`. A Claude Code skill in
`.claude/skills/netlog` tells Claude to use it.

## Viewer

`viewer/` is the web server, written for [Bun](https://bun.sh): it serves `static/`, reads
`data/netmap.sqlite` with `bun:sqlite`, and exposes `/api/data`, `/api/stream` and `/api/reset`
plus the device, site and trace APIs below. `netlog record` does the recording.

Pages: `/` is the overview: what changed against this network's own baseline, as a short list of
findings with evidence and an *Expect* button (an app reaching a company or tracker it never has, a
device or app far busier in an hour than its norm for that hour, a site pulling in a new third party,
a process making its first connection, the recorder or pktap being down), a what's-normal panel
(top apps, busy hours, devices, what you marked expected), a compact strip of counts with their change
against the prior window, opens per minute by app, a mini world map and the live feed. Findings need a
day of history before they fire; `GET /api/findings?since=24h`, `POST /api/findings/expect
{"key", "title", "expected"}`. Expected keys live in netlog's `meta` table;
`/map` is the full world map; `/devices` and `/sites` are below. All four share `static/app.css` and
`static/app.js` (top nav, light/dark theme that follows the system with a toggle, sparklines, tables).
The old `/#trace=IP` links redirect to `/map#trace=IP`.

```sh
cd viewer && bun install
bun run dev                                  # http://127.0.0.1:8765, restarts on edit
bun run server.ts --port 8766 --home 43.07,-89.40
bun test
bun run build                                # single binary: viewer/dist/netmap-viewer
./dist/netmap-viewer --root ..               # the binary needs --root (or cwd) = this checkout
```

`./install-agents.sh` runs the compiled binary under launchd; rerun it after `bun run build`.

`/devices` is the LAN device dashboard: every device
the resolver has heard from, with lookups over time, domains, tracker lookups, and names it had
never asked for before the chosen window. Click a row to name a device; it's the same `label` that
`netlog name` sets. The detail view includes a weekday-by-hour heatmap of lookups (local time) so a
device that phones home at 3 a.m. stands out (`heat` in the device JSON). Behind it: `GET /api/devices?since=24h`, `GET /api/devices/IP?since=24h` and
`POST /api/devices/IP/name {"label": "..."}`. The tracker list and `base_domain()` are mirrored
from `netlog/src/trackers.rs` and `db.rs` in `viewer/trackers.ts`; change both together.

`/sites` is the dependency-trace view: what loading one website pulls in. A load is a burst of
new connections from one app (3 s of quiet or 20 s ends it, and a `www.` host of another site
starts a new one); the site is the first name in the burst that is not a tracker, browser
plumbing, a CDN or a bare IP, and everything else in the burst is attributed to it. The page shows
a trace of the richest recent load (or any load you pick from the list) plus the hosts, companies and
trackers across all loads. With the extension the trace is a Gantt: every request as a bar from start
to finish, grouped by company, colored by what the host is to the site, with a time ruler, sizes and
status on hover, and a summary of when first-party work finished and how long trackers kept going.
Heuristic loads only know when each host first appeared, so they draw ticks instead of bars.
A site with exact loads also gets a report card: what a visit costs in requests and bytes, the
split by role (first party, update, telemetry, ads, CDN, other) by request count and by bytes, who
gets the bytes by company, request types, when the page's own work finished versus how long trackers
ran, and the trend across visits. `GET /api/sites/SITE/card?since=24h`. Bytes come from
Content-Length, so chunked responses count as 0.

The recorder gives every TCP connection the same treatment: it captures FIN and RST as well as SYN,
so `opens.closed` and `opens.duration` say how long each connection lived, and an app's report card
shows its recent connections as a Gantt with the typical lifetime per host class.
Browsers only by default; `?apps=all` includes CLIs and daemons. The lists of plumbing and
never-a-root domains live in `viewer/sites.ts`. API: `GET /api/sites?since=24h`,
`GET /api/sites/DOMAIN?since=24h`. Known limits: connections a browser kept open from an earlier
visit never reappear, and a second site opened inside the gap without a `www.` host merges into the first.
Pin a host as a site from the page (or `POST /api/sites/known {"name": "tripp.horbin.ski"}`) when the
heuristics get it wrong; pinned sites live in netlog's `meta` table and always split out their own loads.
A pinned site is named by its root host (tripp.horbin.ski); everything else by base domain.

With no site selected the page shows the dependency graph: the sites with the biggest third-party
footprint on the left, the companies serving those hosts on the right, one ribbon per pair, hover for
the host names, a table view behind the *Table* button. `GET /api/sites/graph?since=24h`.

`/apps` is the report card per app (helpers merged under the product name): bundle, version and
update feed, who launched it, opens over time, and every host it reached classified as first party
(from the bundle id and feed domain), update check, telemetry (crash and analytics vendors), ads
(the tracker list), CDN, or other, as a segmented bar and a table, with companies and countries.
`GET /api/apps/report?since=24h`, `GET /api/apps/report/NAME?since=24h`.

`/companies` is the rollup: every company (the network owner behind an IP, from DB-IP's ASN data)
ranked by reach, which is how many sites it appeared in, how many apps on this Mac connected to it,
and how many LAN devices resolved names to its addresses. A stacked bar per company shows the three,
with a table view; click one for the sites, apps, devices and hosts behind each number.
`GET /api/companies?since=24h`, `GET /api/companies/ORG?since=24h`.

## Blocking (the resolver as a gate)

`netlog resolve` refuses lookups on its block list with NXDOMAIN and logs the refusal with the
rule that fired (`lookups.blocked`). Rules are a domain (it and everything under it), scoped to one
device or to every device, kept in the `blocks` table that the CLI and the pages share; the resolver
picks up changes within 5 s. `@trackers` stands for netlog's built-in tracker list.

```sh
netlog/target/release/netlog block                      # the rules
netlog/target/release/netlog block add doubleclick.net   # every device
netlog/target/release/netlog block add @trackers --device 192.168.1.37
netlog/target/release/netlog block import https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts --source stevenblack
netlog/target/release/netlog block refused --since 24h   # what was refused, by device
```

On the pages, a *block* button sits beside hosts on the app and company pages, beside domains on a
device's page (scoped to that device), and beside findings about trackers on the overview; the
device page also lists what was refused and has one-click tracker blocking per device or for all.
`GET/POST/DELETE /api/blocks`, `GET /api/blocks/refused?since=24h`. Only devices that use this Mac
as their DNS are affected, and a device with its own DoH walks past it.

## Naming every connection's process (pktap, root)

`lsof` polling only sees connections that live longer than the poll and only processes running
as you, so one-shot update checks and Apple's daemons show as "(unknown)". macOS's `tcpdump`
can capture on the `pktap` pseudo-interface, where every packet carries its owning process, and
netlog uses that when it runs as root: the SYN or QUIC Initial names the connection on its first
packet, with the app a system proxy (`nsurlsessiond`) acted for when the kernel knows it.

```sh
sudo ./install-agents.sh        # recorder as a root LaunchDaemon; resolver and viewer stay yours
netlog/target/release/netlog status   # "pktap: on" once it is naming connections
```

The recorder hands the database files back to your user after each write, so the viewer keeps
working. `--no-pktap` turns it off. Without sudo everything works as before.

Either way, netlog now resolves each process to its app: executable path from the pid, then the
outermost `.app` bundle's Info.plist (name, bundle id, version, Sparkle update feed), stored in an
`apps` table and served at `GET /api/apps`. The pages show "Google Chrome" for every Chrome helper
and `releases.zentty.org` can be read back to Zentty's update check from its feed URL. A browser the recorder saw
started headless or under automation (`--headless`, `--remote-debugging-*`, `--enable-automation`:
a screenshot script, Playwright, a DevTools client) is recorded as a separate app, "Google Chrome
Helper (Aperitif) [headless]", shown as "Chrome (headless)", so it never blends into the browser
you use. Each open
also records `via`: the app the process was launched from, found by walking the parent chain to
the first different `.app` bundle, so `ssh` run in a terminal shows "ssh via Zentty" in the feeds
and `opens.via` in SQL (NULL for daemons and for processes gone before the lookup).

## Exact browser attribution (Chrome extension)

Chrome sends every tab's traffic through one Network Service process, so from outside the browser
`lsof` can only say "Google Chrome Helper": which tab, and therefore which site, is invisible. The
viewer shows helper processes under their product name (Chrome, Spotify, Claude) and the sites view
reconstructs sites from bursts, but that is a heuristic. `extension/` is a small Chrome extension
(Manifest V3, `webRequest` + `webNavigation`) that reports every request with the tab and the page
the tab was on to `POST /api/browser/requests` on localhost. Nothing leaves the machine; the rows
land in a `browser_requests` table in `data/netmap.sqlite`.

Install once: chrome://extensions, *Developer mode*, *Load unpacked*, pick `extension/`. From then on:

- `/sites` uses the reported loads for Chrome instead of the heuristic (marked *exact*; other
  browsers still use bursts), so a site's trace is what the tab really requested, with start and
  end times, type, status and size per request (`GET /api/sites/SITE/load/START`).
- The live feed and the map's feed show the page behind each Chrome connection
  ("Chrome · github.com → api.github.com"), including the ones `lsof` was too slow to name.
- `GET /api/browser/status` says how much has been reported. The endpoint is configurable on the
  extension's options page if the viewer runs on another port.

Countries on the map are shaded by how many destinations in the window sit inside them (one hue,
lighter to darker, legend in the sidebar, hover a shaded country for the count). The overview's mini
map shades the same way.

**Route traces** on the map: the *route* button in any destination popup runs the system
`traceroute` in ICMP mode (setuid on macOS, so no sudo; UDP probes die at AT&T) and draws the path
through every hop that geolocates, with the full hop list in the sidebar (each row's wash is its
round-trip time relative to the slowest hop). Results cache for six
hours in a `traces` table; *again* reruns. `GET /api/trace/IP[?fresh=1]`, or open the map at
`/map#trace=IP`. The probe gives up after six silent hops in a row. Hop locations are the DB-IP guess
for the block, which is often the carrier's regional hub rather than the router's city.

## Run it as a service

```sh
./install-agents.sh              # launchd agents: start at login, restart on crash
./install-agents.sh uninstall
launchctl list | grep -E "netlog|netmap"
tail -f ~/Library/Logs/netmap/*.log
```

After rebuilding `netlog` or the viewer, rerun `./install-agents.sh` to restart the services on the new binaries.

## Whole-LAN visibility: the Mac as the house DNS server (interim, until an always-on box)

```sh
netlog/target/release/netlog resolve &        # logging DNS forwarder on port 53, no sudo needed
netlog/target/release/netlog report devices   # every device that has asked, with tracker counts
netlog/target/release/netlog name 192.168.1.37 "Living room TV"
netlog/target/release/netlog report device --device "Living room TV" --since 24h
```

Setup, once: give the Mac a DHCP reservation in the router (so its IP never changes), then set the
router's DHCP DNS server to the Mac's IP (the devices page shows it) with the router itself or 1.1.1.1
as the secondary. Devices pick it up on their next DHCP renew; toggling Wi-Fi forces it.

Caveats: the secondary DNS means devices silently bypass the log sometimes, especially while the
Mac sleeps (`sudo pmset -c disablesleep 1` keeps it awake on power); any device using DoH or a
hardcoded DNS server never shows up; the log has names only, no bytes or app. When the always-on
box arrives, copy the binary and the SQLite file and change the one router setting.

Hostname capture needs BPF access (`brew install --cask wireshark` sets that up); without it,
run `netlog record --no-sniff`.

## Caveats

- **CDNs and anycast:** Cloudflare, Google and Akamai IPs geolocate to wherever the
  database says the block lives, often the company's HQ, not the server you're hitting.
  The org name is usually more telling than the dot on the map.
- **Hostnames** come from TLS handshakes (SNI) and DNS answers seen while recording.
  Connections opened before recording started only have reverse DNS (`lga25s71-in-f14.1e100.net`)
  until they reconnect.
- **System daemons** running as root aren't visible without sudo.
- **Real time:** `netlog record` sees each new TCP/QUIC connection the moment its first packet
  leaves, and the map animates it instantly. The app name comes from `lsof` ~20 ms later, so
  very short connections (well under ~60 ms) can show as `(unknown)`. Running `sudo netlog record`
  could use macOS `pktap` for exact per-packet app names (not built yet).

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0).
