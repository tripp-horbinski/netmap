# netmap

A live map of where this Mac's network connections go.

- Polls `lsof` every 2 s. No sudo needed; it sees every process running as your user.
- Geolocates IPs **offline** with the free DB-IP Lite databases, so your IPs aren't sent to a lookup service.
- Keeps history in `data/netmap.sqlite` so it builds up over time.

```sh
./setup.sh                      # venv + download DB-IP Lite (~150 MB)
.venv/bin/python netmap.py      # http://127.0.0.1:8765 (map only; the Bun viewer below has the full dashboard)
.venv/bin/python netmap.py --home 43.07,-89.40   # set your location by hand
```

## netlog (Rust CLI: recorder + analytics for people and AI agents)

```sh
cd netlog && cargo build --release && cd ..
netlog/target/release/netlog record &                 # records lsof + DNS/TLS hostnames
.venv/bin/python netmap.py --viewer                   # map only; netlog does the recording

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

## Bun viewer (optional replacement for `netmap.py --viewer`)

`viewer/` is the map server written for [Bun](https://bun.sh): it serves `static/`, reads
`data/netmap.sqlite` with `bun:sqlite`, and exposes the same `/api/data`, `/api/stream` and
`/api/reset` routes as the Python viewer plus the device, site and trace APIs below. `netlog record`
still does the recording.

Pages: `/` is the overview (opens per minute, destinations, LAN devices, tracker share, sites visited,
a mini world map, the live feed, and the top sites, devices, apps and networks for the chosen window);
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

`VIEWER=bun ./install-agents.sh` points the launchd viewer agent at the compiled binary instead of
Python; run `bun run build` first and rerun the script after rebuilding.

The Bun viewer also serves a LAN device dashboard at `/devices` (linked from the map): every device
the resolver has heard from, with lookups over time, domains, tracker lookups, and names it had
never asked for before the chosen window. Click a row to name a device; it's the same `label` that
`netlog name` sets. Behind it: `GET /api/devices?since=24h`, `GET /api/devices/IP?since=24h` and
`POST /api/devices/IP/name {"label": "..."}`. The tracker list and `base_domain()` are mirrored
from `netlog/src/trackers.rs` and `db.rs` in `viewer/trackers.ts`; change both together.

`/sites` is the dependency-trace view: what loading one website pulls in. A load is a burst of
new connections from one app (3 s of quiet or 20 s ends it, and a `www.` host of another site
starts a new one); the site is the first name in the burst that is not a tracker, browser
plumbing, a CDN or a bare IP, and everything else in the burst is attributed to it. The page shows
a waterfall of the richest recent load plus the hosts, companies and trackers across all loads.
Browsers only by default; `?apps=all` includes CLIs and daemons. The lists of plumbing and
never-a-root domains live in `viewer/sites.ts`. API: `GET /api/sites?since=24h`,
`GET /api/sites/DOMAIN?since=24h`. Known limits: connections a browser kept open from an earlier
visit never reappear, and a second site opened inside the gap without a `www.` host merges into the first.
Pin a host as a site from the page (or `POST /api/sites/known {"name": "tripp.horbin.ski"}`) when the
heuristics get it wrong; pinned sites live in netlog's `meta` table and always split out their own loads.

**Route traces** on the map: the *route* button in any destination popup runs the system
`traceroute` in ICMP mode (setuid on macOS, so no sudo; UDP probes die at AT&T) and draws the path
through every hop that geolocates, with the full hop list in the sidebar. Results cache for six
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

After rebuilding `netlog`, rerun `./install-agents.sh` to restart the services on the new binary.

## Whole-LAN visibility: the Mac as the house DNS server (interim, until an always-on box)

```sh
netlog/target/release/netlog resolve &        # logging DNS forwarder on port 53, no sudo needed
netlog/target/release/netlog report devices   # every device that has asked, with tracker counts
netlog/target/release/netlog name 192.168.1.37 "Living room TV"
netlog/target/release/netlog report device --device "Living room TV" --since 24h
```

Setup, once: give the Mac a DHCP reservation in the router (so its IP never changes), then set the
router's DHCP DNS server to the Mac's IP (currently 192.168.1.98) with the router itself or 1.1.1.1
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
