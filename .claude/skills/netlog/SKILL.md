---
name: netlog
description: Analyze where this Mac's network connections go and what every device on the home LAN looks up, through hazel (the dashboard at http://127.0.0.1:8765, repo netmap) and its `netlog` CLI. Which apps talk to which servers, companies, countries and trackers; what changed against the baseline (findings); what a site visit costs and who gets the bytes; what to block. Use when Tripp asks about his laptop's or LAN's network traffic, privacy, trackers, "what is X phoning home to", "why is Y on the network", wants a digest, or wants something blocked or allowed.
---

# netlog / hazel

Two doors to the same SQLite log (`data/netmap.sqlite`):

- **`netlog`** (Rust CLI): `/Users/tripp/git/netmap/netlog/target/release/netlog`. Raw and aggregate
  data, reports, SQL, live tail, block-list management. JSON when piped.
- **hazel viewer** (Bun, launchd, `http://127.0.0.1:8765`): the judged views. Everything the pages
  show is JSON under `/api/...`; use `curl -s`. If it is down, `launchctl list | grep netmap`.

## Workflow

1. `netlog status`: recorder running, pktap on, how much history. If the recorder is down say so;
   it is a root launchd daemon, restarted with `sudo ./install-agents.sh` in a real terminal (the
   agent cannot sudo).
2. **Findings first**: `curl -s 'http://127.0.0.1:8765/api/findings?since=24h'`. Ranked, with
   evidence, links, and `block` (a domain) when applicable. `baseline.days` < 1 means the detectors
   are still gated. Then `netlog suggest` for the CLI's own findings (hostname coverage, DoH bypass).
3. Follow the finding to its page's API: app → `/api/apps/report/NAME`, site →
   `/api/sites/SITE` and `/api/sites/SITE/card`, company → `/api/companies/ORG`, device →
   `/api/devices/IP`. Always with `?since=1h|24h|7d|all`.
4. For anything else: `netlog report NAME`, `netlog query "SQL"` (`netlog schema` for columns and
   helpers `since('1h')`, `base_domain(host)`, `is_tracker(host)`), `netlog tail --count N`.

## The viewer's JSON (all GET unless noted)

| Endpoint | What it answers |
|---|---|
| `/api/findings?since=` | what changed vs this network's own baseline; `expected_hidden`; `baseline` (top apps, busy hours, days of history) |
| `/api/findings/expect` POST `{key,title,expected}` | mark a finding normal (or undo); **confirm with Tripp first** |
| `/api/apps/report?since=` · `/api/apps/report/NAME` | app report cards: hosts classified first-party / update / telemetry / ads / cdn / other, companies, countries, launcher (`via`), recent connections with lifetimes |
| `/api/apps` | every process netlog resolved: bundle id, name, version, update feed, path |
| `/api/sites?since=` · `/api/sites/SITE` · `/api/sites/SITE/card` · `/api/sites/graph` | sites visited, what each pulls in (exact from the Chrome extension, else heuristic), the report card (bytes by role and company, own-work-done time, per-visit trend), the site→company graph |
| `/api/companies?since=` · `/api/companies/ORG` | who sees you: reach across sites, apps and LAN devices, with the lists behind each number |
| `/api/devices?since=` · `/api/devices/IP` | LAN devices by DNS: domains, trackers, new names, weekday×hour heatmap (`heat`) |
| `/api/blocks` GET · POST `{pattern,device?}` · DELETE | the resolver's block list; `/api/blocks/refused?since=` what it refused. **Blocking or unblocking needs Tripp's yes** |
| `/api/data` | the map's snapshot: every connection with app, host, org, place, `via` |
| `/api/browser/status` | whether the Chrome extension is reporting |

## Interpreting

- Names come from pktap (root): every TCP/QUIC connection is named on its first packet, system
  daemons included. `(unknown)` now means no process owned the packet at all.
- Process names are the kernel's; the viewer shows product names ("Google Chrome Helper (Aperitif)"
  → Chrome). ` [headless]` / ` [automated]` suffixes mark browsers started by scripts or Playwright;
  they are separate apps from the real browser on purpose. "2.1.319"-style names are Claude Code.
- `via` is the app a process was launched from (`gh via Claude Code 2.1.319 via Zentty`).
- `opens.closed` / `duration`: TCP lifetimes from FIN/RST. QUIC has no close.
- Company = network owner of the IP (ASN). A host on Google Cloud shows under Google LLC even if it
  is Datadog's; the host list is the truth.
- LAN views (`devices`, `lookups`, companies' device column) cover only devices that use this Mac as
  DNS, by name only; DoH on a device bypasses it.
- Site traces are exact only where the extension reported them (`exact: true`); bytes come from
  Content-Length, so chunked responses count 0.

## Acting

Reversible actions the APIs expose: expect a finding, block/allow a domain (per device or all), pin a
site, name a device. Propose with the evidence, apply only after Tripp agrees, then confirm from the
data (refused log, next findings). Never block from a single tracker hit without saying what else
that domain serves.

When reporting, separate what the data shows (host, app, counts, times) from interpretation, and
name the caveat that applies.
