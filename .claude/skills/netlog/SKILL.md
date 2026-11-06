---
name: netlog
description: Analyze where this Mac's network connections go, and what every device on the home LAN looks up (the Mac is the LAN's DNS server via `netlog resolve`): which apps talk to which servers, companies, countries and trackers, what changed recently, plain HTTP or odd ports. Use when Tripp asks about his laptop's network traffic, privacy, trackers, "what is X phoning home to", or wants analytics on the netmap/netlog data.
---

# netlog

`netlog` is a Rust CLI over a local SQLite log of this Mac's connections. Binary:
`/Users/tripp/git/netmap/netlog/target/release/netlog` (build with `cargo build --release` in `netlog/`).

1. Run `netlog guide` once for the data model and caveats.
2. Run `netlog status`. If the recorder isn't running, say so and suggest
   `netlog record` (it runs until stopped; start it in the background only if asked).
3. Run `netlog suggest` and follow the most relevant `run` commands.
4. For LAN questions (the TV, the thermostat, a phone) use `report devices`, `report lookups`,
   `report device --device X`; the `lookups` view has DNS names only, no app or bytes.
   Use `netlog report NAME` or `netlog query "SQL"` for follow-ups; `netlog schema` lists
   columns and helpers (`since('1h')`, `base_domain(host)`, `is_tracker(host)`).

Output is JSON when piped. Prefer aggregates over raw rows. When reporting, separate what the
data shows (host, app, counts) from interpretation, and mention the caveats that apply
(CDN geolocation is fuzzy; hostname coverage; missed short-lived and root-owned connections).
