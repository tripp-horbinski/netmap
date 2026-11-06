//! Built-in reports, the `suggest` heuristics, and self-description for agents.

use anyhow::{bail, Result};
use rusqlite::{Connection, ToSql};
use serde_json::{json, Value};

use crate::db;
use crate::output::{run_sql, Format, Table};

pub struct Report {
    pub name: &'static str,
    pub about: &'static str,
    pub sql: &'static str,
}

/// Every report takes :since (unix ts) and may use :app (NULL = all apps).
pub const REPORTS: &[Report] = &[
    Report {
        name: "apps",
        about: "Each app: how many IPs, domains and companies it talked to (name = resolved bundle)",
        sql: "SELECT app,
                     COALESCE(a.name || CASE WHEN a.version IS NOT NULL AND app = a.version THEN ' ' || a.version ELSE '' END, app) AS name,
                     COUNT(DISTINCT ip) AS ips, COUNT(DISTINCT base_domain(host)) AS domains,
                     COUNT(DISTINCT org) AS orgs, SUM(samples) AS samples,
                     datetime(MAX(last_seen), 'unixepoch', 'localtime') AS last_seen
              FROM connections LEFT JOIN apps a ON a.process = app
              WHERE last_seen >= :since AND (:app IS NULL OR app = :app)
              GROUP BY app ORDER BY ips DESC",
    },
    Report {
        name: "domains",
        about: "Domains contacted (from DNS/TLS names), with the apps that used them",
        sql: "SELECT base_domain(host) AS domain, COUNT(DISTINCT ip) AS ips,
                     GROUP_CONCAT(DISTINCT app) AS apps, MAX(is_tracker(host)) AS tracker
              FROM connections WHERE host IS NOT NULL AND last_seen >= :since
                AND (:app IS NULL OR app = :app)
              GROUP BY domain ORDER BY ips DESC",
    },
    Report {
        name: "orgs",
        about: "Networks/companies that own the IPs (ASN org), with apps",
        sql: "SELECT COALESCE(org, '(unknown)') AS org, COUNT(DISTINCT ip) AS ips,
                     COUNT(DISTINCT app) AS n_apps, GROUP_CONCAT(DISTINCT app) AS apps
              FROM connections WHERE last_seen >= :since AND (:app IS NULL OR app = :app)
              GROUP BY org ORDER BY ips DESC",
    },
    Report {
        name: "countries",
        about: "Countries the destination IPs geolocate to (CDNs make this fuzzy)",
        sql: "SELECT COALESCE(country, '(unknown)') AS country, COUNT(DISTINCT ip) AS ips,
                     GROUP_CONCAT(DISTINCT org) AS orgs
              FROM connections WHERE last_seen >= :since AND (:app IS NULL OR app = :app)
              GROUP BY country ORDER BY ips DESC",
    },
    Report {
        name: "new",
        about: "Destinations first seen in the window, newest first",
        sql: "SELECT datetime(MIN(first_seen), 'unixepoch', 'localtime') AS first_seen, app,
                     COALESCE(host, rdns, ip) AS dest, org, city, country
              FROM connections WHERE first_seen >= :since AND (:app IS NULL OR app = :app)
              GROUP BY app, ip ORDER BY MIN(first_seen) DESC",
    },
    Report {
        name: "opens",
        about: "Connection opens per app, caught in real time (includes short-lived ones)",
        sql: "SELECT app, COUNT(*) AS opens, COUNT(DISTINCT ip) AS ips,
                     COUNT(DISTINCT base_domain(host)) AS domains,
                     datetime(MAX(ts), 'unixepoch', 'localtime') AS last_open
              FROM opens WHERE ts >= :since AND (:app IS NULL OR app = :app)
              GROUP BY app ORDER BY opens DESC",
    },
    Report {
        name: "trackers",
        about: "Connections to known ad/analytics/tracking domains",
        sql: "SELECT app, base_domain(host) AS tracker, GROUP_CONCAT(DISTINCT host) AS hosts,
                     COUNT(DISTINCT ip) AS ips,
                     datetime(MAX(last_seen), 'unixepoch', 'localtime') AS last_seen
              FROM connections WHERE is_tracker(host) AND last_seen >= :since
                AND (:app IS NULL OR app = :app)
              GROUP BY app, tracker ORDER BY app, ips DESC",
    },
    Report {
        name: "ports",
        about: "Traffic on ports other than 443 (HTTPS), e.g. plain HTTP or odd services",
        sql: "SELECT port, proto, COUNT(DISTINCT ip) AS ips, GROUP_CONCAT(DISTINCT app) AS apps,
                     GROUP_CONCAT(DISTINCT COALESCE(host, org)) AS dests
              FROM connections WHERE port != 443 AND last_seen >= :since
                AND (:app IS NULL OR app = :app)
              GROUP BY port, proto ORDER BY ips DESC",
    },
    Report {
        name: "timeline",
        about: "New destinations and active apps per hour",
        sql: "SELECT strftime('%Y-%m-%d %H:00', first_seen, 'unixepoch', 'localtime') AS hour,
                     COUNT(DISTINCT ip) AS new_ips, COUNT(DISTINCT app) AS apps
              FROM connections WHERE first_seen >= :since AND (:app IS NULL OR app = :app)
              GROUP BY hour ORDER BY hour",
    },
    Report {
        name: "app",
        about: "Everything one app talked to (requires --app)",
        sql: "SELECT COALESCE(host, rdns, ip) AS dest, org, city, country, port, proto, samples,
                     datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
                     datetime(last_seen, 'unixepoch', 'localtime') AS last_seen
              FROM connections WHERE app = :app AND last_seen >= :since
              ORDER BY samples DESC",
    },
    Report {
        name: "devices",
        about: "LAN devices seen by the resolver: lookups, domains, trackers (needs `netlog resolve`)",
        sql: "SELECT device, client AS ip, COUNT(*) AS lookups, COUNT(DISTINCT base_domain(qname)) AS domains,
                     SUM(is_tracker(qname)) AS tracker_lookups,
                     datetime(MAX(ts), 'unixepoch', 'localtime') AS last_seen
              FROM lookups WHERE ts >= :since AND (:device IS NULL OR device = :device OR client = :device)
              GROUP BY client ORDER BY lookups DESC",
    },
    Report {
        name: "lookups",
        about: "Domains looked up across the LAN, with the devices asking (needs `netlog resolve`)",
        sql: "SELECT base_domain(qname) AS domain, COUNT(*) AS lookups, COUNT(DISTINCT client) AS n_devices,
                     GROUP_CONCAT(DISTINCT device) AS devices, MAX(is_tracker(qname)) AS tracker
              FROM lookups WHERE ts >= :since AND (:device IS NULL OR device = :device OR client = :device)
              GROUP BY domain ORDER BY lookups DESC",
    },
    Report {
        name: "device",
        about: "Everything one LAN device looked up (requires --device NAME-OR-IP)",
        sql: "SELECT qname, COUNT(*) AS lookups, is_tracker(qname) AS tracker,
                     datetime(MIN(ts), 'unixepoch', 'localtime') AS first,
                     datetime(MAX(ts), 'unixepoch', 'localtime') AS last
              FROM lookups WHERE ts >= :since AND (device = :device OR client = :device)
              GROUP BY qname ORDER BY lookups DESC",
    },
    Report {
        name: "unnamed",
        about: "Destinations with no DNS/TLS hostname (opened before recording, QUIC, or hardcoded IPs)",
        sql: "SELECT app, ip, rdns, org, port, samples FROM connections
              WHERE host IS NULL AND last_seen >= :since AND (:app IS NULL OR app = :app)
              ORDER BY samples DESC",
    },
];

pub fn list_reports() -> Table {
    Table {
        columns: vec!["report".into(), "about".into()],
        rows: REPORTS.iter().map(|r| vec![json!(r.name), json!(r.about)]).collect(),
        truncated: false,
    }
}

pub fn report(conn: &Connection, name: &str, since: &str, app: Option<&str>, device: Option<&str>, limit: usize) -> Result<Table> {
    let Some(r) = REPORTS.iter().find(|r| r.name == name) else {
        bail!("unknown report {name:?}; run `netlog report` to list them");
    };
    if r.name == "app" && app.is_none() {
        bail!("the app report needs --app NAME (see `netlog report apps` for names)");
    }
    if r.name == "device" && device.is_none() {
        bail!("the device report needs --device NAME-OR-IP (see `netlog report devices`)");
    }
    let ts = db::since_ts(since)?;
    let params: [(&str, &dyn ToSql); 3] = [(":since", &ts), (":app", &app), (":device", &device)];
    run_sql(conn, r.sql, &params, limit)
}

struct Finding {
    score: u32,
    kind: &'static str,
    finding: String,
    run: String,
}

fn scalar<T: rusqlite::types::FromSql>(conn: &Connection, sql: &str, since: f64) -> Result<T> {
    let mut stmt = conn.prepare(sql)?;
    if let Some(i) = stmt.parameter_index(":since")? {
        stmt.raw_bind_parameter(i, since)?;
    }
    let mut rows = stmt.raw_query();
    Ok(rows.next()?.expect("aggregate returns a row").get(0)?)
}

fn rows(conn: &Connection, sql: &str, since: f64) -> Result<Vec<Vec<Value>>> {
    Ok(run_sql(conn, sql, &[(":since", &since)], 1000)?.rows)
}

fn s(v: &Value) -> String {
    v.as_str().map(String::from).unwrap_or_else(|| v.to_string())
}

fn list(items: &[String], max: usize) -> String {
    let mut out = items.iter().take(max).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > max {
        out.push_str(&format!(", +{} more", items.len() - max));
    }
    out
}

/// Look at the data and rank analyses worth running. Each finding carries a command.
pub fn suggest(conn: &Connection, window: &str) -> Result<Table> {
    let since = db::since_ts(window)?;
    let now = db::now();
    let w = window;
    let mut out: Vec<Finding> = Vec::new();

    // Recorder health first: stale data makes every other finding misleading.
    let heartbeat: Option<f64> = db::get_meta(conn, "heartbeat").and_then(|v| v.parse().ok());
    let total: i64 = scalar(conn, "SELECT COUNT(*) FROM conn", since)?;
    match heartbeat {
        _ if total == 0 => out.push(Finding {
            score: 100, kind: "setup",
            finding: "No connections recorded yet".into(),
            run: "netlog record".into(),
        }),
        Some(hb) if now - hb > 120.0 => out.push(Finding {
            score: 95, kind: "setup",
            finding: format!("Recorder isn't running; last data {} ago", human_age(now - hb)),
            run: "netlog record".into(),
        }),
        None => out.push(Finding {
            score: 40, kind: "setup",
            finding: "No recorder heartbeat in the database; was this recorded by `netlog record`?".into(),
            run: "netlog status".into(),
        }),
        _ => {}
    }

    // Trackers, per app.
    for r in rows(conn,
        "SELECT app, GROUP_CONCAT(DISTINCT base_domain(host)) FROM connections
         WHERE is_tracker(host) AND last_seen >= :since GROUP BY app ORDER BY COUNT(DISTINCT host) DESC", since)?
    {
        let domains: Vec<String> = s(&r[1]).split(',').map(String::from).collect();
        out.push(Finding {
            score: 80 + domains.len().min(10) as u32,
            kind: "privacy",
            finding: format!("{} contacted {} tracking domain(s): {}", s(&r[0]), domains.len(), list(&domains, 4)),
            run: format!("netlog report trackers --since {w} --app {:?}", s(&r[0])),
        });
    }

    // LAN devices (from the resolver), if it's running.
    let devices: i64 = scalar(conn, "SELECT COUNT(*) FROM devices", since)?;
    if devices > 0 {
        for r in rows(conn,
            "SELECT device, client, COUNT(*) AS n, GROUP_CONCAT(DISTINCT base_domain(qname)) FROM lookups
             WHERE is_tracker(qname) AND ts >= :since GROUP BY client ORDER BY n DESC LIMIT 5", since)?
        {
            let domains: Vec<String> = s(&r[3]).split(',').map(String::from).collect();
            out.push(Finding {
                score: 70 + domains.len().min(10) as u32,
                kind: "privacy",
                finding: format!("Device {} made {} lookups of tracking domains: {}", s(&r[0]), s(&r[2]), list(&domains, 4)),
                run: format!("netlog report device --device {:?} --since {w}", s(&r[1])),
            });
        }
        for r in rows(conn,
            "SELECT device, client FROM lookups GROUP BY client HAVING MIN(ts) >= :since", now - 86400.0)?
        {
            out.push(Finding {
                score: 65, kind: "change",
                finding: format!("New device on the LAN in the last 24h: {}", s(&r[0])),
                run: format!("netlog report device --device {:?} --since 24h", s(&r[1])),
            });
        }
        let unlabeled: i64 = scalar(conn, "SELECT COUNT(*) FROM devices WHERE label IS NULL", since)?;
        if unlabeled > 0 {
            out.push(Finding {
                score: 25, kind: "setup",
                finding: format!("{unlabeled} LAN device(s) have no name yet; name them so reports read well"),
                run: "netlog report devices --since 7d   # then: netlog name <ip> \"Living room TV\"".into(),
            });
        }
    }

    // Encrypted DNS going around the resolver. On this Mac we see the connections themselves.
    let bypass = rows(conn,
        "SELECT COALESCE(host, ip) AS dest, SUM(port = 853) AS dot, SUM(port = 443) AS doh,
                GROUP_CONCAT(DISTINCT app) FROM opens
         WHERE ts >= :since AND is_encrypted_dns(host, ip, port)
         GROUP BY dest ORDER BY COUNT(*) DESC", since)?;
    if !bypass.is_empty() {
        let total: i64 = bypass.iter().map(|r| r[1].as_i64().unwrap_or(0) + r[2].as_i64().unwrap_or(0)).sum();
        let dests: Vec<String> = bypass.iter().map(|r| s(&r[0])).collect();
        let apps: Vec<String> = bypass.iter().flat_map(|r| s(&r[3]).split(',').map(String::from).collect::<Vec<_>>()).collect();
        out.push(Finding {
            score: 70,
            kind: "data-quality",
            finding: format!(
                "This Mac sent {total} encrypted-DNS connections (DoT/DoH) straight to {}; those lookups \
                 bypass the resolver log. Apps: {}. If the Mac lists a public DNS server as a fallback, \
                 macOS upgrades it to encrypted DNS; list only 127.0.0.1 to keep every lookup local.",
                list(&dests, 3), list(&apps, 3)),
            run: format!("netlog query \"SELECT app, COALESCE(host,ip) dest, port, COUNT(*) n FROM opens \
                 WHERE ts >= since('{w}') AND is_encrypted_dns(host, ip, port) GROUP BY 1,2,3 ORDER BY n DESC\""),
        });
    }
    // For LAN devices we only see DNS, so the signal is the discovery probes.
    for r in rows(conn,
        "SELECT device, client, COUNT(*) AS n, GROUP_CONCAT(DISTINCT base_domain(qname)) FROM lookups
         WHERE ts >= :since AND client != 'local' AND is_doh_probe(qname)
         GROUP BY client ORDER BY n DESC LIMIT 5", since)?
    {
        out.push(Finding {
            score: 45,
            kind: "data-quality",
            finding: format!(
                "Device {} looked up encrypted-DNS endpoints {} times ({}); it may be sending later \
                 lookups there directly, so its row here is a lower bound",
                s(&r[0]), s(&r[2]), s(&r[3])),
            run: format!("netlog report device --device {:?} --since {w}", s(&r[1])),
        });
    }

    // Plain HTTP: readable by anyone on the network path.
    for r in rows(conn,
        "SELECT app, GROUP_CONCAT(DISTINCT COALESCE(host, org, ip)) FROM connections
         WHERE port = 80 AND proto = 'TCP' AND last_seen >= :since GROUP BY app", since)?
    {
        out.push(Finding {
            score: 75, kind: "security",
            finding: format!("{} used unencrypted HTTP (port 80) to {}", s(&r[0]), s(&r[1])),
            run: format!("netlog report app --app {:?} --since {w}", s(&r[0])),
        });
    }

    // Non-browser apps that talk to many different companies.
    for r in rows(conn,
        "SELECT app, COUNT(DISTINCT org) AS n, GROUP_CONCAT(DISTINCT org) FROM connections
         WHERE last_seen >= :since AND org IS NOT NULL
           AND lower(app) NOT GLOB '*chrome*' AND lower(app) NOT GLOB '*safari*'
           AND lower(app) NOT GLOB '*firefox*' AND lower(app) NOT GLOB '*webkit*'
           AND lower(app) NOT GLOB '*brave*' AND lower(app) NOT GLOB '*arc*'
           AND lower(app) NOT GLOB '*edge*'
         GROUP BY app HAVING n >= 4 ORDER BY n DESC LIMIT 5", since)?
    {
        let orgs: Vec<String> = s(&r[2]).split(',').map(String::from).collect();
        out.push(Finding {
            score: 55 + orgs.len().min(20) as u32,
            kind: "privacy",
            finding: format!("{} (not a browser) talks to {} companies: {}", s(&r[0]), orgs.len(), list(&orgs, 4)),
            run: format!("netlog report app --app {:?} --since {w}", s(&r[0])),
        });
    }

    // Brand-new networks in the last hour, if there's older history to compare against.
    let oldest: Option<f64> = scalar(conn, "SELECT MIN(first_seen) FROM conn", since)?;
    if oldest.is_some_and(|o| now - o > 2.0 * 3600.0) {
        let fresh = rows(conn,
            "SELECT org FROM connections WHERE org IS NOT NULL GROUP BY org
             HAVING MIN(first_seen) >= :since ORDER BY MIN(first_seen) DESC", now - 3600.0)?;
        if !fresh.is_empty() {
            let orgs: Vec<String> = fresh.iter().map(|r| s(&r[0])).collect();
            out.push(Finding {
                score: 60, kind: "change",
                finding: format!("{} network(s) never seen before appeared in the last hour: {}", orgs.len(), list(&orgs, 4)),
                run: "netlog report new --since 1h".into(),
            });
        }
    }

    // Unusual ports (beyond web, mail, DNS-over-TLS, push, STUN/WebRTC).
    let odd = rows(conn,
        "SELECT DISTINCT port || '/' || proto FROM connections WHERE last_seen >= :since
           AND port NOT IN (443, 80, 53, 853, 993, 995, 465, 587, 5223, 5228, 22, 3478, 3479, 3480, 3481)
           AND port NOT BETWEEN 19302 AND 19309", since)?;
    if !odd.is_empty() {
        let ports: Vec<String> = odd.iter().map(|r| s(&r[0])).collect();
        out.push(Finding {
            score: 50, kind: "security",
            finding: format!("Traffic on {} unusual port(s): {}", ports.len(), list(&ports, 6)),
            run: format!("netlog report ports --since {w}"),
        });
    }

    // Geography.
    let countries = rows(conn,
        "SELECT country FROM connections WHERE last_seen >= :since AND country IS NOT NULL
         GROUP BY country ORDER BY COUNT(DISTINCT ip) DESC", since)?;
    if countries.len() > 1 {
        let names: Vec<String> = countries.iter().skip(1).map(|r| s(&r[0])).collect();
        out.push(Finding {
            score: 35, kind: "geography",
            finding: format!("Besides {}, traffic went to {}", s(&countries[0][0]), list(&names, 5)),
            run: format!("netlog report countries --since {w}"),
        });
    }

    // Chattiest app overall: a good starting point for a deep dive.
    if let Some(r) = rows(conn,
        "SELECT app, COUNT(DISTINCT base_domain(COALESCE(host, rdns, ip))) AS n FROM connections
         WHERE last_seen >= :since GROUP BY app ORDER BY n DESC LIMIT 1", since)?.first()
    {
        out.push(Finding {
            score: 30, kind: "overview",
            finding: format!("{} is the chattiest app ({} destinations)", s(&r[0]), s(&r[1])),
            run: format!("netlog report app --app {:?} --since {w}", s(&r[0])),
        });
    }

    // Name coverage: low coverage means host-based analyses undercount.
    let (named, all): (i64, i64) = conn.query_row(
        "SELECT COUNT(DISTINCT CASE WHEN host IS NOT NULL THEN ip END), COUNT(DISTINCT ip)
         FROM connections WHERE last_seen >= ?1", [since], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if all > 0 && (named as f64) < 0.6 * all as f64 {
        out.push(Finding {
            score: 20, kind: "data-quality",
            finding: format!(
                "Only {named} of {all} destinations have hostnames; domain/tracker reports undercount. \
                 Names come from new DNS/TLS handshakes, so coverage grows the longer `netlog record` runs."),
            run: format!("netlog report unnamed --since {w}"),
        });
    }

    out.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(Table {
        columns: vec!["score".into(), "kind".into(), "finding".into(), "run".into()],
        rows: out.into_iter().map(|f| vec![json!(f.score), json!(f.kind), json!(f.finding), json!(f.run)]).collect(),
        truncated: false,
    })
}

fn human_age(secs: f64) -> String {
    match secs {
        s if s < 120.0 => format!("{s:.0}s"),
        s if s < 7200.0 => format!("{:.0}m", s / 60.0),
        s if s < 172800.0 => format!("{:.0}h", s / 3600.0),
        s => format!("{:.0}d", s / 86400.0),
    }
}

pub fn status(conn: &Connection) -> Result<Table> {
    let now = db::now();
    let (rows, ips, apps, first, last): (i64, i64, i64, Option<f64>, Option<f64>) = conn.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT process), MIN(first_seen), MAX(last_seen) FROM conn",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    let names: i64 = conn.query_row("SELECT COUNT(*) FROM ip_name", [], |r| r.get(0))?;
    let hb: Option<f64> = db::get_meta(conn, "heartbeat").and_then(|v| v.parse().ok());
    let recorder = match hb {
        Some(h) if now - h < 30.0 => "running".to_string(),
        Some(h) => format!("stopped ({} ago)", human_age(now - h)),
        None => "never run (start with `netlog record`)".into(),
    };
    let kv = |k: &str, v: Value| vec![json!(k), v];
    Ok(Table {
        columns: vec!["key".into(), "value".into()],
        rows: vec![
            kv("recorder", json!(recorder)),
            kv("sniffer", json!(db::get_meta(conn, "sniffer"))),
            kv("pktap", json!(db::get_meta(conn, "pktap"))),
            kv("connections", json!(rows)),
            kv("distinct_ips", json!(ips)),
            kv("apps", json!(apps)),
            kv("hostnames_learned", json!(names)),
            kv("history", json!(first.map(|f| human_age(now - f)))),
            kv("last_activity", json!(last.map(|l| format!("{} ago", human_age(now - l))))),
        ],
        truncated: false,
    })
}

pub fn schema(format: Format) {
    let doc = json!({
        "connections (view — use this)": {
            "app": "process name (e.g. 'Google Chrome Helper', 'Slack Helper'; Claude Code shows as its version, e.g. '2.1.318')",
            "ip": "remote IP", "port": "remote port", "proto": "TCP or UDP",
            "host": "hostname the app asked for, from TLS SNI or DNS answers; NULL if unknown",
            "rdns": "reverse-DNS name of the IP (often a CDN machine name)",
            "org": "company/network owning the IP (ASN org, e.g. 'Google LLC')", "asn": "AS number",
            "city": "geolocated city (CDN/anycast IPs are fuzzy)", "region": "state/province",
            "country": "country", "lat": "latitude", "lon": "longitude",
            "first_seen": "unix seconds, first poll that saw this (app, ip, port, proto)",
            "last_seen": "unix seconds, most recent poll that saw it",
            "samples": "how many 2-second polls saw it open (≈ seconds open / 2)"
        },
        "opens (view — every connection open, in real time)": {
            "id": "increasing event id", "ts": "unix seconds the connection's first packet was seen",
            "app": "process, from lsof ~150ms after the open; '(unknown)' if it closed first",
            "ip": "remote IP", "port": "remote port", "proto": "TCP or UDP (QUIC)",
            "host": "hostname, as in connections", "org": "ASN org", "city": "city", "region": "region",
            "country": "country", "lat": "latitude", "lon": "longitude"
        },
        "lookups (view — every DNS query from every LAN device; needs `netlog resolve`)": {
            "ts": "unix seconds", "client": "device IP, or 'local' for the machine running the resolver", "device": "label, else MAC, else IP",
            "qname": "name asked for", "qtype": "1=A, 28=AAAA, 65=HTTPS, 12=PTR ...",
            "rcode": "0=ok, 3=NXDOMAIN", "answers": "space-separated IPs", "cached": "1 if served from cache",
            "ms": "time to answer"
        },
        "tables": {
            "conn": "raw connections keyed by (process, ip, port, proto)",
            "ip_info": "per-IP geolocation, ASN org and reverse DNS",
            "ip_name": "every hostname learned for an IP: (ip, name, source 'sni'|'dns', last_seen)",
            "meta": "recorder heartbeat and sniffer status",
            "events": "raw connection opens behind the opens view",
            "dns": "raw resolver log behind the lookups view",
            "devices": "LAN devices: ip, mac, label (set with `netlog name`), first/last seen"
        },
        "functions": {
            "since('1h')": "unix ts for the start of a window: 90s, 15m, 1h, 7d, 2w or all",
            "base_domain(host)": "'a.b.example.co.uk' -> 'example.co.uk'",
            "is_tracker(host)": "1 if host is a known ad/analytics/tracking domain",
            "is_encrypted_dns(host, ip, port)": "1 if the connection is DoT (853) or DoH to a known public resolver",
            "is_doh_probe(qname)": "1 if the lookup is a device discovering encrypted DNS (resolver.arpa, DoH hosts)",
            "datetime(ts, 'unixepoch', 'localtime')": "format a timestamp (built into SQLite)"
        },
        "examples": [
            "SELECT app, COUNT(DISTINCT ip) FROM connections WHERE last_seen >= since('1h') GROUP BY app ORDER BY 2 DESC",
            "SELECT base_domain(host) d, GROUP_CONCAT(DISTINCT app) FROM connections WHERE is_tracker(host) GROUP BY d",
            "SELECT app, host, org FROM connections WHERE country != 'United States' AND last_seen >= since('24h')",
            "SELECT strftime('%H', first_seen, 'unixepoch', 'localtime') hr, COUNT(DISTINCT ip) FROM connections GROUP BY hr"
        ]
    });
    if format.resolve() == Format::Json {
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        return;
    }
    for (section, body) in doc.as_object().unwrap() {
        println!("{section}");
        match body {
            Value::Object(m) => m.iter().for_each(|(k, v)| println!("  {k:<40} {}", s(v))),
            Value::Array(a) => a.iter().for_each(|v| println!("  {}", s(v))),
            _ => {}
        }
        println!();
    }
}

pub const GUIDE: &str = r#"# netlog guide for AI agents

netlog records which servers this Mac's apps connect to (every 2s via lsof), with
hostnames (from DNS answers and TLS SNI), owning company (ASN) and rough location.
Everything is local SQLite; queries are read-only.

## Scope
Two sources. `connections`/`opens` cover THIS Mac with per-app detail. `lookups`/`devices` cover
every device on the LAN by DNS name only (the Mac is the LAN's DNS server via `netlog resolve`),
with no app, no byte counts, and nothing from devices that use their own DNS (DoH, hardcoded 8.8.8.8).

## Workflow
1. `netlog status`     Is the recorder running? How much history is there?
2. `netlog suggest`    Ranked findings, each with a `run` command to dig in. Start here.
3. `netlog report`     List canned reports; `netlog report NAME --since 24h [--app APP] [--device D]`.
                       LAN reports: devices, lookups, device.
4. `netlog schema`     Columns, helper functions and example SQL for the `connections` view.
5. `netlog query SQL`  Anything else. Read-only; aggregate rather than dumping rows.
6. `netlog tail`       Live stream of connection opens (JSON lines when piped). Runs until
                       killed, so use `--count N` to stop after N opens.

Output is JSON when piped (your case) and a table in a terminal; force with `-f json|table|csv`.
Windows: --since 90s|15m|1h|24h|7d|all. Default 24h.

## Interpreting results
- `host` is the best evidence of what an app meant to reach. `rdns` and `org` describe the
  server, which for CDNs (Cloudflare, Akamai, Fastly, Google) is shared by many sites.
- City/country of CDN IPs is approximate; don't claim data "went to Montreal" from one row.
- `samples` counts 2-second polls, so samples*2 ≈ seconds a connection stayed open.
- `opens` is the real-time log: every new TCP/QUIC connection as it starts, including ones
  too short-lived for the 2s poll. `(unknown)` app = closed before it could be attributed.
- Short-lived connections between polls are missed, and root-owned system daemons are invisible.
- Low hostname coverage (see suggest) means tracker/domain counts are lower bounds.
- Encrypted DNS (DoT/DoH) goes around the resolver: `suggest` flags it; `lookups` undercounts
  any device doing it. On macOS, listing a public DNS server as fallback triggers this.
- Process names are truncated by macOS in places; "2.1.318"-style names are Claude Code.

## Good questions to answer
- Which apps phone home to trackers, and how often?
- What does app X talk to in the background when I'm not using it? (compare hours via timeline)
- What changed in the last hour? (`report new --since 1h`)
- Is anything using plain HTTP or unusual ports?
"#;

/// Stream connection opens as they happen. Each open is held ~1s so its hostname
/// (from the TLS handshake right after it) has time to arrive.
pub fn tail(conn: &Connection, app: Option<&str>, last: usize, count: Option<usize>, format: Format) -> Result<()> {
    use std::io::Write;
    let json_lines = format.resolve() == Format::Json;
    let max: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
    let mut after = (max - last as i64).max(0);
    let mut printed = 0usize;
    let mut stmt = conn.prepare(
        "SELECT id, ts, strftime('%H:%M:%f', ts, 'unixepoch', 'localtime'), app,
                COALESCE(host, ip), port, proto, org, city, country
         FROM opens WHERE id > ?1 ORDER BY id LIMIT 500",
    )?;
    if !json_lines {
        eprintln!("watching connection opens… (Ctrl-C to stop)");
    }
    let mut out = std::io::stdout().lock();
    loop {
        let cutoff = db::now() - 1.0;
        let mut rows = stmt.query([after])?;
        while let Some(r) = rows.next()? {
            if r.get::<_, f64>(1)? > cutoff {
                break; // too fresh; its hostname may not be in yet
            }
            after = r.get(0)?;
            let a: String = r.get(3)?;
            if app.is_some_and(|want| want != a) {
                continue;
            }
            let (time, dest, port, proto): (String, String, i64, String) = (r.get(2)?, r.get(4)?, r.get(5)?, r.get(6)?);
            let (org, city, country): (Option<String>, Option<String>, Option<String>) = (r.get(7)?, r.get(8)?, r.get(9)?);
            if json_lines {
                let line = json!({ "id": after, "ts": r.get::<_, f64>(1)?, "app": a, "dest": dest,
                                   "port": port, "proto": proto, "org": org, "city": city, "country": country });
                writeln!(out, "{line}")?;
            } else {
                let place = [city, country].into_iter().flatten().collect::<Vec<_>>().join(", ");
                writeln!(out, "{time}  {a:<28.28}  → {dest}:{port}/{proto}  {}{}",
                    org.unwrap_or_default(), if place.is_empty() { String::new() } else { format!(" · {place}") })?;
            }
            out.flush()?;
            printed += 1;
            if count.is_some_and(|c| printed >= c) {
                return Ok(());
            }
        }
        drop(rows);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}
