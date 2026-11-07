//! SQLite schema (read by the Bun viewer in ../viewer), views and SQL helper functions.

use anyhow::{bail, Context, Result};
use rusqlite::functions::FunctionFlags;
use rusqlite::Connection;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::trackers;

/// Base tables. The viewer (viewer/db.ts, lan.ts, sites.ts, trace.ts) reads these; change both together.
const TABLES: &str = "
CREATE TABLE IF NOT EXISTS conn (
  process TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, samples INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (process, ip, port, proto)
);
CREATE TABLE IF NOT EXISTS ip_info (
  ip TEXT PRIMARY KEY, hostname TEXT, city TEXT, region TEXT, country TEXT,
  lat REAL, lon REAL, asn INTEGER, org TEXT
);
CREATE TABLE IF NOT EXISTS ip_name (
  ip TEXT NOT NULL, name TEXT NOT NULL, source TEXT NOT NULL, last_seen REAL NOT NULL,
  PRIMARY KEY (ip, name)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, process TEXT NOT NULL,
  ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS dns (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, client TEXT NOT NULL, qname TEXT NOT NULL,
  qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, answers TEXT, cached INTEGER NOT NULL, ms REAL
);
CREATE INDEX IF NOT EXISTS dns_ts ON dns (ts);
CREATE INDEX IF NOT EXISTS dns_client ON dns (client, ts);
CREATE TABLE IF NOT EXISTS devices (
  ip TEXT PRIMARY KEY, mac TEXT, label TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS conn_last_seen ON conn (last_seen);
CREATE TABLE IF NOT EXISTS blocks (
  pattern TEXT NOT NULL, device TEXT NOT NULL DEFAULT '*', source TEXT NOT NULL DEFAULT 'user',
  note TEXT, created REAL NOT NULL, PRIMARY KEY (pattern, device)
);
CREATE TABLE IF NOT EXISTS apps (
  process TEXT PRIMARY KEY, path TEXT, bundle_id TEXT, name TEXT, version TEXT, feed_url TEXT,
  first_seen REAL NOT NULL
);
";

/// Friendly view for analysis. Recreated on every open so changes here take effect.
const VIEWS: &str = "
DROP VIEW IF EXISTS connections;
CREATE VIEW connections AS
SELECT c.process AS app, c.ip, c.port, c.proto,
  (SELECT n.name FROM ip_name n WHERE n.ip = c.ip
     ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host,
  i.hostname AS rdns, i.org, i.asn, i.city, i.region, i.country, i.lat, i.lon,
  c.first_seen, c.last_seen, c.samples
FROM conn c LEFT JOIN ip_info i USING (ip);

DROP VIEW IF EXISTS opens;
CREATE VIEW opens AS
SELECT e.id, e.ts, e.process AS app, e.via, e.ip, e.port, e.proto, e.closed,
  CASE WHEN e.closed IS NOT NULL THEN e.closed - e.ts END AS duration,
  (SELECT n.name FROM ip_name n WHERE n.ip = e.ip
     ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host,
  i.org, i.city, i.region, i.country, i.lat, i.lon
FROM events e LEFT JOIN ip_info i USING (ip);

DROP VIEW IF EXISTS lookups;
CREATE VIEW lookups AS
SELECT d.id, d.ts, d.client, COALESCE(v.label, v.mac, d.client) AS device,
  d.qname, d.qtype, d.rcode, d.answers, d.cached, d.ms, d.blocked
FROM dns d LEFT JOIN devices v ON v.ip = d.client;
";

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// "90s", "15m", "1h", "7d", "2w" or "all" -> seconds (None for "all").
pub fn parse_window(s: &str) -> Result<Option<f64>> {
    let s = s.trim().to_ascii_lowercase();
    if s == "all" {
        return Ok(None);
    }
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().with_context(|| format!("bad duration {s:?}; try 30m, 1h, 7d or all"))?;
    let mult = match unit {
        "s" => 1.0,
        "m" | "" => 60.0,
        "h" => 3600.0,
        "d" => 86400.0,
        "w" => 604800.0,
        _ => bail!("bad duration unit in {s:?}; use s, m, h, d, w or all"),
    };
    Ok(Some(n * mult))
}

/// Unix timestamp for the start of a window like "1h" (0 for "all").
pub fn since_ts(window: &str) -> Result<f64> {
    Ok(parse_window(window)?.map_or(0.0, |secs| now() - secs))
}

/// Registrable-ish domain: "a.b.example.co.uk" -> "example.co.uk". Heuristic, no PSL.
pub fn base_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    const TWO_PART: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
        "com.br", "com.cn", "co.in", "co.kr", "com.mx", "com.tr", "co.za", "com.sg", "com.hk",
    ];
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host;
    }
    let last_two = labels[n - 2..].join(".");
    let keep = if TWO_PART.contains(&last_two.as_str()) { 3 } else { 2 };
    labels[n.saturating_sub(keep)..].join(".")
}

pub fn open(path: &Path, read_only: bool) -> Result<Connection> {
    if read_only && !path.exists() {
        bail!("no database at {}; start recording with `netlog record`", path.display());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(TABLES)?;
    migrate(&conn)?;
    conn.execute_batch(VIEWS)?;
    register_functions(&conn)?;
    if read_only {
        conn.pragma_update(None, "query_only", "ON")?;
    }
    Ok(conn)
}

/// Columns added after the first release; CREATE TABLE IF NOT EXISTS won't add them.
fn migrate(conn: &Connection) -> Result<()> {
    let has = |table: &str, col: &str| -> Result<bool> {
        let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let cols: Vec<String> = st.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
        Ok(cols.iter().any(|c| c == col))
    };
    if !has("events", "via")? {
        // The app the process was launched from (a terminal, an IDE), when it has one.
        conn.execute_batch("ALTER TABLE events ADD COLUMN via TEXT")?;
    }
    if !has("dns", "blocked")? {
        // The block pattern that refused a lookup (NULL = answered normally).
        conn.execute_batch("ALTER TABLE dns ADD COLUMN blocked TEXT")?;
    }
    if !has("events", "lport")? {
        // Local port, to match a FIN/RST back to its open; `closed` is when that happened.
        conn.execute_batch("ALTER TABLE events ADD COLUMN lport INTEGER; ALTER TABLE events ADD COLUMN closed REAL")?;
    }
    Ok(())
}

fn register_functions(conn: &Connection) -> Result<()> {
    let det = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("since", 1, FunctionFlags::SQLITE_UTF8, |ctx| {
        let w: String = ctx.get(0)?;
        since_ts(&w).map_err(|e| rusqlite::Error::UserFunctionError(e.into()))
    })?;
    conn.create_scalar_function("base_domain", 1, det, |ctx| {
        Ok(ctx.get::<Option<String>>(0)?.map(|h| base_domain(&h)))
    })?;
    conn.create_scalar_function("is_tracker", 1, det, |ctx| {
        Ok(ctx.get::<Option<String>>(0)?.is_some_and(|h| trackers::is_tracker(&h)))
    })?;
    conn.create_scalar_function("is_encrypted_dns", 3, det, |ctx| {
        let host: Option<String> = ctx.get(0)?;
        let ip: Option<String> = ctx.get(1)?;
        let port: i64 = ctx.get(2)?;
        Ok(trackers::is_encrypted_dns(host.as_deref(), ip.as_deref(), port))
    })?;
    conn.create_scalar_function("is_doh_probe", 1, det, |ctx| {
        Ok(ctx.get::<Option<String>>(0)?.is_some_and(|q| trackers::is_doh_probe(&q)))
    })?;
    Ok(())
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert_eq!(base_domain("a.b.example.com."), "example.com");
        assert_eq!(base_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(base_domain("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn windows() {
        assert_eq!(parse_window("90s").unwrap(), Some(90.0));
        assert_eq!(parse_window("1h").unwrap(), Some(3600.0));
        assert_eq!(parse_window("all").unwrap(), None);
        assert!(parse_window("5y").is_err());
    }
}
