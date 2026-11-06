//! `netlog record`: poll lsof for live connections, geolocate, and log hostnames.

use anyhow::{Context, Result};
use maxminddb::Reader;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::db;
use crate::sniff::{self, Event, Name, Open};

/// How long to wait after a connection opens before asking lsof which app owns it. lsof
/// takes ~35ms and a quick HTTPS request lives ~90ms, so this has to be short.
const ATTRIBUTE_AFTER: Duration = Duration::from_millis(20);
/// Minimum gap between lsof runs, so bursts of opens share one run instead of hogging CPU.
const MIN_LSOF_GAP: Duration = Duration::from_millis(60);

pub struct Options {
    pub interval: f64,
    pub sniff: bool,
}

/// One live socket from lsof.
#[derive(PartialEq, Eq, Hash)]
struct Conn {
    process: String,
    ip: String,
    port: u16,
    proto: String,
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))) // benchmarking
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let s = v6.segments();
                (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
            }
        },
    }
}

/// '1.2.3.4:443' or '[2001:db8::1]:443' -> (ip, port).
fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let ip: IpAddr = host.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    Some((ip, port.parse().ok()?))
}

/// Live outbound sockets, plus (proto, local port) -> process for attributing new opens.
type PortOwners = HashMap<(String, u16), String>;

fn poll_lsof() -> Result<(HashSet<Conn>, PortOwners)> {
    let out = Command::new("lsof").args(["-nP", "+c", "0", "-i", "-F", "pcPnT"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut conns = HashSet::new();
    let mut owners = PortOwners::new();
    let mut cmd = String::new();
    // Current file record: (proto, name, tcp state)
    let mut cur: Option<(String, String, String)> = None;

    let mut emit = |rec: Option<(String, String, String)>, cmd: &str| {
        let Some((proto, name, state)) = rec else { return };
        let Some((local, remote)) = name.split_once("->") else { return };
        if let Some((_, lport)) = parse_endpoint(local) {
            owners.insert((proto.clone(), lport), cmd.to_string());
        }
        if proto == "TCP" && state != "ESTABLISHED" && state != "SYN_SENT" {
            return;
        }
        if let Some((ip, port)) = parse_endpoint(remote) {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                v4 => v4,
            };
            if is_public(ip) {
                conns.insert(Conn { process: cmd.to_string(), ip: ip.to_string(), port, proto });
            }
        }
    };

    for line in text.lines() {
        let (tag, val) = match line.chars().next() {
            Some(t) => (t, &line[t.len_utf8()..]),
            None => continue,
        };
        match tag {
            'p' => emit(cur.take(), &cmd),
            'c' => cmd = val.to_string(),
            'f' => {
                emit(cur.take(), &cmd);
                cur = Some(Default::default());
            }
            'P' => if let Some(c) = cur.as_mut() { c.0 = val.to_string() },
            'n' => if let Some(c) = cur.as_mut() { c.1 = val.to_string() },
            'T' => {
                if let (Some(c), Some(st)) = (cur.as_mut(), val.strip_prefix("ST=")) {
                    c.2 = st.to_string();
                }
            }
            _ => {}
        }
    }
    emit(cur.take(), &cmd);
    drop(emit);
    Ok((conns, owners))
}

struct Geo {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

fn newest_db(dir: &Path, prefix: &str) -> Option<Reader<Vec<u8>>> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(prefix) && n.ends_with(".mmdb"))
        })
        .collect();
    files.sort();
    Reader::open_readfile(files.pop()?).ok()
}

#[derive(Default)]
struct GeoInfo {
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    asn: Option<i64>,
    org: Option<String>,
}

impl Geo {
    fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let get = |r: &Option<Reader<Vec<u8>>>| -> Option<Value> { r.as_ref()?.lookup(ip).ok()?.decode().ok()? };
        let en = |v: &Value| v.pointer("/names/en").and_then(Value::as_str).map(String::from);
        let mut g = GeoInfo::default();
        if let Some(c) = get(&self.city) {
            g.city = c.get("city").and_then(en);
            g.region = c.pointer("/subdivisions/0").and_then(en);
            g.country = c.get("country").and_then(en);
            g.lat = c.pointer("/location/latitude").and_then(Value::as_f64);
            g.lon = c.pointer("/location/longitude").and_then(Value::as_f64);
        }
        if let Some(a) = get(&self.asn) {
            g.asn = a.get("autonomous_system_number").and_then(Value::as_i64);
            g.org = a.get("autonomous_system_organization").and_then(Value::as_str).map(String::from);
        }
        g
    }
}

/// A few threads doing reverse DNS so slow lookups never stall polling.
fn spawn_rdns_pool(results: Sender<(String, String)>) -> Sender<String> {
    let (tx, rx) = mpsc::channel::<String>();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..6 {
        let (rx, results) = (rx.clone(), results.clone());
        std::thread::spawn(move || loop {
            let Ok(ip) = rx.lock().unwrap().recv() else { return };
            let host = ip.parse().ok().and_then(|a| dns_lookup::lookup_addr(&a).ok()).unwrap_or_default();
            let host = if host == ip { String::new() } else { host };
            let _ = results.send((ip, host));
        });
    }
    tx
}

pub fn run(db_path: &Path, data_dir: &Path, opts: Options) -> Result<()> {
    let conn = db::open(db_path, false)?;
    let geo = Geo { city: newest_db(data_dir, "dbip-city-lite"), asn: newest_db(data_dir, "dbip-asn-lite") };
    if geo.city.is_none() {
        eprintln!("warning: no DB-IP database in {}; run ../setup.sh for locations", data_dir.display());
    }

    let status = Arc::new(Mutex::new(if opts.sniff { "starting".to_string() } else { "off (--no-sniff)".to_string() }));
    // Keep `ev_tx` alive here even without sniffing, so recv_timeout waits instead of spinning.
    let (ev_tx, ev_rx) = mpsc::channel::<Event>();
    if opts.sniff {
        let (tx, status) = (ev_tx.clone(), status.clone());
        std::thread::spawn(move || sniff::run(tx, status));
    }
    let (rdns_tx, rdns_rx) = mpsc::channel();
    let mut st = State {
        conn,
        geo,
        known: HashSet::new(),
        rdns: spawn_rdns_pool(rdns_tx),
        rdns_results: rdns_rx,
        status,
        names: Vec::new(),
        opens: Vec::new(),
        recent: HashMap::new(),
    };
    st.known = st.conn.prepare("SELECT ip FROM ip_info")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    db::set_meta(&st.conn, "recorder", "netlog")?;
    eprintln!("netlog: recording to {} (poll every {}s, opens in real time)", db_path.display(), opts.interval);

    let interval = Duration::from_secs_f64(opts.interval);
    let mut next_poll = Instant::now();
    let mut first_open: Option<Instant> = None;
    let mut first_name: Option<Instant> = None;
    let mut last_poll = Instant::now() - MIN_LSOF_GAP;
    loop {
        // Full poll (lsof) when the interval is up or new opens need attributing;
        // a cheap write when only hostnames are waiting.
        let poll_at = first_open
            .map_or(next_poll, |t| (t + ATTRIBUTE_AFTER).max(last_poll + MIN_LSOF_GAP).min(next_poll));
        let flush_at = first_name.map_or(poll_at, |t| (t + Duration::from_millis(300)).min(poll_at));
        let now = Instant::now();
        if now >= flush_at {
            let full = now >= poll_at;
            if let Err(e) = st.tick(full) {
                eprintln!("poll failed: {e:#}");
            }
            first_name = None;
            if full {
                first_open = None;
                last_poll = now;
                next_poll = Instant::now() + interval;
            }
            continue;
        }
        match ev_rx.recv_timeout(flush_at - now) {
            Ok(Event::Name(n)) => {
                st.names.push(n);
                first_name.get_or_insert_with(Instant::now);
            }
            Ok(Event::Open(o)) => {
                if st.accept_open(&o) {
                    st.opens.push(o);
                    first_open.get_or_insert_with(Instant::now);
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }
    }
}

struct State {
    conn: Connection,
    geo: Geo,
    known: HashSet<String>,
    rdns: Sender<String>,
    rdns_results: Receiver<(String, String)>,
    status: Arc<Mutex<String>>,
    names: Vec<Name>,
    opens: Vec<Open>,
    /// (ip, local port, proto) -> when we last logged an open; QUIC repeats long headers.
    recent: HashMap<(IpAddr, u16, &'static str), Instant>,
}

impl State {
    fn accept_open(&mut self, o: &Open) -> bool {
        if !is_public(o.ip) {
            return false;
        }
        let now = Instant::now();
        if self.recent.len() > 5000 {
            self.recent.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
        }
        match self.recent.insert((o.ip, o.local_port, o.proto), now) {
            Some(prev) => now.duration_since(prev) > Duration::from_secs(30),
            None => true,
        }
    }

    fn tick(&mut self, full: bool) -> Result<()> {
        let now = db::now();
        let (live, owners) = if full { poll_lsof().context("running lsof")? } else { Default::default() };
        let State { conn, geo, known, rdns, rdns_results, status, names, opens, .. } = self;
        let tx = conn.unchecked_transaction()?;

        // Geolocate an IP the first time we see it, and queue a reverse-DNS lookup.
        let mut ensure_ip = |tx: &Connection, ip: &str| -> Result<()> {
            if known.insert(ip.to_string()) {
                let g = ip.parse().map(|a| geo.lookup(a)).unwrap_or_default();
                tx.execute(
                    "INSERT OR IGNORE INTO ip_info (ip, city, region, country, lat, lon, asn, org)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    (ip, g.city, g.region, g.country, g.lat, g.lon, g.asn, g.org),
                )?;
                let _ = rdns.send(ip.to_string());
            }
            Ok(())
        };

        for c in &live {
            tx.execute(
                "INSERT INTO conn VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
                 ON CONFLICT(process, ip, port, proto)
                 DO UPDATE SET last_seen = excluded.last_seen, samples = samples + 1",
                (&c.process, &c.ip, c.port, &c.proto, now),
            )?;
            ensure_ip(&tx, &c.ip)?;
        }
        for o in opens.drain(..) {
            // Connections that closed before lsof ran can't be attributed to an app.
            let process = owners
                .get(&(o.proto.to_string(), o.local_port))
                .cloned()
                .unwrap_or_else(|| "(unknown)".into());
            let ip = o.ip.to_string();
            tx.execute(
                "INSERT INTO events (ts, process, ip, port, proto) VALUES (?1, ?2, ?3, ?4, ?5)",
                (o.ts, &process, &ip, o.port, o.proto),
            )?;
            // Make sure short-lived connections still show up in `conn` (and on the map).
            tx.execute(
                "INSERT INTO conn VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
                 ON CONFLICT(process, ip, port, proto) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
                (&process, &ip, o.port, o.proto, o.ts),
            )?;
            ensure_ip(&tx, &ip)?;
        }
        for n in names.drain(..) {
            // SNI is what the app actually connected to; never downgrade it to a DNS guess.
            tx.execute(
                "INSERT INTO ip_name VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(ip, name) DO UPDATE SET last_seen = excluded.last_seen,
                   source = CASE WHEN ip_name.source = 'sni' THEN 'sni' ELSE excluded.source END",
                (&n.ip, &n.name, n.source, now),
            )?;
        }
        for (ip, host) in rdns_results.try_iter() {
            tx.execute("UPDATE ip_info SET hostname = ?1 WHERE ip = ?2", (host, ip))?;
        }
        if full {
            db::set_meta(&tx, "heartbeat", &now.to_string())?;
            db::set_meta(&tx, "sniffer", &status.lock().unwrap())?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(parse_endpoint("1.2.3.4:443"), Some(("1.2.3.4".parse().unwrap(), 443)));
        assert_eq!(parse_endpoint("[2606:4700::1]:443"), Some(("2606:4700::1".parse().unwrap(), 443)));
        assert_eq!(parse_endpoint("*:*"), None);
    }

    #[test]
    fn public_ips() {
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(!is_public("192.168.1.5".parse().unwrap()));
        assert!(!is_public("100.100.1.1".parse().unwrap()));
        assert!(!is_public("224.0.0.251".parse().unwrap()));
        assert!(is_public("2606:4700::1111".parse().unwrap()));
        assert!(!is_public("fe80::1".parse().unwrap()));
        assert!(!is_public("::ffff:10.0.0.1".parse().unwrap()));
    }
}
