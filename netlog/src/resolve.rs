//! `netlog resolve`: a logging DNS forwarder for the whole LAN.
//!
//! Point the router's DHCP DNS at this machine and every device's lookups come here,
//! get logged by client IP, and are forwarded upstream. Plain UDP and TCP on port 53,
//! with a small TTL-respecting cache. No root needed on macOS (Mojave and later).

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::block::{self, Rules};
use crate::db;
use crate::sniff::{be16, read_name};
use std::sync::RwLock;

pub struct Options {
    pub listen: String,
    pub upstreams: Vec<String>,
}

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CACHE_TTL: u64 = 300;
const NEGATIVE_TTL: u64 = 30;

/// One answered query, for the log.
struct Lookup {
    ts: f64,
    client: Option<IpAddr>, // None = this machine
    qname: String,
    qtype: u16,
    rcode: u8,
    answers: Vec<IpAddr>,
    cached: bool,
    ms: f64,
    /// The block pattern that refused it, if it was refused.
    blocked: Option<String>,
}

/// What we need from a DNS message: question, answer IPs, and the cache lifetime.
struct Parsed {
    qname: String,
    qtype: u16,
    rcode: u8,
    truncated: bool,
    answers: Vec<IpAddr>,
    min_ttl: Option<u64>,
}

fn parse(m: &[u8]) -> Option<Parsed> {
    let flags = be16(m, 2)?;
    let (qd, an) = (be16(m, 4)?, be16(m, 6)?);
    let mut pos = 12;
    let mut qname = String::new();
    let mut qtype = 0;
    for i in 0..qd {
        let (name, p) = read_name(m, pos)?;
        if i == 0 {
            qname = name;
            qtype = be16(m, p)? as u16;
        }
        pos = p + 4;
    }
    let mut answers = Vec::new();
    let mut min_ttl: Option<u64> = None;
    for _ in 0..an {
        let (_, p) = read_name(m, pos)?;
        let rtype = be16(m, p)?;
        let ttl = u32::from_be_bytes([*m.get(p + 4)?, *m.get(p + 5)?, *m.get(p + 6)?, *m.get(p + 7)?]) as u64;
        let rdlen = be16(m, p + 8)?;
        let rdata = m.get(p + 10..p + 10 + rdlen)?;
        pos = p + 10 + rdlen;
        min_ttl = Some(min_ttl.map_or(ttl, |t| t.min(ttl)));
        match (rtype, rdlen) {
            (1, 4) => answers.push(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?)),
            (28, 16) => answers.push(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?)),
            _ => {}
        }
    }
    Some(Parsed { qname, qtype, rcode: (flags & 0xF) as u8, truncated: flags & 0x200 != 0, answers, min_ttl })
}

struct Cache {
    entries: HashMap<(String, u16), (Instant, Vec<u8>)>,
}

impl Cache {
    fn get(&mut self, key: &(String, u16)) -> Option<Vec<u8>> {
        match self.entries.get(key) {
            Some((exp, resp)) if *exp > Instant::now() => Some(resp.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, key: (String, u16), ttl: u64, resp: Vec<u8>) {
        if self.entries.len() > 20_000 {
            let now = Instant::now();
            self.entries.retain(|_, (exp, _)| *exp > now);
        }
        self.entries.insert(key, (Instant::now() + Duration::from_secs(ttl), resp));
    }
}

/// Client value under which this machine's own lookups are logged, whatever network it's
/// on. The devices row for it is labelled with the computer name.
pub const LOCAL: &str = "local";

struct Resolver {
    upstreams: Vec<SocketAddr>,
    /// Every address of this machine's interfaces, refreshed as networks change. Lookups
    /// from any of them (or loopback) are logged as LOCAL, so the host is one device.
    local_ips: Arc<Mutex<HashSet<IpAddr>>>,
    cache: Mutex<Cache>,
    log: Sender<Lookup>,
    /// Block rules, reloaded from the database every few seconds.
    rules: Arc<RwLock<Rules>>,
}

impl Resolver {
    /// Answer one query (wire format in, wire format out). Works for UDP and TCP payloads.
    fn handle(&self, query: &[u8], client: IpAddr) -> Option<Vec<u8>> {
        let start = Instant::now();
        let client = if client.is_loopback() || self.local_ips.lock().unwrap().contains(&client) {
            None
        } else {
            Some(client)
        };
        let id = &query[..2.min(query.len())];
        let q = parse(query)?;
        let key = (q.qname.clone(), q.qtype);

        // Blocked for this device (or everyone): NXDOMAIN, logged with the rule that fired.
        let device = client.map_or_else(|| LOCAL.to_string(), |c| c.to_string());
        if let Some(pat) = self.rules.read().unwrap().matches(&q.qname, &device) {
            let resp = block::refusal(query)?;
            self.record_blocked(client, &q, pat, start);
            return Some(resp);
        }

        if let Some(mut resp) = self.cache.lock().unwrap().get(&key) {
            resp[..2].copy_from_slice(id);
            let p = parse(&resp)?;
            self.record(client, &q, p.rcode, p.answers, true, start);
            return Some(resp);
        }

        let resp = self.forward(query)?;
        let p = parse(&resp)?;
        if !p.truncated {
            let ttl = match (p.rcode, p.min_ttl) {
                (0, Some(t)) => t.clamp(1, MAX_CACHE_TTL),
                (0, None) | (3, _) => NEGATIVE_TTL,
                _ => 0,
            };
            if ttl > 0 {
                self.cache.lock().unwrap().put(key, ttl, resp.clone());
            }
        }
        self.record(client, &q, p.rcode, p.answers, false, start);
        Some(resp)
    }

    fn forward(&self, query: &[u8]) -> Option<Vec<u8>> {
        for up in &self.upstreams {
            let Ok(sock) = UdpSocket::bind(if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) else { continue };
            let _ = sock.set_read_timeout(Some(UPSTREAM_TIMEOUT));
            if sock.send_to(query, up).is_err() {
                continue;
            }
            let mut buf = vec![0u8; 4096];
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if n >= 12 && buf[..2] == query[..2] {
                    buf.truncate(n);
                    return Some(buf);
                }
            }
        }
        None
    }

    fn record(&self, client: Option<IpAddr>, q: &Parsed, rcode: u8, answers: Vec<IpAddr>, cached: bool, start: Instant) {
        let _ = self.log.send(Lookup {
            ts: db::now(),
            client,
            qname: q.qname.clone(),
            qtype: q.qtype,
            rcode,
            answers,
            cached,
            ms: start.elapsed().as_secs_f64() * 1000.0,
            blocked: None,
        });
    }

    fn record_blocked(&self, client: Option<IpAddr>, q: &Parsed, pattern: String, start: Instant) {
        let _ = self.log.send(Lookup {
            ts: db::now(), client, qname: q.qname.clone(), qtype: q.qtype, rcode: 3, answers: Vec::new(), cached: false,
            ms: start.elapsed().as_secs_f64() * 1000.0, blocked: Some(pattern),
        });
    }
}

/// Every 5 s: pick up block-list changes made by the CLI or the viewer.
fn rules_watcher(conn: Connection, rules: Arc<RwLock<Rules>>) {
    loop {
        std::thread::sleep(Duration::from_secs(5));
        if let Ok(r) = Rules::load(&conn) {
            *rules.write().unwrap() = r;
        }
    }
}

/// Batch log writes so a busy LAN doesn't mean a transaction per query.
fn writer(conn: Connection, rx: mpsc::Receiver<Lookup>) {
    loop {
        let Ok(first) = rx.recv() else { return };
        std::thread::sleep(Duration::from_millis(250));
        let batch: Vec<Lookup> = std::iter::once(first).chain(rx.try_iter()).collect();
        if let Err(e) = write_batch(&conn, &batch) {
            eprintln!("dns log write failed: {e:#}");
        }
    }
}

fn write_batch(conn: &Connection, batch: &[Lookup]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    for l in batch {
        let client = l.client.map_or_else(|| LOCAL.to_string(), |c| c.to_string());
        let answers = l.answers.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(" ");
        tx.execute(
            "INSERT INTO dns (ts, client, qname, qtype, rcode, answers, cached, ms, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (l.ts, &client, &l.qname, l.qtype, l.rcode, answers, l.cached, l.ms, &l.blocked),
        )?;
        for a in &l.answers {
            tx.execute(
                "INSERT INTO ip_name VALUES (?1, ?2, 'dns', ?3)
                 ON CONFLICT(ip, name) DO UPDATE SET last_seen = excluded.last_seen",
                (a.to_string(), &l.qname, l.ts),
            )?;
        }
        tx.execute(
            "INSERT INTO devices (ip, first_seen, last_seen) VALUES (?1, ?2, ?2)
             ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen",
            (&client, l.ts),
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// This machine's interface addresses, from ifconfig.
fn interface_ips() -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    if let Ok(out) = Command::new("ifconfig").output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut w = line.split_whitespace();
            if let (Some("inet" | "inet6"), Some(addr)) = (w.next(), w.next()) {
                if let Ok(ip) = addr.split('%').next().unwrap_or(addr).parse() {
                    ips.insert(ip);
                }
            }
        }
    }
    ips
}

fn computer_name() -> String {
    Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "This machine".into())
}

/// Every 30s: refresh this machine's addresses, and learn MACs for LAN devices from ARP.
fn arp_watcher(conn: Connection, local_ips: Arc<Mutex<HashSet<IpAddr>>>) {
    let _ = conn.execute(
        "INSERT INTO devices (ip, label, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(ip) DO UPDATE SET label = COALESCE(label, excluded.label)",
        (LOCAL, computer_name(), db::now()),
    );
    loop {
        *local_ips.lock().unwrap() = interface_ips();
        if let Ok(out) = Command::new("arp").args(["-a", "-n"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            let _ = (|| -> Result<()> {
                let tx = conn.unchecked_transaction()?;
                for line in text.lines() {
                    // "? (192.168.1.5) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]"
                    let Some(ip) = line.split('(').nth(1).and_then(|s| s.split(')').next()) else { continue };
                    let Some(mac) = line.split(" at ").nth(1).and_then(|s| s.split_whitespace().next()) else { continue };
                    if mac.starts_with("ff:") || mac.starts_with("1:0:5e") || mac == "(incomplete)" {
                        continue;
                    }
                    let mac: String = mac.split(':').map(|h| format!("{:0>2}", h)).collect::<Vec<_>>().join(":");
                    tx.execute("UPDATE devices SET mac = ?1 WHERE ip = ?2", (mac, ip))?;
                }
                tx.commit()?;
                Ok(())
            })();
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn serve_udp(sock: UdpSocket, r: Arc<Resolver>) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        if n < 12 {
            continue;
        }
        let (query, sock, r) = (buf[..n].to_vec(), sock.try_clone().unwrap(), r.clone());
        std::thread::spawn(move || {
            if let Some(resp) = r.handle(&query, from.ip()) {
                let _ = sock.send_to(&resp, from);
            }
        });
    }
}

fn serve_tcp(listener: TcpListener, r: Arc<Resolver>) {
    for stream in listener.incoming().flatten() {
        let r = r.clone();
        std::thread::spawn(move || {
            let _ = tcp_session(stream, &r);
        });
    }
}

fn tcp_session(mut s: TcpStream, r: &Resolver) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let client = s.peer_addr()?.ip();
    loop {
        let mut len = [0u8; 2];
        if s.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut query)?;
        if let Some(resp) = r.handle(&query, client) {
            s.write_all(&(resp.len() as u16).to_be_bytes())?;
            s.write_all(&resp)?;
        }
    }
}

pub fn run(db_path: &Path, opts: Options) -> Result<()> {
    let upstreams: Vec<SocketAddr> = opts
        .upstreams
        .iter()
        .map(|u| {
            let u = if u.contains(':') && !u.starts_with('[') && u.matches(':').count() == 1 { u.clone() } else { format!("{u}:53") };
            u.to_socket_addrs()?.next().with_context(|| format!("bad upstream {u}"))
        })
        .collect::<Result<_>>()?;

    let udp = UdpSocket::bind(&opts.listen).with_context(|| format!("binding UDP {}", opts.listen))?;
    let tcp = TcpListener::bind(&opts.listen).with_context(|| format!("binding TCP {}", opts.listen))?;

    let (log_tx, log_rx) = mpsc::channel();
    std::thread::spawn({
        let conn = db::open(db_path, false)?;
        move || writer(conn, log_rx)
    });
    let local_ips = Arc::new(Mutex::new(interface_ips()));
    std::thread::spawn({
        let conn = db::open(db_path, false)?;
        let local_ips = local_ips.clone();
        move || arp_watcher(conn, local_ips)
    });

    let rules = Arc::new(RwLock::new(Rules::load(&db::open(db_path, false)?)?));
    std::thread::spawn({
        let conn = db::open(db_path, false)?;
        let rules = rules.clone();
        move || rules_watcher(conn, rules)
    });
    let blocking = if rules.read().unwrap().is_empty() { String::new() } else { " · block list active".to_string() };
    let r = Arc::new(Resolver { upstreams, local_ips, cache: Mutex::new(Cache { entries: HashMap::new() }), log: log_tx, rules });
    eprintln!(
        "netlog resolve: listening on {} (UDP+TCP), forwarding to {}{} — set the router's DNS to this machine",
        opts.listen,
        opts.upstreams.join(", "),
        blocking
    );
    std::thread::spawn({
        let r = r.clone();
        move || serve_tcp(tcp, r)
    });
    serve_udp(udp, r);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_response() {
        // Response for "a.b" A with one answer 1.2.3.4, TTL 60.
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 1, 0, 1]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let p = parse(&m).unwrap();
        assert_eq!(p.qname, "a.b");
        assert_eq!(p.qtype, 1);
        assert_eq!(p.answers, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(p.min_ttl, Some(60));
        assert_eq!(p.rcode, 0);
        assert!(!p.truncated);
    }
}
