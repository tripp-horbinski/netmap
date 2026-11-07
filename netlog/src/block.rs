//! Block lists for the resolver: domains it refuses (NXDOMAIN) instead of forwarding, per
//! device or for everyone. Rules live in the `blocks` table so the viewer and the CLI share
//! them; the resolver reloads them every few seconds.
//!
//! A pattern matches a name and every name under it ("doubleclick.net" blocks
//! "stats.g.doubleclick.net"). The special pattern "@trackers" stands for netlog's built-in
//! tracker list. `device` is a client IP, or "*" for all devices.

use anyhow::{bail, Context, Result};
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};

use crate::{db, trackers};

pub const ALL: &str = "*";
pub const TRACKERS: &str = "@trackers";

#[derive(Default, Clone)]
pub struct Rules {
    /// device ("*" or ip) -> patterns
    by_device: HashMap<String, HashSet<String>>,
}

impl Rules {
    pub fn load(conn: &Connection) -> Result<Rules> {
        let mut st = conn.prepare("SELECT pattern, device FROM blocks")?;
        let mut by_device: HashMap<String, HashSet<String>> = HashMap::new();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (p, d) = row?;
            by_device.entry(d).or_default().insert(p.to_ascii_lowercase());
        }
        Ok(Rules { by_device })
    }

    pub fn is_empty(&self) -> bool {
        self.by_device.values().all(|s| s.is_empty())
    }

    /// The pattern that blocks `qname` for `device` ("local" for this machine), if any.
    pub fn matches(&self, qname: &str, device: &str) -> Option<String> {
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        for scope in [ALL, device] {
            let Some(pats) = self.by_device.get(scope) else { continue };
            if pats.contains(TRACKERS) && trackers::is_tracker(&name) {
                return Some(TRACKERS.to_string());
            }
            // walk up the labels: a.b.c.d -> b.c.d -> c.d -> d
            let mut rest = name.as_str();
            loop {
                if pats.contains(rest) {
                    return Some(rest.to_string());
                }
                match rest.split_once('.') {
                    Some((_, tail)) => rest = tail,
                    None => break,
                }
            }
        }
        None
    }
}

/// The NXDOMAIN reply for a query: same id and question, answer sections empty.
pub fn refusal(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut r = query.to_vec();
    r[2] = 0x81 | (query[2] & 0x01); // QR, RD as asked (opcode 0), AA/TC clear
    r[3] = 0x83;                      // RA, rcode 3 = NXDOMAIN
    r[6] = 0; r[7] = 0; r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0; // an/ns/ar counts
    // keep only the question section: header + the first question
    let mut pos = 12;
    while pos < r.len() && r[pos] != 0 {
        pos += r[pos] as usize + 1;
        if r[pos.min(r.len() - 1)] & 0xC0 == 0xC0 { pos += 1; break; }
    }
    pos += 1 + 4; // terminator + qtype + qclass
    r.truncate(pos.min(r.len()));
    r[4] = 0; r[5] = 1; // qdcount = 1
    Some(r)
}

pub fn add(conn: &Connection, pattern: &str, device: &str, source: &str, note: Option<&str>) -> Result<()> {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() || p.contains(char::is_whitespace) {
        bail!("bad pattern {pattern:?}");
    }
    conn.execute(
        "INSERT INTO blocks (pattern, device, source, note, created) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(pattern, device) DO UPDATE SET source = excluded.source, note = COALESCE(excluded.note, blocks.note)",
        (&p, device, source, note, db::now()),
    )?;
    Ok(())
}

pub fn remove(conn: &Connection, pattern: &str, device: &str) -> Result<usize> {
    Ok(conn.execute("DELETE FROM blocks WHERE pattern = ?1 AND device = ?2", (pattern.trim().to_ascii_lowercase(), device))?)
}

pub fn clear_source(conn: &Connection, source: &str) -> Result<usize> {
    Ok(conn.execute("DELETE FROM blocks WHERE source = ?1", [source])?)
}

/// Import a hosts-format or one-domain-per-line list (a URL or a file) under `source`.
/// Replaces that source's earlier rules. Returns how many domains were stored.
pub fn import(conn: &Connection, from: &str, source: &str) -> Result<usize> {
    let text = if from.starts_with("http://") || from.starts_with("https://") {
        let out = std::process::Command::new("curl").args(["-fsSL", "--max-time", "60", from]).output().context("running curl")?;
        if !out.status.success() {
            bail!("download failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        std::fs::read_to_string(from).with_context(|| format!("reading {from}"))?
    };
    let mut domains = HashSet::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("");
        // hosts format: "0.0.0.0 domain" / "127.0.0.1 domain"; otherwise a bare domain
        let candidates: Vec<&str> = if first.parse::<std::net::IpAddr>().is_ok() { words.collect() } else { vec![first] };
        for d in candidates {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if d == "localhost" || d == "localhost.localdomain" || d == "broadcasthost" || d.starts_with("ip6-") || !d.contains('.') {
                continue;
            }
            domains.insert(d);
        }
    }
    if domains.is_empty() {
        bail!("no domains found in {from}");
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM blocks WHERE source = ?1", [source])?;
    let now = db::now();
    let mut st = tx.prepare("INSERT OR IGNORE INTO blocks (pattern, device, source, note, created) VALUES (?1, '*', ?2, NULL, ?3)")?;
    for d in &domains {
        st.execute((d, source, now))?;
    }
    drop(st);
    tx.commit()?;
    Ok(domains.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(pairs: &[(&str, &str)]) -> Rules {
        let mut by_device: HashMap<String, HashSet<String>> = HashMap::new();
        for (p, d) in pairs { by_device.entry(d.to_string()).or_default().insert(p.to_string()); }
        Rules { by_device }
    }

    #[test]
    fn suffix_and_scope() {
        let r = rules(&[("doubleclick.net", "*"), ("example.com", "192.168.1.37"), (TRACKERS, "192.168.1.37")]);
        assert_eq!(r.matches("stats.g.doubleclick.net", "local").as_deref(), Some("doubleclick.net"));
        assert_eq!(r.matches("doubleclick.net.", "10.0.0.1").as_deref(), Some("doubleclick.net"));
        assert_eq!(r.matches("notdoubleclick.net", "local"), None);
        assert_eq!(r.matches("www.example.com", "192.168.1.37").as_deref(), Some("example.com"));
        assert_eq!(r.matches("www.example.com", "local"), None);
        assert_eq!(r.matches("www.google-analytics.com", "192.168.1.37").as_deref(), Some(TRACKERS));
        assert_eq!(r.matches("www.google-analytics.com", "local"), None);
    }

    #[test]
    fn nxdomain_reply_keeps_the_question() {
        // id 0xabcd, standard query, one question: example.com A IN
        let q: Vec<u8> = [0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7].iter().copied()
            .chain(*b"example").chain([3]).chain(*b"com").chain([0, 0, 1, 0, 1]).collect();
        let r = refusal(&q).unwrap();
        assert_eq!(&r[..2], &[0xab, 0xcd]);
        assert_eq!(r[2], 0x81);
        assert_eq!(r[3] & 0x0F, 3);
        assert_eq!(&r[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(r.len(), q.len());
    }
}
