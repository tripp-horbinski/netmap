//! Learn hostnames passively from DNS answers and TLS SNI.
//!
//! Runs `tcpdump -w -` (needs BPF access; the Wireshark cask's ChmodBPF grants it)
//! and parses the raw pcap stream, so it doesn't depend on tcpdump's text output.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// DNS responses; outbound HTTPS segments big enough to carry a ClientHello (skips bare
/// ACKs); every TCP SYN (new connection); and QUIC long-header packets (new HTTP/3
/// connections). The ip6[...] offsets assume no IPv6 extension headers, which is the norm.
const FILTER: &str = "udp src port 53 \
    or (tcp dst port 443 and greater 100) \
    or (ip and tcp[13] & 0x12 = 2) \
    or (ip6 and ip6[6] = 6 and ip6[53] & 0x12 = 2) \
    or (ip and udp dst port 443 and udp[8] & 0x80 != 0) \
    or (ip6 and ip6[6] = 17 and udp dst port 443 and ip6[48] & 0x80 != 0)";

pub struct Name {
    pub ip: String,
    pub name: String,
    pub source: &'static str, // "dns" or "sni"
}

/// An outbound connection being opened, seen on the wire the moment it starts.
pub struct Open {
    pub ts: f64,
    pub ip: IpAddr,
    pub port: u16,
    pub local_port: u16,
    pub proto: &'static str, // "TCP" or "UDP"
}

pub enum Event {
    Name(Name),
    Open(Open),
}

pub fn default_interface() -> String {
    let out = Command::new("route").args(["-n", "get", "default"]).output();
    out.ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("interface:").map(|i| i.trim().to_string()))
        })
        .unwrap_or_else(|| "en0".into())
}

/// Capture forever, restarting when tcpdump exits (e.g. the network interface changed).
pub fn run(tx: Sender<Event>, status: Arc<Mutex<String>>) {
    loop {
        let iface = default_interface();
        let msg = match capture(&iface, &tx, &status) {
            Ok(()) => "tcpdump stopped; retrying".to_string(),
            Err(e) => format!("off ({e})"),
        };
        *status.lock().unwrap() = msg;
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn capture(iface: &str, tx: &Sender<Event>, status: &Mutex<String>) -> Result<(), String> {
    let mut child = Command::new("tcpdump")
        .args(["-i", iface, "-n", "-U", "--immediate-mode", "-s", "0", "-w", "-", FILTER])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("can't run tcpdump: {e}"))?;
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut hdr = [0u8; 24];
    if r.read_exact(&mut hdr).is_err() {
        let mut err = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        let _ = child.wait();
        return Err(err.lines().last().unwrap_or("tcpdump exited").to_string());
    }
    // Byte order, and whether record timestamps are micro- or nanoseconds.
    let (le, frac_scale) = match hdr[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, 1e-6),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, 1e-9),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, 1e-6),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, 1e-9),
        _ => return Err("not a pcap stream".into()),
    };
    let u32_at = |b: &[u8]| {
        let a = [b[0], b[1], b[2], b[3]];
        if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let linktype = u32_at(&hdr[20..24]);
    *status.lock().unwrap() = format!("capturing opens + DNS/TLS names on {iface}");

    let mut parser = Parser { tx: tx.clone(), pending: HashMap::new(), ts: 0.0 };
    let mut rec = [0u8; 16];
    let mut pkt = Vec::new();
    while r.read_exact(&mut rec).is_ok() {
        pkt.resize(u32_at(&rec[8..12]) as usize, 0);
        if r.read_exact(&mut pkt).is_err() {
            break;
        }
        parser.ts = u32_at(&rec[0..4]) as f64 + u32_at(&rec[4..8]) as f64 * frac_scale;
        parser.packet(linktype, &pkt);
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

type Flow = (IpAddr, u16, IpAddr, u16);

struct Parser {
    tx: Sender<Event>,
    pending: HashMap<Flow, Vec<u8>>, // partial ClientHellos that span segments
    ts: f64,                         // capture time of the current packet
}

pub(crate) fn be16(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

fn ip_from(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).ok()?)),
        _ => None,
    }
}

impl Parser {
    fn packet(&mut self, linktype: u32, pkt: &[u8]) -> Option<()> {
        let off = match linktype {
            1 => {
                let (mut etype, mut off) = (be16(pkt, 12)?, 14);
                if etype == 0x8100 {
                    (etype, off) = (be16(pkt, 16)?, 18);
                }
                if etype != 0x0800 && etype != 0x86DD {
                    return None;
                }
                off
            }
            0 | 108 => 4, // utun / loopback (VPNs)
            12 | 101 => 0, // raw IP
            _ => return None,
        };
        let ip = pkt.get(off..)?;
        let (proto, src, dst, body) = match ip.first()? >> 4 {
            4 => {
                let ihl = (ip[0] & 0xF) as usize * 4;
                let total = be16(ip, 2)?;
                let end = if total == 0 { ip.len() } else { total.min(ip.len()) };
                (*ip.get(9)?, ip_from(ip.get(12..16)?)?, ip_from(ip.get(16..20)?)?, ip.get(ihl..end)?)
            }
            6 => {
                let len = be16(ip, 4)?;
                let end = (40 + len).min(ip.len());
                (*ip.get(6)?, ip_from(ip.get(8..24)?)?, ip_from(ip.get(24..40)?)?, ip.get(40..end)?)
            }
            _ => return None,
        };
        match proto {
            17 if be16(body, 0)? == 53 => self.dns(body.get(8..)?),
            17 => {
                // QUIC long header to :443 = a new HTTP/3 connection (or its handshake).
                if be16(body, 2)? == 443 && body.get(8)? & 0x80 != 0 {
                    self.open(dst, 443, be16(body, 0)? as u16, "UDP");
                }
                None
            }
            6 => {
                if body.get(13)? & 0x12 == 0x02 {
                    self.open(dst, be16(body, 2)? as u16, be16(body, 0)? as u16, "TCP");
                }
                self.tls(src, dst, body)
            }
            _ => None,
        }
    }

    fn open(&self, ip: IpAddr, port: u16, local_port: u16, proto: &'static str) {
        let _ = self.tx.send(Event::Open(Open { ts: self.ts, ip, port, local_port, proto }));
    }

    fn dns(&self, m: &[u8]) -> Option<()> {
        let (flags, qd, an) = (be16(m, 2)?, be16(m, 4)?, be16(m, 6)?);
        if flags & 0x8000 == 0 {
            return None;
        }
        let mut pos = 12;
        let mut qname = None;
        for _ in 0..qd {
            let (name, p) = read_name(m, pos)?;
            pos = p + 4;
            qname.get_or_insert(name);
        }
        let qname = qname.filter(|q| !q.is_empty())?;
        for _ in 0..an {
            let (_, p) = read_name(m, pos)?;
            let rtype = be16(m, p)?;
            let rdlen = be16(m, p + 8)?;
            let rdata = m.get(p + 10..p + 10 + rdlen)?;
            pos = p + 10 + rdlen;
            if (rtype == 1 && rdlen == 4) || (rtype == 28 && rdlen == 16) {
                let ip = ip_from(rdata)?;
                let _ = self.tx.send(Event::Name(Name { ip: ip.to_string(), name: qname.clone(), source: "dns" }));
            }
        }
        Some(())
    }

    fn tls(&mut self, src: IpAddr, dst: IpAddr, seg: &[u8]) -> Option<()> {
        let sport = be16(seg, 0)? as u16;
        let dport = be16(seg, 2)? as u16;
        let data = seg.get((*seg.get(12)? >> 4) as usize * 4..)?;
        if data.is_empty() {
            return None;
        }
        let flow = (src, sport, dst, dport);
        let mut buf = match self.pending.remove(&flow) {
            Some(mut b) => {
                b.extend_from_slice(data);
                b
            }
            None if data.len() >= 6 && data[0] == 0x16 && data[1] == 3 && data[5] == 1 => data.to_vec(),
            None => return None,
        };
        let need = 5 + be16(&buf, 3)?;
        if buf.len() < need {
            // Large (post-quantum) ClientHellos span several segments; wait for the rest.
            if self.pending.len() > 1000 {
                self.pending.clear();
            }
            self.pending.insert(flow, std::mem::take(&mut buf));
            return None;
        }
        let sni = parse_sni(&buf[5..need])?;
        let _ = self.tx.send(Event::Name(Name { ip: dst.to_string(), name: sni, source: "sni" }));
        Some(())
    }
}

pub(crate) fn read_name(m: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let n = *m.get(pos)? as usize;
        if n & 0xC0 == 0xC0 {
            end.get_or_insert(pos + 2);
            pos = ((n & 0x3F) << 8) | *m.get(pos + 1)? as usize;
        } else if n == 0 {
            return Some((labels.join(".").to_ascii_lowercase(), end.unwrap_or(pos + 1)));
        } else {
            labels.push(String::from_utf8_lossy(m.get(pos + 1..pos + 1 + n)?).into_owned());
            pos += 1 + n;
        }
    }
    None // compression loop
}

/// Pull server_name out of a TLS ClientHello handshake message.
fn parse_sni(h: &[u8]) -> Option<String> {
    if *h.first()? != 1 {
        return None;
    }
    let mut p = 4 + 2 + 32; // header, version, random
    p += 1 + *h.get(p)? as usize; // session id
    p += 2 + be16(h, p)?; // cipher suites
    p += 1 + *h.get(p)? as usize; // compression methods
    let end = p + 2 + be16(h, p)?;
    p += 2;
    while p + 4 <= end {
        let (etype, elen) = (be16(h, p)?, be16(h, p + 2)?);
        p += 4;
        if etype == 0 {
            let nlen = be16(h, p + 3)?;
            let name = h.get(p + 5..p + 5 + nlen)?;
            return Some(String::from_utf8_lossy(name).to_ascii_lowercase());
        }
        p += elen;
    }
    None
}
