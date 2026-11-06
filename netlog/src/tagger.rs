//! Process attribution from pktap. macOS's tcpdump can capture on the `pktap` pseudo-interface,
//! where every packet carries the owning process (`-k NP` prints it). That names a connection on
//! its first packet, so short-lived opens and root daemons stop showing as "(unknown)". Opening
//! pktap needs root, so this runs only when the recorder does (the launchd daemon).
//!
//! Text output is parsed rather than the pcap-ng stream: the metadata is a prefix like
//! `(proc Zentty:37571, eproc Zentty:37571)` and the rest is a normal one-line packet summary.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sniff::Event;

/// TCP SYNs and QUIC long headers: the first packet of each connection, nothing else.
const FILTER: &str = "not (host 127.0.0.1 or ip6 host ::1) and (\
    (ip and tcp[13] & 0x12 = 2) or (ip6 and ip6[6] = 6 and ip6[53] & 0x12 = 2) \
    or (ip and udp dst port 443 and udp[8] & 0x80 != 0) \
    or (ip6 and ip6[6] = 17 and udp dst port 443 and ip6[48] & 0x80 != 0))";

/// Who opened a connection, by its local port.
#[derive(Debug, Clone, PartialEq)]
pub struct Owner {
    pub ts: f64,
    pub proto: &'static str,
    pub local_port: u16,
    /// Kernel process name, truncated to 16 characters ("Google Chrome He").
    pub comm: String,
    pub pid: i32,
    /// The process the connection is really for, when a system proxy made it on its behalf.
    pub epid: Option<i32>,
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}

pub fn run(tx: Sender<Event>, status: Arc<Mutex<String>>) {
    loop {
        let msg = match capture(&tx, &status) {
            Ok(()) => "pktap stopped; retrying".to_string(),
            Err(e) => format!("pktap off ({e})"),
        };
        *status.lock().unwrap() = msg;
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn capture(tx: &Sender<Event>, status: &Mutex<String>) -> Result<(), String> {
    let mut child = Command::new("tcpdump")
        .args(["-i", "pktap,all", "-k", "NP", "-n", "-l", "-q", "-tt", "-U", "--immediate-mode", FILTER])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("can't run tcpdump: {e}"))?;
    let r = BufReader::new(child.stdout.take().unwrap());
    let mut any = false;
    for line in r.lines() {
        let Ok(line) = line else { break };
        if !any {
            any = true;
            *status.lock().unwrap() = "pktap on: naming connections on their first packet".into();
        }
        if let Some(o) = parse_line(&line) {
            let _ = tx.send(Event::Owner(o));
        }
    }
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = child.wait();
    match err.lines().rev().find(|l| !l.trim().is_empty() && !l.contains("packets captured") && !l.contains("packets received") && !l.contains("packets dropped")) {
        Some(last) if !any => Err(last.trim().to_string()),
        _ => Ok(()),
    }
}

/// "name:123" -> (name, 123). The name may contain spaces and colons; the pid is after the last ':'.
fn name_pid(s: &str) -> Option<(String, i32)> {
    let (name, pid) = s.trim().rsplit_once(':')?;
    Some((name.trim().to_string(), pid.trim().parse().ok()?))
}

/// Parse one tcpdump line with `-k NP -tt -q`:
/// `1762455123.456789 (proc Zentty:37571, eproc Zentty:37571) IP 192.168.1.98.52345 > 104.21.71.117.443: tcp 0`
pub fn parse_line(line: &str) -> Option<Owner> {
    let ts: f64 = line.split_whitespace().next()?.parse().ok()?;
    let meta_start = line.find('(')?;
    let meta_end = line[meta_start..].find(')')? + meta_start;
    let meta = &line[meta_start + 1..meta_end];
    let (mut comm, mut pid, mut epid) = (None, None, None);
    for part in meta.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("eproc ") {
            epid = name_pid(v).map(|(_, p)| p);
        } else if let Some(v) = part.strip_prefix("proc ") {
            if let Some((n, p)) = name_pid(v) {
                comm = Some(n);
                pid = Some(p);
            }
        }
    }
    let (comm, pid) = (comm?, pid?);
    let rest = &line[meta_end + 1..];
    let proto = if rest.contains(" UDP") || rest.contains(" udp") { "UDP" } else { "TCP" };
    // "IP 192.168.1.98.52345 > ..." or "IP6 2001:db8::1.52345 > ...": the local port is the last dotted field.
    let src = rest.split_whitespace().skip_while(|w| !w.starts_with("IP")).nth(1)?;
    let local_port: u16 = src.rsplit_once('.')?.1.parse().ok()?;
    Some(Owner { ts, proto, local_port, comm, pid, epid: epid.filter(|e| *e != pid) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_syn_line() {
        let o = parse_line("1762455123.456789 (proc Google Chrome He:39830, eproc Google Chrome He:39830) IP 192.168.1.98.52345 > 104.21.71.117.443: tcp 0").unwrap();
        assert_eq!(o.comm, "Google Chrome He");
        assert_eq!(o.pid, 39830);
        assert_eq!(o.local_port, 52345);
        assert_eq!(o.proto, "TCP");
        assert_eq!(o.epid, None);
        assert!((o.ts - 1762455123.456789).abs() < 1e-6);
    }

    #[test]
    fn quic_and_proxy() {
        let o = parse_line("1762455124.0 (proc nsurlsessiond:421, eproc Zentty:37571) IP6 2001:db8::1.60000 > 2606:4700::1.443: UDP, length 1200").unwrap();
        assert_eq!(o.proto, "UDP");
        assert_eq!(o.local_port, 60000);
        assert_eq!(o.epid, Some(37571));
    }

    /// Lines exactly as macOS tcpdump 4.99.1 (Apple 161) printed them with `-k NP -n -l -q -tt`.
    #[test]
    fn real_output() {
        let udp = parse_line("1793991985.817348 (proc mDNSResponder:562) IP 192.168.1.79.51264 > 1.0.0.1.443: UDP, length 1200").unwrap();
        assert_eq!((udp.comm.as_str(), udp.pid, udp.proto, udp.local_port, udp.epid), ("mDNSResponder", 562, "UDP", 51264, None));
        let tcp = parse_line("1793991985.921385 (proc mDNSResponder:562) IP 192.168.1.79.65081 > 1.0.0.1.443: tcp 0").unwrap();
        assert_eq!((tcp.proto, tcp.local_port), ("TCP", 65081));
        assert!(parse_line("listening on pktap,en0, link-type PKTAP (Apple DLT_PKTAP), snapshot length 524288 bytes").is_none());
        assert!(parse_line("6 packets captured").is_none());
    }

    #[test]
    fn junk_is_ignored() {
        assert!(parse_line("tcpdump: data link type PKTAP").is_none());
        assert!(parse_line("").is_none());
    }
}
