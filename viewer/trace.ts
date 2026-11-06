// Route traces: the path packets take from this Mac to a destination, hop by hop, with each
// hop geolocated offline (same DB-IP data as the markers). Uses the system traceroute in ICMP
// mode, which gets through AT&T where UDP probes die; it is setuid root on macOS so no sudo.
import { Database } from "bun:sqlite";
import { promises as dns } from "node:dns";
import type { Geo } from "./geo";

export const MAX_HOPS = 24;
export const SILENT_RUN = 6;       // consecutive unanswered hops after which we give up
export const CACHE_SECONDS = 6 * 3600;
const CONCURRENCY = 2;

export interface Hop {
  n: number;
  ip: string | null;
  rtt_ms: number | null;
  rdns: string | null;
  private: boolean;
  org: string | null; city: string | null; country: string | null;
  lat: number | null; lon: number | null;
}

export interface Trace {
  ip: string;
  ts: number;
  probe: "icmp";
  /** The last hop answered from the destination itself. */
  reached: boolean;
  /** Probe stopped early after SILENT_RUN unanswered hops, or hit MAX_HOPS. */
  truncated: boolean;
  hops: Hop[];
  seconds: number;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9a-f:]+$/i;

export function isIp(s: string): boolean {
  return (IPV4.test(s) && s.split(".").every((o) => Number(o) <= 255)) || (s.includes(":") && IPV6.test(s));
}

/** RFC 1918, CGNAT (100.64/10), link-local and the IPv6 equivalents: hops with no useful geolocation. */
export function isPrivate(ip: string): boolean {
  const m = IPV4.exec(ip);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || a === 127;
  }
  const l = ip.toLowerCase();
  return l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80") || l === "::1";
}

/** One traceroute output line -> hop, or null for the banner. `-n -q 1` keeps it to one probe per line. */
export function parseLine(line: string): { n: number; ip: string | null; rtt_ms: number | null } | null {
  const m = /^\s*(\d+)\s+(.*)$/.exec(line);
  if (!m) return null;
  const n = Number(m[1]);
  const rest = m[2]!.trim();
  if (rest.startsWith("*")) return { n, ip: null, rtt_ms: null };
  const h = /^(\S+)\s+([\d.]+)\s*ms/.exec(rest);
  return h ? { n, ip: h[1]!, rtt_ms: Number(h[2]) } : { n, ip: null, rtt_ms: null };
}

async function rdns(ip: string): Promise<string | null> {
  const timeout = new Promise<null>((r) => setTimeout(() => r(null), 1500));
  const lookup = dns.reverse(ip).then((names) => names[0] ?? null).catch(() => null);
  return Promise.race([lookup, timeout]);
}

export class Tracer {
  private getQ; private putQ;
  private inflight = new Map<string, Promise<Trace>>();
  private running = 0;
  private queue: (() => void)[] = [];

  constructor(db: Database, private geo: Geo | null) {
    db.exec("CREATE TABLE IF NOT EXISTS traces (ip TEXT PRIMARY KEY, ts REAL NOT NULL, json TEXT NOT NULL)");
    this.getQ = db.query<{ ts: number; json: string }, [string]>("SELECT ts, json FROM traces WHERE ip = ?1");
    this.putQ = db.query<void, [string, number, string]>(
      "INSERT INTO traces VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts, json = excluded.json");
  }

  cached(ip: string): Trace | null {
    const row = this.getQ.get(ip);
    return row && Date.now() / 1000 - row.ts < CACHE_SECONDS ? (JSON.parse(row.json) as Trace) : null;
  }

  /** Cached trace if fresh, else run one. Concurrent requests for the same IP share a run. */
  trace(ip: string, fresh = false): Promise<Trace> {
    if (!fresh) {
      const hit = this.cached(ip);
      if (hit) return Promise.resolve(hit);
    }
    let p = this.inflight.get(ip);
    if (!p) {
      p = this.slot(() => this.run(ip)).finally(() => this.inflight.delete(ip));
      this.inflight.set(ip, p);
    }
    return p;
  }

  private async slot<T>(fn: () => Promise<T>): Promise<T> {
    if (this.running >= CONCURRENCY) await new Promise<void>((r) => this.queue.push(r));
    this.running++;
    try { return await fn(); } finally { this.running--; this.queue.shift()?.(); }
  }

  private async run(ip: string): Promise<Trace> {
    const t0 = Date.now();
    const bin = ip.includes(":") ? "/usr/sbin/traceroute6" : "/usr/sbin/traceroute";
    const proc = Bun.spawn([bin, "-I", "-n", "-q", "1", "-w", "1", "-m", String(MAX_HOPS), ip], { stdout: "pipe", stderr: "pipe" });
    const raw: { n: number; ip: string | null; rtt_ms: number | null }[] = [];
    let silent = 0, reached = false, truncated = false;
    const reader = proc.stdout.getReader();
    const dec = new TextDecoder();
    let buf = "";
    outer: while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const hop = parseLine(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        if (!hop) continue;
        raw.push(hop);
        if (hop.ip === ip) { reached = true; break outer; }
        silent = hop.ip ? 0 : silent + 1;
        if (silent >= SILENT_RUN) { truncated = true; break outer; }
      }
    }
    proc.kill();
    await proc.exited.catch(() => {});
    if (raw.length >= MAX_HOPS && !reached) truncated = true;
    // Drop the trailing silent run: it says nothing.
    while (raw.length && raw[raw.length - 1]!.ip === null && !reached) raw.pop();

    const names = await Promise.all(raw.map((h) => (h.ip && !isPrivate(h.ip) ? rdns(h.ip) : Promise.resolve(null))));
    const hops: Hop[] = raw.map((h, i) => {
      const priv = h.ip ? isPrivate(h.ip) : false;
      const g = h.ip && !priv ? this.geo?.lookup(h.ip) ?? {} : {};
      return { n: h.n, ip: h.ip, rtt_ms: h.rtt_ms, rdns: names[i] ?? null, private: priv,
               org: g.org ?? null, city: g.city ?? null, country: g.country ?? null, lat: g.lat ?? null, lon: g.lon ?? null };
    });
    const trace: Trace = { ip, ts: Date.now() / 1000, probe: "icmp", reached, truncated, hops, seconds: (Date.now() - t0) / 1000 };
    this.putQ.run(ip, trace.ts, JSON.stringify(trace));
    return trace;
  }
}
