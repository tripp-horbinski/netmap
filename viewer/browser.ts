// Requests reported by the Chrome extension in ../extension: which tab asked for each host and
// what page that tab was showing. From outside the browser netlog only sees one "Google Chrome
// Helper" process for every tab; this is the inside view, and where it exists it replaces the
// burst heuristics in sites.ts with exact attribution.
import { Database } from "bun:sqlite";
import type { Geo } from "./geo";
import { baseDomain, isTracker } from "./trackers";
import type { Hit, Load } from "./sites";

export interface BrowserRow {
  ts: number; tab: number; nav_ts: number | null; site: string | null; host: string;
  type: string; initiator: string | null; ip: string | null; cached: boolean;
}

/** Requests with no tab (service workers, prefetch) group by site in spans this long. */
const SPAN = 20;
/** A host opened within this many seconds of a reported request is attributed to that request's page. */
const MATCH = 5;

export class BrowserDb {
  private insertQ; private rowsQ; private statusQ; private siteForQ; private infoQ;
  constructor(private db: Database, private geo: Geo | null) {
    db.exec(`CREATE TABLE IF NOT EXISTS browser_requests (
      id INTEGER PRIMARY KEY, ts REAL NOT NULL, tab INTEGER NOT NULL, nav_ts REAL, site TEXT, host TEXT NOT NULL,
      type TEXT NOT NULL, initiator TEXT, ip TEXT, cached INTEGER NOT NULL DEFAULT 0)`);
    db.exec("CREATE INDEX IF NOT EXISTS browser_requests_ts ON browser_requests (ts)");
    db.exec("CREATE INDEX IF NOT EXISTS browser_requests_host ON browser_requests (host, ts)");
    this.insertQ = db.query<void, [number, number, number | null, string | null, string, string, string | null, string | null, number]>(
      "INSERT INTO browser_requests (ts, tab, nav_ts, site, host, type, initiator, ip, cached) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)");
    this.rowsQ = db.query<BrowserRow, [number]>(
      "SELECT ts, tab, nav_ts, site, host, type, initiator, ip, cached FROM browser_requests WHERE ts >= ?1 AND site IS NOT NULL ORDER BY ts");
    this.statusQ = db.query<{ rows: number; first: number | null; last: number | null }, []>(
      "SELECT COUNT(*) AS rows, MIN(ts) AS first, MAX(ts) AS last FROM browser_requests");
    this.siteForQ = db.query<{ site: string }, [string, number, number]>(
      "SELECT site FROM browser_requests WHERE host = ?1 AND ts BETWEEN ?2 AND ?3 AND site IS NOT NULL ORDER BY ts DESC LIMIT 1");
    this.infoQ = db.query<{ org: string | null; country: string | null }, [string]>("SELECT org, country FROM ip_info WHERE ip = ?1");
  }

  /** Store a batch from the extension; malformed rows are skipped. Returns how many were kept. */
  ingest(rows: unknown): number {
    if (!Array.isArray(rows)) return 0;
    let n = 0;
    const tx = this.db.transaction((list: unknown[]) => {
      for (const r of list) {
        if (!r || typeof r !== "object") continue;
        const o = r as Record<string, unknown>;
        if (typeof o.ts !== "number" || typeof o.host !== "string" || !o.host) continue;
        this.insertQ.run(o.ts, typeof o.tab === "number" ? o.tab : -1, typeof o.nav_ts === "number" ? o.nav_ts : null,
          typeof o.site === "string" ? o.site.toLowerCase() : null, o.host.toLowerCase(), typeof o.type === "string" ? o.type : "other",
          typeof o.initiator === "string" ? o.initiator : null, typeof o.ip === "string" ? o.ip : null, o.cached ? 1 : 0);
        n++;
      }
    });
    tx(rows);
    return n;
  }

  status(): { rows: number; first: number | null; last: number | null } {
    return this.statusQ.get()!;
  }

  /** The page host a request for `host` around `ts` belonged to, if the extension reported one. */
  siteFor(host: string | null, ts: number): string | null {
    if (!host) return null;
    return this.siteForQ.get(host.toLowerCase(), ts - MATCH, ts + MATCH)?.site ?? null;
  }

  private orgOf(ip: string | null): { org: string | null; country: string | null } {
    if (!ip) return { org: null, country: null };
    const known = this.infoQ.get(ip);
    if (known) return known;
    const g = this.geo?.lookup(ip);
    return { org: g?.org ?? null, country: g?.country ?? null };
  }

  /** One load per tab navigation (or per 20 s span of tab-less requests to a site), exact. */
  loads(since: number): Load[] {
    const groups = new Map<string, BrowserRow[]>();
    for (const r of this.rowsQ.all(since)) {
      const key = r.tab >= 0 && r.nav_ts != null ? `${r.tab}:${r.nav_ts}` : `${r.site}:${Math.floor(r.ts / SPAN)}`;
      (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
    }
    const out: Load[] = [];
    const orgCache = new Map<string, { org: string | null; country: string | null }>();
    for (const rows of groups.values()) {
      const root = rows[0]!.site!;
      const start = rows[0]!.nav_ts ?? rows[0]!.ts;
      const seen = new Set<string>();
      const hits: Hit[] = [];
      for (const r of rows) {
        if (seen.has(r.host)) continue;
        seen.add(r.host);
        const key = r.ip ?? "";
        const info = orgCache.get(key) ?? orgCache.set(key, this.orgOf(r.ip)).get(key)!;
        hits.push({ name: r.host, domain: baseDomain(r.host), org: info.org, country: info.country,
                    tracker: isTracker(r.host), offset: Math.max(0, r.ts - start), ip: r.ip ?? "" });
      }
      out.push({ app: "Chrome", site: baseDomain(root), root, strong: true, exact: true,
                 start, end: rows[rows.length - 1]!.ts, hits });
    }
    return out.sort((a, b) => b.start - a.start);
  }
}
