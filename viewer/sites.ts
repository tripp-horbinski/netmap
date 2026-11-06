// Dependency traces: what loading one website pulls in.
//
// A "load" is a burst of new connections from one app (new burst after GAP seconds of
// quiet, or CAP seconds after the burst began). The site is the first name in the burst
// that is not a tracker, not browser plumbing and not a bare IP. Everything else in the
// burst is attributed to that site. Heuristic: a site whose own connection was still open
// from an earlier visit (HTTP/2 keep-alive) can be mis-rooted at its first new third party.
import { Database } from "bun:sqlite";
import { baseDomain, isTracker, sinceTs } from "./trackers";

export const GAP = 3;   // seconds of quiet that ends a load
export const CAP = 20;  // seconds after which a load ends regardless

/** Browser, OS and network plumbing that happens during page loads but belongs to no site:
 *  Chrome sync and update traffic, encrypted DNS (mirrors DOH_HOSTS in netlog/src/trackers.rs),
 *  VPN control planes, reverse lookups. Dropped from traces entirely. */
const PLUMBING: readonly RegExp[] = [
  /(^|\.)[a-z0-9-]+-pa\.googleapis\.com$/, /^clients\d*\.google\.com$/, /^mtalk\.google\.com$/,
  /^ogs\.google\.com$/, /^(update|safebrowsing|oauthaccountmanager|chromesyncpreview)\.googleapis\.com$/,
  /^accounts\.google\.com$/, /(^|\.)ghostery\.net$/,
  /^one\.one\.one\.one$/, /(^|\.)cloudflare-dns\.com$/, /^dns\.google$/, /(^|\.)dns\.quad9\.net$/,
  /(^|\.)nextdns\.io$/, /(^|\.)doh\.opendns\.com$/, /(^|\.)dns\.adguard(-dns)?\.com$/, /(^|\.)mullvad\.net$/,
  /(^|\.)dns\.controld\.com$/, /(^|\.)tailscale\.(com|io)$/,
  /(^|\.)in-addr\.arpa$/, /(^|\.)ip6\.arpa$/, /\.local$/,
];
/** Shared infrastructure that is never the site you visited, only something a site pulled in. */
const NEVER_ROOT: readonly RegExp[] = [
  /(^|\.)gstatic\.com$/, /(^|\.)googleapis\.com$/, /(^|\.)googleusercontent\.com$/, /(^|\.)1e100\.net$/,
  /(^|\.)ggpht\.com$/, /(^|\.)aaplimg\.com$/, /(^|\.)apple-cloudkit\.com$/, /(^|\.)apple-dns\.net$/,
  /(^|\.)icloud-content\.com$/, /(^|\.)mzstatic\.com$/, /(^|\.)cdn-apple\.com$/,
  /(^|\.)akamaihd\.net$/, /(^|\.)akamaized\.net$/, /(^|\.)akadns\.net$/, /(^|\.)edgekey\.net$/,
  /(^|\.)edgesuite\.net$/, /(^|\.)cloudfront\.net$/, /(^|\.)fastly\.net$/, /(^|\.)fastlylb\.net$/,
  /(^|\.)amazonaws\.com$/, /(^|\.)azureedge\.net$/, /(^|\.)msecnd\.net$/, /(^|\.)cloudflare\.net$/,
  /(^|\.)githubassets\.com$/, /(^|\.)githubusercontent\.com$/, /(^|\.)jsdelivr\.net$/, /(^|\.)unpkg\.com$/,
  /(^|\.)cloudflareinsights\.com$/, /(^|\.)digicert\.com$/, /(^|\.)letsencrypt\.org$/, /(^|\.)pki\.goog$/,
  /(^|\.)apple\.com$/, /(^|\.)icloud\.com$/, /(^|\.)attlocal\.net$/,
];
const IP = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)$/i;
const UNKNOWN_APP = "(unknown)";
const BROWSER = /chrome|chromium|safari|firefox|arc|edge|brave|orion|vivaldi|opera|webkit/i;

export function isBrowser(app: string): boolean {
  return BROWSER.test(app);
}

/** Did someone navigate here, as opposed to a page pulling it in? `www.` hosts and apex
 *  domains almost always are; so is anything under a domain in `known` (sites pinned by the
 *  user, plus sites learned from earlier clean loads). */
function looksLikeNavigation(name: string, known: ReadonlySet<string>): boolean {
  if (!rootable(name)) return false;
  const n = name.toLowerCase();
  return n.startsWith("www.") || n === baseDomain(n) || known.has(baseDomain(n));
}

/** Strong evidence a base domain is a site: it began a load with a www. or apex host. */
function strongRoot(name: string): boolean {
  const n = name.toLowerCase();
  return n.startsWith("www.") || n === baseDomain(n);
}

export function isPlumbing(name: string): boolean {
  const n = name.toLowerCase();
  return PLUMBING.some((re) => re.test(n));
}

export function isNeverRoot(name: string): boolean {
  const n = name.toLowerCase();
  return NEVER_ROOT.some((re) => re.test(n));
}

export interface Open { id: number; ts: number; app: string; ip: string; name: string; org: string | null; country: string | null }

export interface Hit { name: string; domain: string; org: string | null; country: string | null; tracker: boolean; offset: number; ip: string }
export interface Load {
  app: string; site: string;
  /** The load began with a www. or apex host, so the site attribution is reliable. */
  strong: boolean;
  start: number; end: number; hits: Hit[];
}

export interface SiteSummary {
  site: string; loads: number; last: number; apps: string[];
  hosts: number; third_party: number; trackers: number; orgs: number;
}

export interface SiteHost {
  name: string; domain: string; org: string | null; country: string | null; tracker: boolean;
  first_party: boolean; loads: number; median_offset: number;
}

export interface SiteDetail {
  summary: SiteSummary;
  /** The site is one the user pinned. */
  pinned: boolean;
  hosts: SiteHost[];
  orgs: { org: string; hosts: number; tracker: boolean }[];
  /** The richest of the ten most recent loads, so a one-host keep-alive ping does not hide the trace. */
  latest: Load | null;
  loads: { start: number; app: string; hosts: number; trackers: number }[];
}

function nameOf(host: string | null, rdns: string | null, ip: string): string {
  return host ?? (rdns && rdns !== "" ? rdns : ip);
}

function rootable(name: string): boolean {
  return !IP.test(name) && !isTracker(name) && !isPlumbing(name) && !isNeverRoot(name);
}

/** Split opens into loads: one burst per app, and a new burst when a `www.` host of another
 *  site shows up (a click to a new page inside the quiet gap). Opens whose app lsof missed
 *  ("(unknown)") join the browser burst active at that moment, else form their own.
 *  Pure, so unit-testable. */
export function sessionize(opens: Open[], known: ReadonlySet<string> = new Set()): Load[] {
  const sorted = opens.filter((o) => !isPlumbing(o.name)).sort((a, b) => a.ts - b.ts);
  const bursts = new Map<string, Open[]>();
  const loads: Load[] = [];
  const flush = (app: string) => {
    const cur = bursts.get(app);
    if (cur?.length) { const l = toLoad(app, cur); if (l) loads.push(l); }
    bursts.delete(app);
  };
  const live = (cur: Open[] | undefined, ts: number) =>
    !!cur?.length && ts - cur[cur.length - 1]!.ts <= GAP && ts - cur[0]!.ts <= CAP;
  for (const o of sorted) {
    let app = o.app;
    if (app === UNKNOWN_APP) {
      let best: string | undefined, bestTs = -Infinity;
      for (const [a, cur] of bursts) {
        if (isBrowser(a) && live(cur, o.ts) && cur[cur.length - 1]!.ts > bestTs) { best = a; bestTs = cur[cur.length - 1]!.ts; }
      }
      if (best) app = best;
    }
    const cur = bursts.get(app);
    const navigated = cur?.length && looksLikeNavigation(o.name, known)
      && cur.some((p) => rootable(p.name)) && baseDomain(o.name) !== baseDomain(cur.find((p) => rootable(p.name))!.name);
    if (!live(cur, o.ts) || navigated) flush(app);
    (bursts.get(app) ?? bursts.set(app, []).get(app)!).push(o);
  }
  for (const app of [...bursts.keys()]) flush(app);
  return loads.sort((a, b) => b.start - a.start);
}

function toLoad(app: string, opens: Open[]): Load | null {
  const root = opens.find((o) => rootable(o.name));
  if (!root) return null;
  const site = baseDomain(root.name);
  const strong = strongRoot(root.name);
  const seen = new Set<string>();
  const hits: Hit[] = [];
  for (const o of opens) {
    if (seen.has(o.name)) continue;
    seen.add(o.name);
    hits.push({ name: o.name, domain: baseDomain(o.name), org: o.org, country: o.country,
                tracker: isTracker(o.name), offset: Math.max(0, o.ts - root.ts), ip: o.ip });
  }
  return { app, site, strong, start: root.ts, end: opens[opens.length - 1]!.ts, hits };
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)]! : 0;
}

function summarize(site: string, loads: Load[]): SiteSummary {
  const hosts = new Set<string>(), orgs = new Set<string>(), apps = new Set<string>();
  let third = 0, trackers = 0;
  const thirdSet = new Set<string>(), trackerSet = new Set<string>();
  for (const l of loads) {
    apps.add(l.app);
    for (const h of l.hits) {
      hosts.add(h.name);
      if (h.org) orgs.add(h.org);
      if (h.domain !== site) thirdSet.add(h.name);
      if (h.tracker) trackerSet.add(h.name);
    }
  }
  third = thirdSet.size; trackers = trackerSet.size;
  return { site, loads: loads.length, last: loads[0]!.start, apps: [...apps].sort(),
           hosts: hosts.size, third_party: third, trackers, orgs: orgs.size };
}

const KNOWN_KEY = "viewer.known_sites";

export class SitesDb {
  private opensQ; private knownQ; private setKnownQ;
  constructor(db: Database) {
    this.knownQ = db.query<{ value: string }, [string]>("SELECT value FROM meta WHERE key = ?1");
    this.setKnownQ = db.query<void, [string, string]>(
      "INSERT INTO meta VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    this.opensQ = db.query<{ id: number; ts: number; app: string; ip: string; host: string | null; rdns: string | null; org: string | null; country: string | null }, [number]>(
      `SELECT e.id, e.ts, e.process AS app, e.ip,
              (SELECT n.name FROM ip_name n WHERE n.ip = e.ip ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host,
              i.hostname AS rdns, i.org, i.country
       FROM events e LEFT JOIN ip_info i USING (ip) WHERE e.ts >= ?1 ORDER BY e.ts`);
  }

  /** Sites the user pinned, as base domains. Stored in netlog's `meta` table. */
  known(): string[] {
    try { return JSON.parse(this.knownQ.get(KNOWN_KEY)?.value ?? "[]") as string[]; } catch { return []; }
  }

  pin(name: string, pinned: boolean): string[] {
    const d = baseDomain(name);
    const set = new Set(this.known());
    if (pinned) set.add(d); else set.delete(d);
    const list = [...set].sort();
    this.setKnownQ.run(KNOWN_KEY, JSON.stringify(list));
    return list;
  }

  /** All loads in the window; with `browsersOnly`, just those from browser processes.
   *  Two passes: the first learns which domains began a load with a www. or apex host, the
   *  second also splits bursts at those domains (and at the user's pinned sites). */
  loads(window: string, browsersOnly = false): Load[] {
    const rows = this.opensQ.all(sinceTs(window));
    const opens = rows.map((r) => ({ id: r.id, ts: r.ts, app: r.app, ip: r.ip, name: nameOf(r.host, r.rdns, r.ip), org: r.org, country: r.country }));
    const known = new Set(this.known());
    for (const l of sessionize(opens, known)) if (l.strong) known.add(l.site);
    const loads = sessionize(opens, known);
    return browsersOnly ? loads.filter((l) => isBrowser(l.app)) : loads;
  }

  sites(window: string, browsersOnly = false): SiteSummary[] {
    const bySite = new Map<string, Load[]>();
    for (const l of this.loads(window, browsersOnly)) (bySite.get(l.site) ?? bySite.set(l.site, []).get(l.site)!).push(l);
    return [...bySite].map(([site, loads]) => summarize(site, loads))
      .sort((a, b) => b.third_party - a.third_party || b.loads - a.loads || a.site.localeCompare(b.site));
  }

  site(site: string, window: string, browsersOnly = false): SiteDetail | null {
    const loads = this.loads(window, browsersOnly).filter((l) => l.site === site);
    if (!loads.length) return null;
    const summary = summarize(site, loads);
    const acc = new Map<string, { h: Hit; offsets: number[] }>();
    for (const l of loads) for (const h of l.hits) {
      const a = acc.get(h.name) ?? acc.set(h.name, { h, offsets: [] }).get(h.name)!;
      a.offsets.push(h.offset);
    }
    const hosts: SiteHost[] = [...acc.values()].map(({ h, offsets }) => ({
      name: h.name, domain: h.domain, org: h.org, country: h.country, tracker: h.tracker,
      first_party: h.domain === site, loads: offsets.length, median_offset: median(offsets),
    })).sort((a, b) => Number(b.first_party) - Number(a.first_party) || b.loads - a.loads || a.median_offset - b.median_offset);
    const orgMap = new Map<string, { org: string; hosts: number; tracker: boolean }>();
    for (const h of hosts) {
      const o = h.org ?? "unknown";
      const row = orgMap.get(o) ?? orgMap.set(o, { org: o, hosts: 0, tracker: false }).get(o)!;
      row.hosts += 1; row.tracker ||= h.tracker;
    }
    return {
      summary, hosts, pinned: this.known().includes(site),
      orgs: [...orgMap.values()].sort((a, b) => b.hosts - a.hosts || a.org.localeCompare(b.org)),
      // The most telling recent load: the one with the most hosts among the last ten.
      latest: loads.slice(0, 10).reduce<Load | null>((best, l) => (!best || l.hits.length > best.hits.length ? l : best), null),
      loads: loads.map((l) => ({ start: l.start, app: l.app, hosts: l.hits.length, trackers: l.hits.filter((h) => h.tracker).length })),
    };
  }
}
