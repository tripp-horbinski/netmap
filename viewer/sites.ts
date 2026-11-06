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
const CHROME = /google chrome|chromium/i;

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

export interface Hit {
  name: string; domain: string; org: string | null; country: string | null; tracker: boolean; offset: number; ip: string;
  /** From the Chrome extension only: when the first request to this host finished, its type, size and status. */
  end_offset?: number | null; type?: string | null; bytes?: number | null; status?: number | null;
  /** What the host is to the site (set by the API, see classify.ts). */
  cls?: string;
}
/** One browser request in a load, from the extension: the trace view draws these. */
export interface Request {
  name: string; offset: number; end_offset: number | null; type: string; status: number | null; bytes: number | null; cached: boolean; org: string | null; cls?: string;
}
export interface Load {
  app: string; site: string;
  /** The host the load was rooted at, e.g. tripp.horbin.ski; `site` is its base domain. */
  root: string;
  /** The load began with a www. or apex host, so the site attribution is reliable. */
  strong: boolean;
  /** Reported by the Chrome extension: the tab really was on this site. */
  exact?: boolean;
  /** Every request of an exact load, in order; heuristic loads have none. */
  requests?: Request[];
  start: number; end: number; hits: Hit[];
}

export interface SiteSummary {
  site: string;
  /** What to call the site: the usual root host when it is a non-www subdomain (tripp.horbin.ski), else the base domain. */
  label: string;
  loads: number;
  /** How many of the loads came from the Chrome extension rather than the burst heuristic. */
  exact: number; last: number; apps: string[];
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
  loads: { start: number; app: string; hosts: number; trackers: number; exact: boolean; span: number }[];
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
  return { app, site, root: root.name, strong, start: root.ts, end: opens[opens.length - 1]!.ts, hits };
}

export interface SiteGraph {
  sites: { site: string; label: string; loads: number; third_party: number }[];
  orgs: { org: string; sites: number; hosts: number; tracker: boolean }[];
  /** Third-party hosts of `site` served by `org`, with the hosts' names for the tooltip and table. */
  edges: { site: string; org: string; hosts: number; names: string[] }[];
}

/** Which companies serve third-party hosts to which sites: the top `maxSites` sites by third-party
 *  footprint and the top `maxOrgs` companies by how many of those sites they appear on. Companies
 *  past the cap fold into "Other". */
export function buildGraph(loads: Load[], known: ReadonlySet<string>, maxSites = 12, maxOrgs = 14): SiteGraph {
  const bySite = new Map<string, Load[]>();
  for (const l of loads) (bySite.get(l.site) ?? bySite.set(l.site, []).get(l.site)!).push(l);
  const summaries = [...bySite].map(([site, ls]) => summarize(site, ls, known.has(site)))
    .filter((s) => s.third_party > 0)
    .sort((a, b) => b.third_party - a.third_party || b.loads - a.loads || a.site.localeCompare(b.site))
    .slice(0, maxSites);
  const edgeMap = new Map<string, { site: string; org: string; names: Set<string>; tracker: boolean }>();
  for (const s of summaries) {
    for (const l of bySite.get(s.site)!) for (const h of l.hits) {
      if (h.domain === s.site) continue;
      const org = h.org ?? "Unknown network";
      const k = `${s.site}\u0000${org}`;
      const e = edgeMap.get(k) ?? edgeMap.set(k, { site: s.site, org, names: new Set(), tracker: false }).get(k)!;
      e.names.add(h.name); e.tracker ||= h.tracker;
    }
  }
  const orgStat = new Map<string, { org: string; sites: number; hosts: number; tracker: boolean }>();
  for (const e of edgeMap.values()) {
    const o = orgStat.get(e.org) ?? orgStat.set(e.org, { org: e.org, sites: 0, hosts: 0, tracker: false }).get(e.org)!;
    o.sites += 1; o.hosts += e.names.size; o.tracker ||= e.tracker;
  }
  const ranked = [...orgStat.values()].sort((a, b) => b.sites - a.sites || b.hosts - a.hosts || a.org.localeCompare(b.org));
  const keep = new Set(ranked.slice(0, maxOrgs).map((o) => o.org));
  const folded = new Map<string, { site: string; org: string; hosts: number; names: string[] }>();
  for (const e of edgeMap.values()) {
    const org = keep.has(e.org) ? e.org : "Other";
    const k = `${e.site}\u0000${org}`;
    const f = folded.get(k) ?? folded.set(k, { site: e.site, org, hosts: 0, names: [] }).get(k)!;
    f.hosts += e.names.size; f.names.push(...e.names);
  }
  const orgs = ranked.filter((o) => keep.has(o.org));
  if (ranked.length > orgs.length) {
    const rest = ranked.filter((o) => !keep.has(o.org));
    const sites = new Set([...folded.values()].filter((e) => e.org === "Other").map((e) => e.site)).size;
    orgs.push({ org: "Other", sites, hosts: rest.reduce((n, o) => n + o.hosts, 0), tracker: rest.some((o) => o.tracker) });
  }
  return {
    sites: summaries.map((s) => ({ site: s.site, label: s.label, loads: s.loads, third_party: s.third_party })),
    orgs,
    edges: [...folded.values()].map((e) => ({ ...e, names: e.names.sort() })).sort((a, b) => b.hosts - a.hosts),
  };
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)]! : 0;
}

function summarize(site: string, loads: Load[], pinned: boolean): SiteSummary {
  const hosts = new Set<string>(), orgs = new Set<string>(), apps = new Set<string>();
  let third = 0, trackers = 0;
  const thirdSet = new Set<string>(), trackerSet = new Set<string>();
  const roots = new Map<string, number>();
  for (const l of loads) {
    apps.add(l.app);
    roots.set(l.root, (roots.get(l.root) ?? 0) + 1);
    for (const h of l.hits) {
      hosts.add(h.name);
      if (h.org) orgs.add(h.org);
      if (h.domain !== site) thirdSet.add(h.name);
      if (h.tracker) trackerSet.add(h.name);
    }
  }
  third = thirdSet.size; trackers = trackerSet.size;
  const top = [...roots].sort((a, b) => b[1] - a[1])[0]![0].toLowerCase();
  // Only a pinned site gets its root host as the name; for the rest the base domain is the
  // identity and the root is often a CDN node like rr10---sn-...googlevideo.com.
  const label = !pinned || top === site || top === `www.${site}` ? site : top;
  return { site, label, loads: loads.length, exact: loads.filter((l) => l.exact).length, last: loads[0]!.start, apps: [...apps].sort(),
           hosts: hosts.size, third_party: third, trackers, orgs: orgs.size };
}

const KNOWN_KEY = "viewer.known_sites";

export class SitesDb {
  private opensQ; private knownQ; private setKnownQ;
  constructor(db: Database, private browser: { loads(since: number): Load[]; status(): { first: number | null } } | null = null) {
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
    const since = sinceTs(window);
    const rows = this.opensQ.all(since);
    const opens = rows.map((r) => ({ id: r.id, ts: r.ts, app: r.app, ip: r.ip, name: nameOf(r.host, r.rdns, r.ip), org: r.org, country: r.country }));
    const known = new Set(this.known());
    // Exact loads from the Chrome extension replace the heuristic ones for Chrome from the moment
    // the extension started reporting; their sites also help split other browsers' bursts.
    const exact = this.browser?.loads(since) ?? [];
    const exactFrom = exact.length ? this.browser!.status().first ?? Infinity : Infinity;
    for (const l of exact) known.add(l.site);
    for (const l of sessionize(opens, known)) if (l.strong) known.add(l.site);
    const heuristic = sessionize(opens, known).filter((l) => !(CHROME.test(l.app) && l.start >= exactFrom));
    const loads = [...exact, ...heuristic].sort((a, b) => b.start - a.start);
    return browsersOnly ? loads.filter((l) => isBrowser(l.app)) : loads;
  }

  sites(window: string, browsersOnly = false): SiteSummary[] {
    const bySite = new Map<string, Load[]>();
    for (const l of this.loads(window, browsersOnly)) (bySite.get(l.site) ?? bySite.set(l.site, []).get(l.site)!).push(l);
    const known = new Set(this.known());
    return [...bySite].map(([site, loads]) => summarize(site, loads, known.has(site)))
      .sort((a, b) => b.third_party - a.third_party || b.loads - a.loads || a.site.localeCompare(b.site));
  }

  graph(window: string, browsersOnly = false): SiteGraph {
    return buildGraph(this.loads(window, browsersOnly), new Set(this.known()));
  }

  /** One load of a site, by its start time (as the detail's load list gives it). */
  load(site: string, start: number, window: string, browsersOnly = false): Load | null {
    return this.loads(window, browsersOnly).find((l) => l.site === site && Math.abs(l.start - start) < 1e-3) ?? null;
  }

  site(site: string, window: string, browsersOnly = false): SiteDetail | null {
    const loads = this.loads(window, browsersOnly).filter((l) => l.site === site);
    if (!loads.length) return null;
    const pinned = this.known().includes(site);
    const summary = summarize(site, loads, pinned);
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
      summary, hosts, pinned,
      orgs: [...orgMap.values()].sort((a, b) => b.hosts - a.hosts || a.org.localeCompare(b.org)),
      // The most telling recent load: the one with the most hosts among the last ten.
      latest: loads.slice(0, 10).reduce<Load | null>((best, l) => (!best || l.hits.length > best.hits.length ? l : best), null),
      loads: loads.map((l) => ({ start: l.start, app: l.app, hosts: l.hits.length, trackers: l.hits.filter((h) => h.tracker).length, exact: !!l.exact, span: l.end - l.start })),
    };
  }
}
