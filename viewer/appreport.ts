// App report cards: for each app (product name, helpers merged), what it sent where in the window,
// classified per host, with the companies, countries, launchers and hourly rhythm behind it.
import { Database } from "bun:sqlite";
import { sinceTs } from "./trackers";
import { appName, type AppRowLite } from "./appname";
import { classifyHost, firstPartyDomains, CLASS_ORDER, type HostClass } from "./classify";

export interface AppSummary {
  name: string; processes: string[]; opens: number; hosts: number; destinations: number; companies: number;
  by_class: Record<HostClass, number>;  // hosts per class
  bundle_id: string | null; version: string | null; feed_url: string | null; path: string | null;
  via: string[]; last: number;
}
export interface AppCard extends AppSummary {
  window: { since: number; now: number; start: number; bin_seconds: number };
  bins: number[];
  host_list: { host: string; ip: string; org: string | null; country: string | null; cls: HostClass; opens: number; last: number }[];
  company_list: { org: string; hosts: number; classes: HostClass[] }[];
  country_list: { country: string; hosts: number }[];
  via_list: { via: string; opens: number }[];
}

const BINS = 24;
interface Row { ts: number; process: string; via: string | null; ip: string; org: string | null; country: string | null; host: string | null }

export class AppReportDb {
  private opensQ; private appsQ; private minTsQ;
  constructor(db: Database) {
    this.opensQ = db.query<Row, [number]>(`
      SELECT e.ts, e.process, e.via, e.ip, i.org, i.country,
             (SELECT n.name FROM ip_name n WHERE n.ip = e.ip ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host
      FROM events e LEFT JOIN ip_info i USING (ip) WHERE e.ts >= ?1 ORDER BY e.ts`);
    this.appsQ = db.query<AppRowLite, []>("SELECT process, name, version, path, bundle_id, feed_url FROM apps");
    this.minTsQ = db.query<{ t: number | null }, []>("SELECT MIN(ts) AS t FROM events");
  }

  private apps(): Map<string, AppRowLite> {
    let rows: AppRowLite[] = [];
    try { rows = this.appsQ.all(); } catch {}
    return new Map(rows.map((a) => [a.process, a]));
  }

  private axis(window: string) {
    const now = Date.now() / 1000;
    const since = sinceTs(window, now);
    const start = since > 0 ? since : (this.minTsQ.get()?.t ?? now - 3600);
    return { since, now, start, bin_seconds: Math.max(1, (now - start) / BINS) };
  }

  /** Group opens by product name; returns one accumulator per app. */
  private collect(window: string) {
    const apps = this.apps();
    const axis = this.axis(window);
    const acc = new Map<string, { rows: Row[]; processes: Set<string> }>();
    for (const r of this.opensQ.all(axis.since)) {
      const name = appName(r.process, apps);
      const a = acc.get(name) ?? acc.set(name, { rows: [], processes: new Set() }).get(name)!;
      a.rows.push(r); a.processes.add(r.process);
    }
    return { apps, axis, acc };
  }

  private build(name: string, rows: Row[], processes: Set<string>, apps: Map<string, AppRowLite>, axis: ReturnType<AppReportDb["axis"]>): AppCard {
    // the bundle row: prefer a process with a bundle id
    const info = [...processes].map((p) => apps.get(p)).filter(Boolean).sort((a, b) => Number(!!b!.bundle_id) - Number(!!a!.bundle_id))[0] ?? null;
    const first = firstPartyDomains(name, info?.bundle_id ?? null, info?.feed_url ?? null);
    const hosts = new Map<string, { ip: string; org: string | null; country: string | null; cls: HostClass; opens: number; last: number }>();
    const via = new Map<string, number>();
    const bins = new Array<number>(BINS).fill(0);
    let last = 0;
    for (const r of rows) {
      const host = r.host ?? r.ip;
      const h = hosts.get(host) ?? hosts.set(host, { ip: r.ip, org: r.org, country: r.country, cls: classifyHost(host, r.org, first), opens: 0, last: 0 }).get(host)!;
      h.opens++; h.last = Math.max(h.last, r.ts);
      if (r.via) via.set(r.via, (via.get(r.via) ?? 0) + 1);
      bins[Math.min(BINS - 1, Math.max(0, Math.floor((r.ts - axis.start) / axis.bin_seconds)))]!++;
      last = Math.max(last, r.ts);
    }
    const by_class = Object.fromEntries(CLASS_ORDER.map((c) => [c, 0])) as Record<HostClass, number>;
    const companies = new Map<string, { hosts: number; classes: Set<HostClass> }>();
    const countries = new Map<string, number>();
    for (const h of hosts.values()) {
      by_class[h.cls]++;
      const org = h.org ?? "Unknown network";
      const c = companies.get(org) ?? companies.set(org, { hosts: 0, classes: new Set() }).get(org)!;
      c.hosts++; c.classes.add(h.cls);
      if (h.country) countries.set(h.country, (countries.get(h.country) ?? 0) + 1);
    }
    const rank = (c: HostClass) => CLASS_ORDER.indexOf(c);
    return {
      name, processes: [...processes].sort(), opens: rows.length, hosts: hosts.size, destinations: new Set(rows.map((r) => r.ip)).size,
      companies: companies.size, by_class, bundle_id: info?.bundle_id ?? null, version: info?.version ?? null, feed_url: info?.feed_url ?? null,
      path: info?.path ?? null, via: [...via].sort((a, b) => b[1] - a[1]).map(([v]) => v), last,
      window: axis, bins,
      host_list: [...hosts].map(([host, h]) => ({ host, ...h })).sort((a, b) => rank(a.cls) - rank(b.cls) || b.opens - a.opens),
      company_list: [...companies].map(([org, c]) => ({ org, hosts: c.hosts, classes: [...c.classes].sort((a, b) => rank(a) - rank(b)) })).sort((a, b) => b.hosts - a.hosts),
      country_list: [...countries].map(([country, hosts]) => ({ country, hosts })).sort((a, b) => b.hosts - a.hosts),
      via_list: [...via].map(([via, opens]) => ({ via, opens })).sort((a, b) => b.opens - a.opens),
    };
  }

  list(window: string): AppSummary[] {
    const { apps, axis, acc } = this.collect(window);
    return [...acc].map(([name, a]) => {
      const { window: _w, bins: _b, host_list: _h, company_list: _c, country_list: _k, via_list: _v, ...summary } = this.build(name, a.rows, a.processes, apps, axis);
      return summary;
    }).sort((x, y) => y.destinations - x.destinations || y.opens - x.opens);
  }

  card(name: string, window: string): AppCard | null {
    const { apps, axis, acc } = this.collect(window);
    const a = acc.get(name);
    return a ? this.build(name, a.rows, a.processes, apps, axis) : null;
  }
}
