// Who sees you: every company behind the hosts this network talks to, rolled up across the
// three vantage points netlog has: apps on this Mac (connection opens), sites visited (loads
// from sites.ts), and LAN devices (the names they resolved, mapped through the answer IPs).
import { Database } from "bun:sqlite";
import type { Geo } from "./geo";
import { baseDomain, isTracker, sinceTs } from "./trackers";
import type { Load } from "./sites";

export interface Company {
  org: string;
  /** Sites whose loads pulled in one of this company's hosts; third_party counts those where it was not the site itself. */
  sites: number; third_party_sites: number;
  apps: number; devices: number; hosts: number;
  tracker: boolean;
  last: number;
  /** sites + apps + devices: how many places this company shows up. */
  reach: number;
}

export interface CompanyDetail extends Company {
  site_list: { site: string; third_party: boolean; hosts: number }[];
  app_list: { app: string; hosts: number; last: number }[];
  device_list: { device: string; ip: string; names: number; last: number }[];
  host_list: { host: string; tracker: boolean; via: ("app" | "site" | "device")[] }[];
}

export const UNKNOWN_ORG = "Unknown network";

interface Acc {
  org: string; last: number; tracker: boolean;
  sites: Map<string, { third_party: boolean; hosts: Set<string> }>;
  apps: Map<string, { hosts: Set<string>; last: number }>;
  devices: Map<string, { device: string; names: Set<string>; last: number }>;
  hosts: Map<string, { tracker: boolean; via: Set<"app" | "site" | "device"> }>;
}

export class CompaniesDb {
  private opensQ; private dnsQ; private orgQ; private deviceNamesQ;
  private orgCache = new Map<string, string>();

  constructor(private db: Database, private geo: Geo | null, private sites: { loads(window: string, browsersOnly?: boolean): Load[] }) {
    this.opensQ = db.query<{ ts: number; process: string; ip: string; org: string | null; host: string | null }, [number]>(`
      SELECT e.ts, e.process, e.ip, i.org,
             (SELECT n.name FROM ip_name n WHERE n.ip = e.ip ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host
      FROM events e LEFT JOIN ip_info i USING (ip) WHERE e.ts >= ?1`);
    this.dnsQ = db.query<{ ts: number; client: string; qname: string; answers: string | null }, [number]>(
      "SELECT ts, client, qname, answers FROM dns WHERE ts >= ?1 AND answers IS NOT NULL AND answers != ''");
    this.orgQ = db.query<{ org: string | null }, [string]>("SELECT org FROM ip_info WHERE ip = ?1");
    this.deviceNamesQ = db.query<{ ip: string; name: string }, []>("SELECT ip, COALESCE(label, mac, ip) AS name FROM devices");
  }

  private orgOf(ip: string): string {
    const hit = this.orgCache.get(ip);
    if (hit !== undefined) return hit;
    const org = this.orgQ.get(ip)?.org ?? this.geo?.lookup(ip).org ?? UNKNOWN_ORG;
    if (this.orgCache.size > 20000) this.orgCache.clear();
    this.orgCache.set(ip, org);
    return org;
  }

  private collect(window: string): Map<string, Acc> {
    const since = sinceTs(window);
    const acc = new Map<string, Acc>();
    const get = (org: string) => acc.get(org) ?? acc.set(org, { org, last: 0, tracker: false, sites: new Map(), apps: new Map(), devices: new Map(), hosts: new Map() }).get(org)!;
    const host = (a: Acc, name: string, via: "app" | "site" | "device") => {
      const h = a.hosts.get(name) ?? a.hosts.set(name, { tracker: isTracker(name), via: new Set() }).get(name)!;
      h.via.add(via); a.tracker ||= h.tracker;
    };
    // apps on this Mac
    for (const o of this.opensQ.all(since)) {
      const a = get(o.org ?? UNKNOWN_ORG);
      const name = o.host ?? o.ip;
      const app = a.apps.get(o.process) ?? a.apps.set(o.process, { hosts: new Set(), last: 0 }).get(o.process)!;
      app.hosts.add(name); app.last = Math.max(app.last, o.ts);
      a.last = Math.max(a.last, o.ts);
      host(a, name, "app");
    }
    // sites visited
    for (const l of this.sites.loads(window, true)) {
      for (const h of l.hits) {
        const a = get(h.org ?? UNKNOWN_ORG);
        const s = a.sites.get(l.site) ?? a.sites.set(l.site, { third_party: false, hosts: new Set() }).get(l.site)!;
        s.hosts.add(h.name); s.third_party ||= h.domain !== l.site;
        a.last = Math.max(a.last, l.start);
        host(a, h.name, "site");
      }
    }
    // LAN devices, through the IPs their lookups resolved to
    const names = new Map(this.deviceNamesQ.all().map((d) => [d.ip, d.name]));
    for (const r of this.dnsQ.all(since)) {
      if (r.qname.endsWith(".arpa")) continue;
      const ip = r.answers!.split(" ")[0]!;
      const a = get(this.orgOf(ip));
      const d = a.devices.get(r.client) ?? a.devices.set(r.client, { device: names.get(r.client) ?? r.client, names: new Set(), last: 0 }).get(r.client)!;
      d.names.add(r.qname); d.last = Math.max(d.last, r.ts);
      a.last = Math.max(a.last, r.ts);
      host(a, r.qname, "device");
    }
    return acc;
  }

  private summary(a: Acc): Company {
    const third = [...a.sites.values()].filter((s) => s.third_party).length;
    return {
      org: a.org, sites: a.sites.size, third_party_sites: third, apps: a.apps.size, devices: a.devices.size, hosts: a.hosts.size,
      tracker: a.tracker, last: a.last, reach: a.sites.size + a.apps.size + a.devices.size,
    };
  }

  list(window: string): Company[] {
    return [...this.collect(window).values()].map((a) => this.summary(a))
      .sort((x, y) => y.reach - x.reach || y.hosts - x.hosts || x.org.localeCompare(y.org));
  }

  detail(org: string, window: string): CompanyDetail | null {
    const a = this.collect(window).get(org);
    if (!a) return null;
    return {
      ...this.summary(a),
      site_list: [...a.sites].map(([site, s]) => ({ site, third_party: s.third_party, hosts: s.hosts.size })).sort((x, y) => y.hosts - x.hosts),
      app_list: [...a.apps].map(([app, s]) => ({ app, hosts: s.hosts.size, last: s.last })).sort((x, y) => y.hosts - x.hosts),
      device_list: [...a.devices].map(([ip, d]) => ({ device: d.device, ip, names: d.names.size, last: d.last })).sort((x, y) => y.names - x.names),
      host_list: [...a.hosts].map(([host, h]) => ({ host, tracker: h.tracker, via: [...h.via] }))
        .sort((x, y) => Number(y.tracker) - Number(x.tracker) || y.via.length - x.via.length || x.host.localeCompare(y.host)),
    };
  }
}
