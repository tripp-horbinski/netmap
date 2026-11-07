// What changed against this household's own baseline. Each detector compares the window to the
// entity's history (an app's companies, a device's hour-of-day rhythm, a site's third parties) and
// emits findings shaped like `netlog suggest` plus evidence and actions. "Expect" marks a finding's
// key as normal; it stops firing and counts toward the baseline instead.
import { Database } from "bun:sqlite";
import { baseDomain, isTracker, sinceTs } from "./trackers";
import type { Load } from "./sites";

export interface Finding {
  key: string;            // stable id: kind + entity, what Expect stores
  kind: "first-contact" | "off-hours" | "new-third-party" | "new-app" | "health";
  score: number;          // 0-100, higher = look sooner
  title: string;          // one plain sentence
  detail: string;         // the evidence in one line
  entity: string;         // app / device / site / "recorder"
  ts: number;             // when it started in the window
  links: { label: string; href: string }[];
  /** A domain the resolver could refuse to make this stop, when the finding is about one. */
  block?: string;
}

export interface Baseline {
  /** Days of history behind the comparisons (0 = nothing before the window). */
  days: number;
  devices: number;
  apps: number;
  /** Share of opens per app over the baseline, top few. */
  top_apps: { app: string; share: number }[];
  /** Hours of the day with clearly more opens than average, as ranges like "9–11". */
  busy_hours: string[];
  /** Keys the user marked as expected, newest first. */
  expected: { key: string; ts: number; title: string }[];
}

export interface FindingsReport {
  window: { since: number; now: number };
  baseline: Baseline;
  findings: Finding[];
  /** Findings hidden because they were expected. */
  expected_hidden: number;
}

const EXPECTED_KEY = "viewer.expected";
const HISTORY_DAYS = 30;
const UNKNOWN_ORG = "Unknown network";

interface OpenRow { ts: number; process: string; ip: string; org: string | null; host: string | null }

export class FindingsDb {
  private opensQ; private histQ; private firstSeenQ; private hourlyQ; private dnsHourlyQ; private appsQ; private metaQ; private setMetaQ; private minTsQ; private deviceNamesQ; private dayQ;

  constructor(private db: Database, private sites: { loads(window: string, browsersOnly?: boolean): Load[] }) {
    const openSql = (where: string) => `
      SELECT e.ts, e.process, e.ip, i.org,
             (SELECT n.name FROM ip_name n WHERE n.ip = e.ip ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host
      FROM events e LEFT JOIN ip_info i USING (ip) WHERE ${where} ORDER BY e.ts`;
    this.opensQ = db.query<OpenRow, [number]>(openSql("e.ts >= ?1"));
    this.histQ = db.query<{ process: string; org: string | null; domain: string | null }, [number, number]>(`
      SELECT DISTINCT e.process, i.org,
             (SELECT n.name FROM ip_name n WHERE n.ip = e.ip ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS domain
      FROM events e LEFT JOIN ip_info i USING (ip) WHERE e.ts >= ?1 AND e.ts < ?2`);
    this.firstSeenQ = db.query<{ process: string; first: number; n: number }, [number]>(
      "SELECT process, MIN(ts) AS first, COUNT(*) AS n FROM events GROUP BY process HAVING first >= ?1");
    this.hourlyQ = db.query<{ process: string; day: string; hour: number; n: number }, [number]>(`
      SELECT process, date(ts, 'unixepoch', 'localtime') AS day, CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS hour, COUNT(*) AS n
      FROM events WHERE ts >= ?1 GROUP BY process, day, hour`);
    this.dnsHourlyQ = db.query<{ client: string; day: string; hour: number; n: number }, [number]>(`
      SELECT client, date(ts, 'unixepoch', 'localtime') AS day, CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS hour, COUNT(*) AS n
      FROM dns WHERE ts >= ?1 GROUP BY client, day, hour`);
    this.appsQ = db.query<{ process: string; name: string | null; version: string | null; feed_url: string | null; bundle_id: string | null }, []>(
      "SELECT process, name, version, feed_url, bundle_id FROM apps");
    this.metaQ = db.query<{ value: string }, [string]>("SELECT value FROM meta WHERE key = ?1");
    this.setMetaQ = db.query<void, [string, string]>("INSERT INTO meta VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    this.minTsQ = db.query<{ t: number | null }, []>("SELECT MIN(ts) AS t FROM events");
    this.deviceNamesQ = db.query<{ ip: string; name: string }, []>("SELECT ip, COALESCE(label, mac, ip) AS name FROM devices");
    // The local calendar day of a timestamp, by SQLite's clock, so it matches the day() in the hourly
    // queries whatever zone the JS runtime thinks it is in (bun test runs in UTC).
    this.dayQ = db.query<{ d: string }, [number]>("SELECT date(?1, 'unixepoch', 'localtime') AS d");
  }

  // ---- expected ------------------------------------------------------------------------------
  expected(): Record<string, { ts: number; title: string }> {
    try { return JSON.parse(this.metaQ.get(EXPECTED_KEY)?.value ?? "{}"); } catch { return {}; }
  }
  expect(key: string, title: string, on = true): Record<string, { ts: number; title: string }> {
    const all = this.expected();
    if (on) all[key] = { ts: Date.now() / 1000, title }; else delete all[key];
    this.setMetaQ.run(EXPECTED_KEY, JSON.stringify(all));
    return all;
  }

  // ---- report --------------------------------------------------------------------------------
  report(window: string): FindingsReport {
    const now = Date.now() / 1000;
    const since = sinceTs(window, now);
    const histStart = since - HISTORY_DAYS * 86400;
    const oldest = this.minTsQ.get()?.t ?? now;
    const days = Math.max(0, (since - oldest) / 86400);
    const names = new Map(this.deviceNamesQ.all().map((d) => [d.ip, d.name]));
    const apps = new Map(this.appsQ.all().map((a) => [a.process, a]));
    const expected = this.expected();

    let findings: Finding[] = [
      ...this.firstContact(since, histStart, days),
      ...this.offHours(since, histStart, names),
      ...this.newThirdParty(since, days),
      ...this.newApp(since, days, apps),
      ...this.health(now),
    ];
    const total = findings.length;
    findings = findings.filter((f) => !(f.key in expected)).sort((a, b) => b.score - a.score || b.ts - a.ts);
    return {
      window: { since, now },
      baseline: this.baseline(histStart, since, days, names, expected),
      findings,
      expected_hidden: total - findings.length,
    };
  }

  /** An app reached a company (or a tracker domain) it had not in the previous 30 days. */
  private firstContact(since: number, histStart: number, days: number): Finding[] {
    if (days < 1) return [];
    const seenOrg = new Set<string>(), seenDomain = new Set<string>(), knownApps = new Set<string>();
    for (const h of this.histQ.all(histStart, since)) {
      knownApps.add(h.process);
      seenOrg.add(`${h.process}\u0000${h.org ?? UNKNOWN_ORG}`);
      if (h.domain) seenDomain.add(`${h.process}\u0000${baseDomain(h.domain)}`);
    }
    const byApp = new Map<string, Map<string, { ips: Set<string>; hosts: Set<string>; first: number; tracker: boolean }>>();
    for (const o of this.opensQ.all(since)) {
      if (!knownApps.has(o.process)) continue; // a brand-new app is its own finding
      const org = o.org ?? UNKNOWN_ORG;
      const domain = o.host ? baseDomain(o.host) : null;
      const tracker = !!o.host && isTracker(o.host) && !!domain && !seenDomain.has(`${o.process}\u0000${domain}`);
      if (seenOrg.has(`${o.process}\u0000${org}`) && !tracker) continue;
      const key = tracker ? `tracker ${domain}` : org;
      const m = byApp.get(o.process) ?? byApp.set(o.process, new Map()).get(o.process)!;
      const e = m.get(key) ?? m.set(key, { ips: new Set(), hosts: new Set(), first: o.ts, tracker }).get(key)!;
      e.ips.add(o.ip); if (o.host) e.hosts.add(o.host); e.first = Math.min(e.first, o.ts);
    }
    const out: Finding[] = [];
    for (const [app, m] of byApp) for (const [what, e] of m) {
      const unknown = what === UNKNOWN_ORG;
      const hosts = [...e.hosts].slice(0, 3).join(", ") || [...e.ips].slice(0, 3).join(", ");
      out.push({
        key: `first-contact:${app}:${what}`, kind: "first-contact", entity: app, ts: e.first,
        block: e.tracker ? what.slice(8) : undefined,
        score: e.tracker ? 85 : unknown ? 45 : 65,
        title: e.tracker ? `${app} started talking to a tracker, ${what.slice(8)}` : `${app} reached a new company: ${what}`,
        detail: `${e.ips.size} host${e.ips.size === 1 ? "" : "s"} (${hosts}) · never in the previous ${Math.min(HISTORY_DAYS, Math.round(days))} days`,
        links: [{ label: "map", href: `/map` }, ...(e.hosts.size ? [{ label: "trace", href: `/map#trace=${[...e.ips][0]}` }] : [])],
      });
    }
    return out;
  }

  /** An app or device far busier in some hour than its own norm for that hour of the day. */
  private offHours(since: number, histStart: number, names: Map<string, string>): Finding[] {
    const out: Finding[] = [];
    const check = (rows: { who: string; day: string; hour: number; n: number }[], kindOf: (who: string) => { entity: string; href: string; what: string }) => {
      const sinceDay = this.dayQ.get(since)!.d;
      const base = new Map<string, number[]>(); // who:hour -> counts on prior days
      const days = new Map<string, Set<string>>();
      const cur = new Map<string, { hour: number; n: number; day: string }>();
      for (const r of rows) {
        const k = `${r.who}\u0000${r.hour}`;
        if (r.day < sinceDay) {
          (base.get(k) ?? base.set(k, []).get(k)!).push(r.n);
          (days.get(r.who) ?? days.set(r.who, new Set()).get(r.who)!).add(r.day);
        } else {
          const c = cur.get(r.who);
          if (!c || r.n > c.n) cur.set(r.who, { hour: r.hour, n: r.n, day: r.day });
        }
      }
      for (const [who, c] of cur) {
        const nDays = days.get(who)?.size ?? 0;
        if (nDays < 3 || c.n < 20) continue;
        const counts = base.get(`${who}\u0000${c.hour}`) ?? [];
        const typical = counts.length ? counts.reduce((a, b) => a + b, 0) / nDays : 0; // days with nothing count as 0
        if (c.n <= 3 * Math.max(typical, 2)) continue;
        const { entity, href, what } = kindOf(who);
        const h = `${c.hour}–${(c.hour + 1) % 24}`;
        out.push({
          key: `off-hours:${entity}:${c.hour}`, kind: "off-hours", entity, ts: new Date(`${c.day}T${String(c.hour).padStart(2, "0")}:00`).getTime() / 1000,
          score: typical < 1 ? 80 : 60,
          title: `${entity} ${what} ${c.n} times between ${h}`,
          detail: `its usual for that hour is ${typical < 1 ? "nothing" : Math.round(typical)} over ${nDays} day${nDays === 1 ? "" : "s"}`,
          links: [{ label: "detail", href }],
        });
      }
    };
    check(this.dnsHourlyQ.all(histStart).map((r) => ({ who: r.client, day: r.day, hour: r.hour, n: r.n })),
      (ip) => ({ entity: names.get(ip) ?? ip, href: `/devices#${encodeURIComponent(ip)}`, what: "looked up names" }));
    check(this.hourlyQ.all(histStart).map((r) => ({ who: r.process, day: r.day, hour: r.hour, n: r.n })),
      (app) => ({ entity: app, href: `/map`, what: "opened connections" }));
    return out;
  }

  /** A site you visit pulled in a company it did not before. */
  private newThirdParty(since: number, days: number): Finding[] {
    if (days < 1) return [];
    const loads = this.sites.loads(`${HISTORY_DAYS + Math.ceil((Date.now() / 1000 - since) / 86400)}d`, true);
    const prior = new Map<string, { loads: number; orgs: Set<string> }>();
    const cur = new Map<string, Map<string, { hosts: Set<string>; first: number; tracker: boolean }>>();
    for (const l of loads) {
      if (l.start < since) {
        const p = prior.get(l.site) ?? prior.set(l.site, { loads: 0, orgs: new Set() }).get(l.site)!;
        p.loads++;
        for (const h of l.hits) if (h.domain !== l.site) p.orgs.add(h.org ?? UNKNOWN_ORG);
      } else {
        const m = cur.get(l.site) ?? cur.set(l.site, new Map()).get(l.site)!;
        for (const h of l.hits) {
          if (h.domain === l.site) continue;
          const org = h.org ?? UNKNOWN_ORG;
          const e = m.get(org) ?? m.set(org, { hosts: new Set(), first: l.start, tracker: false }).get(org)!;
          e.hosts.add(h.name); e.tracker ||= h.tracker; e.first = Math.min(e.first, l.start);
        }
      }
    }
    const out: Finding[] = [];
    for (const [site, m] of cur) {
      const p = prior.get(site);
      if (!p || p.loads < 2) continue;
      for (const [org, e] of m) {
        if (p.orgs.has(org)) continue;
        out.push({
          key: `new-third-party:${site}:${org}`, kind: "new-third-party", entity: site, ts: e.first,
          block: e.tracker ? baseDomain([...e.hosts][0]!) : undefined,
          score: e.tracker ? 75 : 55,
          title: `${site} now pulls in ${org}${e.tracker ? " (tracker)" : ""}`,
          detail: `${[...e.hosts].slice(0, 3).join(", ")} · not in its ${p.loads} earlier load${p.loads === 1 ? "" : "s"}`,
          links: [{ label: "site trace", href: `/sites#${encodeURIComponent(site)}` }],
        });
      }
    }
    return out;
  }

  /** A process made its first connection ever in this window. */
  private newApp(since: number, days: number, apps: Map<string, { name: string | null; version: string | null; feed_url: string | null }>): Finding[] {
    if (days < 1) return [];
    return this.firstSeenQ.all(since).map((r) => {
      const a = apps.get(r.process);
      const label = a?.name ? `${a.name}${a.version ? ` ${a.version}` : ""} (${r.process})` : r.process;
      const automated = /\[(headless|automated)\]/.test(r.process);
      return {
        key: `new-app:${r.process}`, kind: "new-app" as const, entity: r.process, ts: r.first,
        score: automated ? 40 : a?.feed_url ? 35 : 50,
        title: `New app on the network: ${label}`,
        detail: `${r.n} connection${r.n === 1 ? "" : "s"} since ${new Date(r.first * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}${a?.feed_url ? ` · updates from ${new URL(a.feed_url).hostname}` : ""}`,
        links: [{ label: "map", href: "/map" }],
      };
    });
  }

  /** The instrument itself: is the recorder alive, is pktap naming processes. */
  private health(now: number): Finding[] {
    const out: Finding[] = [];
    const hb = Number(this.metaQ.get("heartbeat")?.value ?? 0);
    if (!hb || now - hb > 120) {
      out.push({ key: "health:recorder", kind: "health", entity: "recorder", ts: hb || now, score: 95,
        title: "The recorder is not running", detail: hb ? `last data ${Math.round((now - hb) / 60)} min ago` : "no heartbeat yet",
        links: [{ label: "README", href: "https://github.com/tripp-horbinski/netmap#run-it-as-a-service" }] });
    }
    const pktap = this.metaQ.get("pktap")?.value ?? "";
    if (pktap && !pktap.startsWith("pktap on")) {
      out.push({ key: "health:pktap", kind: "health", entity: "recorder", ts: now, score: 30,
        title: "Processes are named by lsof polling, not pktap", detail: pktap, links: [] });
    }
    return out;
  }

  private baseline(histStart: number, since: number, days: number, names: Map<string, string>, expected: Record<string, { ts: number; title: string }>): Baseline {
    const byApp = new Map<string, number>(), byHour = new Array<number>(24).fill(0);
    let total = 0;
    for (const r of this.hourlyQ.all(histStart)) {
      byApp.set(r.process, (byApp.get(r.process) ?? 0) + r.n); byHour[r.hour]! += r.n; total += r.n;
    }
    const top_apps = [...byApp].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([app, n]) => ({ app, share: total ? n / total : 0 }));
    const mean = total / 24;
    const busy: number[] = byHour.map((n, h) => (n > 1.5 * mean && n > 0 ? h : -1)).filter((h) => h >= 0);
    const busy_hours: string[] = [];
    for (let i = 0; i < busy.length; i++) {
      let j = i;
      while (j + 1 < busy.length && busy[j + 1] === busy[j]! + 1) j++;
      busy_hours.push(i === j ? `${busy[i]}` : `${busy[i]}–${busy[j]! + 1}`);
      i = j;
    }
    const devices = new Set(this.dnsHourlyQ.all(histStart).map((r) => r.client)).size;
    return {
      days: Math.round(days * 10) / 10, devices: Math.max(devices, names.size ? 0 : 0), apps: byApp.size, top_apps, busy_hours,
      expected: Object.entries(expected).map(([key, v]) => ({ key, ...v })).sort((a, b) => b.ts - a.ts),
    };
  }
}
