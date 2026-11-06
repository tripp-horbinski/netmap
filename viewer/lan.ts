// LAN side of the database: what every device asked the resolver (`netlog resolve`).
// Mirrors netlog's `devices`, `device` and `lookups` reports, with the tracker and
// base-domain helpers applied in TypeScript (see trackers.ts).
import { Database } from "bun:sqlite";
import { baseDomain, isTracker, sinceTs } from "./trackers";

export const BINS = 24;

export interface DeviceSummary {
  ip: string; mac: string | null; label: string | null;
  /** label, else MAC, else IP: the same display name as the `lookups` view. */
  device: string;
  first_seen: number; last_seen: number;
  lookups: number; domains: number; tracker_lookups: number;
  /** Lookups per bin across the window, oldest first. */
  bins: number[];
}

export interface DomainRow { domain: string; lookups: number; hosts: number; tracker: boolean; last: number }
export interface NameRow { qname: string; lookups: number; tracker: boolean; first: number; last: number }

export interface DeviceDetail {
  device: DeviceSummary;
  window: { since: number; now: number; start: number; bin_seconds: number };
  domains: DomainRow[];
  trackers: NameRow[];
  /** Names this device had never looked up before the window began. */
  new_names: NameRow[];
  /** Lookups by local weekday and hour: 7 rows of 24, Sunday first, for the window. */
  heat: number[][];
}

interface DeviceRec { ip: string; mac: string | null; label: string | null; first_seen: number; last_seen: number }
interface NameAgg { client: string; qname: string; n: number; first: number; last: number }

export class LanDb {
  private devicesQ; private namesQ; private namesForQ; private firstSeenQ; private binsQ; private minTsQ; private renameQ; private heatQ;

  constructor(private db: Database) {
    this.devicesQ = db.query<DeviceRec, []>("SELECT ip, mac, label, first_seen, last_seen FROM devices ORDER BY last_seen DESC");
    this.namesQ = db.query<NameAgg, [number]>(
      `SELECT client, qname, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last
       FROM dns WHERE ts >= ?1 GROUP BY client, qname`);
    this.namesForQ = db.query<NameAgg, [number, string]>(
      `SELECT client, qname, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last
       FROM dns WHERE ts >= ?1 AND client = ?2 GROUP BY qname`);
    this.firstSeenQ = db.query<{ qname: string; first: number }, [string]>(
      "SELECT qname, MIN(ts) AS first FROM dns WHERE client = ?1 GROUP BY qname");
    this.binsQ = db.query<{ client: string; b: number; n: number }, [number, number]>(
      `SELECT client, CAST((ts - ?1) / ?2 AS INTEGER) AS b, COUNT(*) AS n
       FROM dns WHERE ts >= ?1 GROUP BY client, b`);
    this.minTsQ = db.query<{ t: number | null }, []>("SELECT MIN(ts) AS t FROM dns");
    this.heatQ = db.query<{ d: number; h: number; n: number }, [number, string]>(
      `SELECT CAST(strftime('%w', ts, 'unixepoch', 'localtime') AS INTEGER) AS d,
              CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) AS h, COUNT(*) AS n
       FROM dns WHERE ts >= ?1 AND client = ?2 GROUP BY d, h`);
    this.renameQ = db.query<{ changes: number }, [string | null, string]>(
      "UPDATE devices SET label = ?1 WHERE ip = ?2 RETURNING 1 AS changes");
  }

  /** The time axis for a window: `start` is `since`, or the first lookup ever for "all". */
  private axis(window: string) {
    const now = Date.now() / 1000;
    const since = sinceTs(window, now);
    const start = since > 0 ? since : (this.minTsQ.get()?.t ?? now - 3600);
    const bin_seconds = Math.max(1, (now - start) / BINS);
    return { since, now, start, bin_seconds };
  }

  private binsByClient(start: number, width: number): Map<string, number[]> {
    const out = new Map<string, number[]>();
    for (const { client, b, n } of this.binsQ.all(start, width)) {
      const bins = out.get(client) ?? new Array<number>(BINS).fill(0);
      bins[Math.min(BINS - 1, Math.max(0, b))]! += n;
      out.set(client, bins);
    }
    return out;
  }

  private summarize(rec: DeviceRec, names: NameAgg[], bins: number[] | undefined): DeviceSummary {
    const domains = new Set<string>();
    let lookups = 0, tracker_lookups = 0;
    for (const r of names) {
      lookups += r.n;
      domains.add(baseDomain(r.qname));
      if (isTracker(r.qname)) tracker_lookups += r.n;
    }
    return {
      ...rec, device: rec.label ?? rec.mac ?? rec.ip,
      lookups, domains: domains.size, tracker_lookups,
      bins: bins ?? new Array<number>(BINS).fill(0),
    };
  }

  devices(window: string): { window: DeviceDetail["window"]; devices: DeviceSummary[] } {
    const axis = this.axis(window);
    const byClient = new Map<string, NameAgg[]>();
    for (const r of this.namesQ.all(axis.since)) {
      (byClient.get(r.client) ?? byClient.set(r.client, []).get(r.client)!).push(r);
    }
    const bins = this.binsByClient(axis.start, axis.bin_seconds);
    const devices = this.devicesQ.all()
      .map((d) => this.summarize(d, byClient.get(d.ip) ?? [], bins.get(d.ip)))
      .sort((a, b) => b.lookups - a.lookups || b.last_seen - a.last_seen);
    return { window: axis, devices };
  }

  device(ip: string, window: string): DeviceDetail | null {
    const rec = this.devicesQ.all().find((d) => d.ip === ip);
    if (!rec) return null;
    const axis = this.axis(window);
    const names = this.namesForQ.all(axis.since, ip);
    const bins = this.binsByClient(axis.start, axis.bin_seconds).get(ip);
    const device = this.summarize(rec, names, bins);

    const domains = new Map<string, DomainRow>();
    for (const r of names) {
      const d = baseDomain(r.qname);
      const row = domains.get(d) ?? { domain: d, lookups: 0, hosts: 0, tracker: false, last: 0 };
      row.lookups += r.n; row.hosts += 1; row.last = Math.max(row.last, r.last);
      row.tracker ||= isTracker(r.qname);
      domains.set(d, row);
    }
    const toRow = (r: NameAgg): NameRow =>
      ({ qname: r.qname, lookups: r.n, tracker: isTracker(r.qname), first: r.first, last: r.last });
    const trackers = names.filter((r) => isTracker(r.qname)).map(toRow).sort((a, b) => b.lookups - a.lookups);
    const firstEver = new Map(this.firstSeenQ.all(ip).map((r) => [r.qname, r.first]));
    // Reverse lookups (in-addr.arpa, ip6.arpa) are new every time and say nothing; skip them here.
    const new_names = axis.since > 0
      ? names.filter((r) => !r.qname.endsWith(".arpa") && (firstEver.get(r.qname) ?? 0) >= axis.since)
          .map(toRow).sort((a, b) => b.first - a.first)
      : [];
    const heat = Array.from({ length: 7 }, () => new Array<number>(24).fill(0));
    for (const { d, h, n } of this.heatQ.all(axis.since, ip)) heat[d]![h] = n;
    return {
      device, window: axis, heat,
      domains: [...domains.values()].sort((a, b) => b.lookups - a.lookups || a.domain.localeCompare(b.domain)),
      trackers, new_names,
    };
  }

  /** Same write as `netlog name`; an empty label clears it. Returns false if the IP is unknown. */
  rename(ip: string, label: string): boolean {
    const trimmed = label.trim();
    return this.renameQ.all(trimmed === "" ? null : trimmed, ip).length > 0;
  }
}
