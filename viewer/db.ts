// Read side of data/netmap.sqlite. The schema is owned by `netlog record`; the viewer
// only reads it, except for /api/reset which clears the `conn` table.
import { Database } from "bun:sqlite";

export interface Connection {
  process: string; ip: string; port: number; proto: string;
  first_seen: number; last_seen: number; samples: number;
  hostname: string | null; city: string | null; region: string | null; country: string | null;
  lat: number | null; lon: number | null; asn: number | null; org: string | null;
  names: string[];
}

export interface OpenEvent {
  id: number; ts: number; app: string; ip: string; port: number; proto: string;
  host: string | null; org: string | null; city: string | null; country: string | null;
  lat: number | null; lon: number | null;
}

export class NetmapDb {
  readonly db: Database;
  private connQ; private namesQ; private maxEventQ; private eventsQ; private metaQ; private resetQ;

  constructor(path: string) {
    this.db = new Database(path, { readwrite: true, create: false });
    this.db.exec("PRAGMA busy_timeout = 5000");
    this.connQ = this.db.query<Omit<Connection, "names">, []>(
      `SELECT c.process, c.ip, c.port, c.proto, c.first_seen, c.last_seen, c.samples,
              i.hostname, i.city, i.region, i.country, i.lat, i.lon, i.asn, i.org
       FROM conn c LEFT JOIN ip_info i USING (ip)`);
    this.namesQ = this.db.query<{ ip: string; name: string }, []>(
      `SELECT ip, name FROM ip_name WHERE ip IN (SELECT ip FROM conn)
       ORDER BY ip, source='sni' DESC, last_seen DESC`);
    this.maxEventQ = this.db.query<{ id: number }, []>("SELECT COALESCE(MAX(id), 0) AS id FROM events");
    this.eventsQ = this.db.query<OpenEvent, [number]>(
      `SELECT e.id, e.ts, e.process AS app, e.ip, e.port, e.proto,
              (SELECT n.name FROM ip_name n WHERE n.ip = e.ip
                 ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1) AS host,
              i.org, i.city, i.country, i.lat, i.lon
       FROM events e LEFT JOIN ip_info i USING (ip)
       WHERE e.id > ?1 ORDER BY e.id LIMIT 200`);
    this.metaQ = this.db.query<{ value: string }, [string]>("SELECT value FROM meta WHERE key = ?1");
    this.resetQ = this.db.query("DELETE FROM conn");
  }

  connections(): Connection[] {
    const names = new Map<string, string[]>();
    for (const { ip, name } of this.namesQ.all()) {
      const list = names.get(ip) ?? [];
      if (list.length < 3) list.push(name);
      names.set(ip, list);
    }
    return this.connQ.all().map((c) => ({ ...c, names: names.get(c.ip) ?? [] }));
  }

  maxEventId(): number {
    return this.maxEventQ.get()!.id;
  }

  /** Connection opens newer than `after`, held ~1 s so their TLS hostname can land. */
  eventsAfter(after: number): OpenEvent[] {
    const cutoff = Date.now() / 1000 - 1.0;
    const out: OpenEvent[] = [];
    for (const e of this.eventsQ.all(after)) {
      if (e.ts > cutoff) break;
      out.push(e);
    }
    return out;
  }

  meta(key: string): string | null {
    return this.metaQ.get(key)?.value ?? null;
  }

  reset(): void {
    this.resetQ.run();
  }
}
