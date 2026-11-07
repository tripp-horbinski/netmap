// The resolver's block list, shared with `netlog block`: rules in the `blocks` table (pattern,
// device "*" or ip), and the lookups it refused (`dns.blocked` names the rule that fired).
import { Database } from "bun:sqlite";
import { sinceTs } from "./trackers";

export interface Block { pattern: string; device: string; source: string; note: string | null; created: number }
export interface Refused { device: string; ip: string; qname: string; rule: string; n: number; last: number }

export const TRACKERS = "@trackers";

export class BlocksDb {
  private listQ; private addQ; private removeQ; private refusedQ; private hasBlocked: boolean;
  constructor(private db: Database) {
    db.exec(`CREATE TABLE IF NOT EXISTS blocks (
      pattern TEXT NOT NULL, device TEXT NOT NULL DEFAULT '*', source TEXT NOT NULL DEFAULT 'user',
      note TEXT, created REAL NOT NULL, PRIMARY KEY (pattern, device))`);
    this.listQ = db.query<Block, []>("SELECT pattern, device, source, note, created FROM blocks ORDER BY source, pattern, device");
    this.addQ = db.query<void, [string, string, string | null, number]>(
      "INSERT INTO blocks (pattern, device, source, note, created) VALUES (?1, ?2, 'user', ?3, ?4) ON CONFLICT(pattern, device) DO UPDATE SET note = COALESCE(excluded.note, blocks.note)");
    this.removeQ = db.query<void, [string, string]>("DELETE FROM blocks WHERE pattern = ?1 AND device = ?2");
    this.hasBlocked = db.query<{ name: string }, []>("PRAGMA table_info(dns)").all().some((c) => c.name === "blocked");
    this.refusedQ = db.query<Refused, [number]>(`
      SELECT COALESCE(v.label, v.mac, d.client) AS device, d.client AS ip, d.qname, d.blocked AS rule, COUNT(*) AS n, MAX(d.ts) AS last
      FROM dns d LEFT JOIN devices v ON v.ip = d.client
      WHERE d.blocked IS NOT NULL AND d.ts >= ?1 GROUP BY d.client, d.qname, d.blocked ORDER BY n DESC, last DESC`);
  }

  list(): Block[] { return this.listQ.all(); }

  /** Normalizes like the CLI: lower case, no trailing dot; "@trackers" is allowed as is. */
  add(pattern: string, device = "*", note: string | null = null): Block[] {
    const p = pattern.trim().replace(/\.$/, "").toLowerCase();
    if (!p || /\s/.test(p)) throw new Error(`bad pattern ${JSON.stringify(pattern)}`);
    this.addQ.run(p, device.trim() || "*", note, Date.now() / 1000);
    return this.list();
  }

  remove(pattern: string, device = "*"): Block[] {
    this.removeQ.run(pattern.trim().toLowerCase(), device.trim() || "*");
    return this.list();
  }

  refused(window: string): Refused[] {
    if (!this.hasBlocked) return [];
    return this.refusedQ.all(sinceTs(window));
  }
}
