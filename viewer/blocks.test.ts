import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { BlocksDb } from "./blocks";

const NOW = Date.now() / 1000;

describe("blocks", () => {
  test("add, list, remove, and the refused log", () => {
    const db = new Database(":memory:");
    db.exec(`
      CREATE TABLE dns (id INTEGER PRIMARY KEY, ts REAL, client TEXT, qname TEXT, qtype INTEGER, rcode INTEGER, answers TEXT, cached INTEGER, ms REAL, blocked TEXT);
      CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, label TEXT, first_seen REAL, last_seen REAL);
      INSERT INTO devices VALUES ('192.168.1.37', NULL, 'Living room TV', ${NOW}, ${NOW});
      INSERT INTO dns (ts, client, qname, qtype, rcode, answers, cached, blocked) VALUES
        (${NOW - 10}, '192.168.1.37', 'stats.g.doubleclick.net', 1, 3, '', 0, 'doubleclick.net'),
        (${NOW - 5}, '192.168.1.37', 'stats.g.doubleclick.net', 1, 3, '', 0, 'doubleclick.net'),
        (${NOW - 3}, 'local', 'www.google.com', 1, 0, '1.2.3.4', 0, NULL);
    `);
    const b = new BlocksDb(db);
    expect(b.list()).toEqual([]);
    b.add("DoubleClick.net.", "*", "ads");
    b.add("@trackers", "192.168.1.37");
    expect(b.list().map((r) => [r.pattern, r.device])).toEqual([["@trackers", "192.168.1.37"], ["doubleclick.net", "*"]]);
    expect(() => b.add("not a domain")).toThrow();
    const refused = b.refused("1h");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ device: "Living room TV", qname: "stats.g.doubleclick.net", rule: "doubleclick.net", n: 2 });
    b.remove("doubleclick.net");
    expect(b.list()).toHaveLength(1);
  });
});
