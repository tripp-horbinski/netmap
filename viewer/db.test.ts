import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NetmapDb } from "./db";

function fixture(): string {
  const path = join(tmpdir(), `netmap-viewer-test-${process.pid}-${Date.now()}.sqlite`);
  const db = new Database(path, { create: true });
  db.exec(`
    CREATE TABLE conn (process TEXT, ip TEXT, port INTEGER, proto TEXT, first_seen REAL,
      last_seen REAL, samples INTEGER DEFAULT 1, PRIMARY KEY (process, ip, port, proto));
    CREATE TABLE ip_info (ip TEXT PRIMARY KEY, hostname TEXT, city TEXT, region TEXT,
      country TEXT, lat REAL, lon REAL, asn INTEGER, org TEXT);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, process TEXT, ip TEXT, port INTEGER, proto TEXT);
    CREATE TABLE ip_name (ip TEXT, name TEXT, source TEXT, last_seen REAL, PRIMARY KEY (ip, name));
  `);
  const now = Date.now() / 1000;
  db.exec(`INSERT INTO conn VALUES ('curl','1.1.1.1',443,'TCP',${now - 10},${now},5)`);
  db.exec(`INSERT INTO ip_info VALUES ('1.1.1.1','one.one.one.one','Sydney','NSW','Australia',-33.8,151.2,13335,'Cloudflare')`);
  db.exec(`INSERT INTO meta VALUES ('sniffer','capturing on en0')`);
  for (const [name, source, seen] of [["dns-a", "dns", 1], ["dns-b", "dns", 2], ["dns-c", "dns", 3], ["sni-host", "sni", 0]]) {
    db.exec(`INSERT INTO ip_name VALUES ('1.1.1.1','${name}','${source}',${seen})`);
  }
  db.exec(`INSERT INTO events VALUES (1,${now - 5},'curl','1.1.1.1',443,'TCP')`); // old enough to send
  db.exec(`INSERT INTO events VALUES (2,${now - 0.2},'curl','1.1.1.1',443,'TCP')`); // held for SNI
  db.close();
  return path;
}

describe("NetmapDb", () => {
  const db = new NetmapDb(fixture());

  test("connections join geo info and cap names at three, SNI first", () => {
    const [c] = db.connections();
    expect(c!.org).toBe("Cloudflare");
    expect(c!.names).toHaveLength(3);
    expect(c!.names[0]).toBe("sni-host");
  });

  test("eventsAfter holds events younger than one second", () => {
    const events = db.eventsAfter(0);
    expect(events.map((e) => e.id)).toEqual([1]);
    expect(events[0]!.host).toBe("sni-host");
    expect(events[0]!.app).toBe("curl");
  });

  test("meta and reset", () => {
    expect(db.meta("sniffer")).toBe("capturing on en0");
    expect(db.meta("missing")).toBeNull();
    db.reset();
    expect(db.connections()).toHaveLength(0);
    expect(db.maxEventId()).toBe(2);
  });
});
