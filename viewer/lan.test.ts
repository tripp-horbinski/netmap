import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LanDb, BINS } from "./lan";
import { baseDomain, isTracker, sinceTs } from "./trackers";

const NOW = Date.now() / 1000;
const H = 3600;

function fixture(): Database {
  const db = new Database(join(tmpdir(), `netmap-lan-test-${process.pid}-${Date.now()}.sqlite`), { create: true });
  db.exec(`
    CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, label TEXT, first_seen REAL, last_seen REAL);
    CREATE TABLE dns (id INTEGER PRIMARY KEY, ts REAL, client TEXT, qname TEXT, qtype INTEGER,
      rcode INTEGER, answers TEXT, cached INTEGER, ms REAL);
  `);
  db.exec(`INSERT INTO devices VALUES ('192.168.1.37','aa:bb:cc:dd:ee:ff',NULL,${NOW - 48 * H},${NOW})`);
  db.exec(`INSERT INTO devices VALUES ('local',NULL,'This Mac',${NOW - 48 * H},${NOW})`);
  db.exec(`INSERT INTO devices VALUES ('192.168.1.99',NULL,'Quiet',${NOW - 48 * H},${NOW - 30 * H})`);
  const ins = db.query("INSERT INTO dns (ts, client, qname, qtype, rcode, cached) VALUES (?, ?, ?, 1, 0, 0)");
  // TV: an old domain, two tracker lookups in the last hour, one brand-new domain 10 min ago.
  ins.run(NOW - 40 * H, "192.168.1.37", "api.samsung.com");
  ins.run(NOW - 2 * H, "192.168.1.37", "api.samsung.com");
  ins.run(NOW - 0.5 * H, "192.168.1.37", "stats.g.doubleclick.net");
  ins.run(NOW - 0.4 * H, "192.168.1.37", "stats.g.doubleclick.net");
  ins.run(NOW - 600, "192.168.1.37", "cdn.new-thing.co.uk");
  ins.run(NOW - 300, "192.168.1.37", "1.1.168.192.in-addr.arpa"); // reverse lookup: never "new"
  ins.run(NOW - 3 * H, "local", "github.com");
  return db;
}

describe("trackers helpers", () => {
  test("isTracker matches on label boundary only", () => {
    expect(isTracker("stats.g.doubleclick.net")).toBe(true);
    expect(isTracker("doubleclick.net.")).toBe(true);
    expect(isTracker("notdoubleclick.net")).toBe(false);
    expect(isTracker("github.com")).toBe(false);
  });
  test("baseDomain mirrors netlog", () => {
    expect(baseDomain("a.b.example.co.uk")).toBe("example.co.uk");
    expect(baseDomain("www.GitHub.com.")).toBe("github.com");
    expect(baseDomain("10.0.0.1")).toBe("10.0.0.1");
    expect(baseDomain("localhost")).toBe("localhost");
  });
  test("sinceTs parses windows", () => {
    expect(sinceTs("all")).toBe(0);
    expect(sinceTs("1h", 1000 * H)).toBe(999 * H);
    expect(() => sinceTs("soon")).toThrow();
  });
});

describe("LanDb", () => {
  const lan = new LanDb(fixture());

  test("devices summarizes the window and keeps quiet devices", () => {
    const { devices, window } = lan.devices("24h");
    expect(window.bin_seconds).toBeCloseTo(H, 0);
    expect(devices.map((d) => d.device)).toEqual(["aa:bb:cc:dd:ee:ff", "This Mac", "Quiet"]);
    const tv = devices[0]!;
    expect(tv.lookups).toBe(5);
    expect(tv.domains).toBe(4);
    expect(tv.tracker_lookups).toBe(2);
    expect(tv.bins).toHaveLength(BINS);
    expect(tv.bins.reduce((a, b) => a + b, 0)).toBe(5);
    expect(devices[2]!.lookups).toBe(0);
  });

  test("device detail groups by base domain and finds new names", () => {
    const d = lan.device("192.168.1.37", "24h")!;
    expect(d.domains.map((r) => r.domain)).toEqual(["doubleclick.net", "in-addr.arpa", "new-thing.co.uk", "samsung.com"]);
    expect(d.domains[0]!.tracker).toBe(true);
    expect(d.trackers.map((r) => r.qname)).toEqual(["stats.g.doubleclick.net"]);
    expect(d.new_names.map((r) => r.qname)).toEqual(["cdn.new-thing.co.uk", "stats.g.doubleclick.net"]);
    expect(lan.device("192.168.1.37", "all")!.new_names).toEqual([]);
    expect(lan.device("10.9.9.9", "24h")).toBeNull();
  });

  test("rename writes the label and clears it with an empty string", () => {
    expect(lan.rename("192.168.1.37", " Living room TV ")).toBe(true);
    expect(lan.devices("1h").devices[0]!.device).toBe("Living room TV");
    expect(lan.rename("192.168.1.37", "")).toBe(true);
    expect(lan.devices("1h").devices[0]!.device).toBe("aa:bb:cc:dd:ee:ff");
    expect(lan.rename("10.9.9.9", "x")).toBe(false);
  });
});
