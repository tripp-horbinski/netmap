import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { FindingsDb } from "./findings";
import type { Load } from "./sites";

const NOW = Date.now() / 1000;
const H = 3600, D = 86400;
// Keep every fixture timestamp inside the same local day as NOW's hour-of-day comparisons expect.
function fixture(): { db: Database; loads: Load[] } {
  const db = new Database(":memory:");
  db.exec(`
    CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, process TEXT, ip TEXT, port INTEGER, proto TEXT, via TEXT);
    CREATE TABLE ip_info (ip TEXT PRIMARY KEY, org TEXT, country TEXT);
    CREATE TABLE ip_name (ip TEXT, name TEXT, source TEXT, last_seen REAL);
    CREATE TABLE dns (id INTEGER PRIMARY KEY, ts REAL, client TEXT, qname TEXT, qtype INTEGER, rcode INTEGER, answers TEXT, cached INTEGER, ms REAL);
    CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, label TEXT, first_seen REAL, last_seen REAL);
    CREATE TABLE apps (process TEXT PRIMARY KEY, path TEXT, bundle_id TEXT, name TEXT, version TEXT, feed_url TEXT, first_seen REAL);
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    INSERT INTO ip_info VALUES ('1.1.1.1','Spotify AB','SE'),('2.2.2.2','Fastly, Inc.','US'),('3.3.3.3','Google LLC','US');
    INSERT INTO ip_name VALUES ('2.2.2.2','api.fastly.com','sni',${NOW}),('3.3.3.3','stats.g.doubleclick.net','sni',${NOW});
    INSERT INTO devices VALUES ('192.168.1.37',NULL,'Living room TV',${NOW - 10 * D},${NOW});
    INSERT INTO apps VALUES ('Zentty','/Applications/Zentty.app/Contents/MacOS/Zentty','be.zenjoy.zentty','Zentty','0.6.0','https://releases.zentty.org/appcast.xml',${NOW});
    INSERT INTO meta VALUES ('heartbeat','${NOW - 30}'),('pktap','pktap on: naming connections on their first packet');
  `);
  const ev = db.query("INSERT INTO events (ts, process, ip, port, proto) VALUES (?, ?, ?, 443, 'TCP')");
  // Spotify has talked to Spotify AB for days; today it reached Fastly (new company) and doubleclick (tracker).
  for (let d = 1; d <= 6; d++) ev.run(NOW - d * D, "Spotify Helper", "1.1.1.1");
  ev.run(NOW - 20 * 60, "Spotify Helper", "1.1.1.1");
  ev.run(NOW - 15 * 60, "Spotify Helper", "2.2.2.2");
  ev.run(NOW - 10 * 60, "Spotify Helper", "3.3.3.3");
  // Zentty: first connection ever, 5 minutes ago.
  ev.run(NOW - 5 * 60, "Zentty", "2.2.2.2");
  // The TV: a few lookups a day at this hour for 5 days, then 60 in the current hour.
  const dns = db.query("INSERT INTO dns (ts, client, qname, qtype, rcode, cached) VALUES (?, ?, ?, 1, 0, 0)");
  for (let d = 1; d <= 5; d++) for (let i = 0; i < 2; i++) dns.run(NOW - d * D - i, "192.168.1.37", "api.samsung.com");
  for (let i = 0; i < 60; i++) dns.run(NOW - i, "192.168.1.37", `cdn${i}.example.net`);
  // Sites: nytimes had two clean loads last week; today it pulled in Datadog.
  const load = (start: number, orgs: string[]): Load => ({
    app: "Google Chrome Helper", site: "nytimes.com", root: "www.nytimes.com", strong: true, start, end: start + 2,
    hits: [{ name: "www.nytimes.com", domain: "nytimes.com", org: "NYT", country: null, tracker: false, offset: 0, ip: "9.9.9.9" },
      ...orgs.map((org, i) => ({ name: `${i}.${org.toLowerCase().replace(/[^a-z]/g, "")}.com`, domain: `${org.toLowerCase().replace(/[^a-z]/g, "")}.com`, org, country: null, tracker: org === "Datadog, Inc.", offset: 0.3, ip: "8.8.8.8" }))],
  });
  const loads = [load(NOW - 5 * D, ["Fastly, Inc."]), load(NOW - 3 * D, ["Fastly, Inc."]), load(NOW - 30 * 60, ["Fastly, Inc.", "Datadog, Inc."])];
  return { db, loads };
}

describe("findings", () => {
  test("detects first contact, a tracker, a new app, off-hours lookups and a new third party", () => {
    const { db, loads } = fixture();
    const f = new FindingsDb(db, { loads: () => loads });
    const r = f.report("1h");
    const kinds = r.findings.map((x) => `${x.kind}:${x.entity}`);
    expect(kinds).toContain("first-contact:Spotify Helper");
    expect(r.findings.find((x) => x.key === "first-contact:Spotify Helper:Fastly, Inc.")?.score).toBe(65);
    expect(r.findings.find((x) => x.key.startsWith("first-contact:Spotify Helper:tracker"))?.score).toBe(85);
    expect(r.findings.find((x) => x.kind === "new-app")?.title).toContain("Zentty 0.6.0");
    expect(r.findings.find((x) => x.kind === "new-third-party")?.title).toBe("nytimes.com now pulls in Datadog, Inc. (tracker)");
    const tv = r.findings.find((x) => x.kind === "off-hours");
    expect(tv?.entity).toBe("Living room TV");
    expect(tv?.title).toContain("60 times");
    expect(r.findings.some((x) => x.kind === "health")).toBe(false);
    expect(r.findings[0]!.score).toBeGreaterThanOrEqual(r.findings[r.findings.length - 1]!.score);
    expect(r.baseline.days).toBeGreaterThan(5);
    expect(r.baseline.top_apps[0]!.app).toBe("Spotify Helper");
  });

  test("expected findings are hidden and listed in the baseline", () => {
    const { db, loads } = fixture();
    const f = new FindingsDb(db, { loads: () => loads });
    const before = f.report("1h");
    const key = before.findings.find((x) => x.kind === "new-app")!.key;
    f.expect(key, "Zentty is fine");
    const after = f.report("1h");
    expect(after.findings.some((x) => x.key === key)).toBe(false);
    expect(after.expected_hidden).toBe(1);
    expect(after.baseline.expected[0]).toMatchObject({ key, title: "Zentty is fine" });
    f.expect(key, "", false);
    expect(f.report("1h").findings.some((x) => x.key === key)).toBe(true);
  });

  test("a stale recorder is the loudest finding", () => {
    const { db, loads } = fixture();
    db.exec(`UPDATE meta SET value = '${NOW - 3600}' WHERE key = 'heartbeat'`);
    const r = new FindingsDb(db, { loads: () => loads }).report("1h");
    expect(r.findings[0]).toMatchObject({ kind: "health", score: 95 });
  });
});
