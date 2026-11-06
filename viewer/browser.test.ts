import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { BrowserDb } from "./browser";

function fresh(): BrowserDb {
  const db = new Database(":memory:");
  db.exec("CREATE TABLE ip_info (ip TEXT PRIMARY KEY, org TEXT, country TEXT)");
  db.exec("INSERT INTO ip_info VALUES ('1.1.1.1', 'Cloudflare, Inc.', 'United States')");
  return new BrowserDb(db, null);
}
const T0 = 1_700_000_000;

describe("BrowserDb", () => {
  test("ingest keeps well-formed rows and skips the rest", () => {
    const b = fresh();
    const n = b.ingest([
      { ts: T0, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "www.nytimes.com", type: "main_frame" },
      { ts: T0 + 0.3, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "cdn.optimizely.com", type: "script", ip: "1.1.1.1" },
      { ts: "nope", host: "x" }, null, { ts: T0, tab: 1 },
    ]);
    expect(n).toBe(2);
    expect(b.status()).toMatchObject({ rows: 2, first: T0, last: T0 + 0.3 });
  });

  test("loads group by tab navigation, with exact site, offsets and org from ip_info", () => {
    const b = fresh();
    b.ingest([
      { ts: T0, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "www.nytimes.com", type: "main_frame" },
      { ts: T0 + 0.3, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "cdn.optimizely.com", type: "script", ip: "1.1.1.1" },
      { ts: T0 + 0.5, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "stats.g.doubleclick.net", type: "xmlhttprequest" },
      { ts: T0 + 0.9, tab: 1, nav_ts: T0, site: "www.nytimes.com", host: "cdn.optimizely.com", type: "script" },   // repeat host
      { ts: T0 + 2, tab: 2, nav_ts: T0 + 2, site: "tripp.horbin.ski", host: "tripp.horbin.ski", type: "main_frame" },
      { ts: T0 + 40, tab: -1, nav_ts: null, site: "mail.google.com", host: "mail.google.com", type: "xmlhttprequest" },
    ]);
    const loads = b.loads(0);
    expect(loads.map((l) => [l.site, l.root, l.hits.length, l.exact])).toEqual([
      ["google.com", "mail.google.com", 1, true], ["horbin.ski", "tripp.horbin.ski", 1, true], ["nytimes.com", "www.nytimes.com", 3, true],
    ]);
    const nyt = loads[2]!;
    expect(nyt.hits[1]).toMatchObject({ name: "cdn.optimizely.com", org: "Cloudflare, Inc.", tracker: true }); // optimizely is on the tracker list
    expect(nyt.hits[1]!.offset).toBeCloseTo(0.3, 5);
    expect(nyt.hits[2]!.tracker).toBe(true);
  });

  test("siteFor matches a host to the page that requested it within a few seconds", () => {
    const b = fresh();
    b.ingest([{ ts: T0, tab: 1, nav_ts: T0, site: "github.com", host: "api.github.com", type: "xmlhttprequest" }]);
    expect(b.siteFor("api.github.com", T0 + 1.5)).toBe("github.com");
    expect(b.siteFor("api.github.com", T0 + 30)).toBeNull();
    expect(b.siteFor(null, T0)).toBeNull();
  });
});
