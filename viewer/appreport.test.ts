import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { AppReportDb } from "./appreport";
import { classifyHost, firstPartyDomains } from "./classify";
import { appName } from "./appname";

const NOW = Date.now() / 1000;

describe("classify", () => {
  test("first party from the bundle id and feed, then update, telemetry, ads, cdn, other", () => {
    const fp = firstPartyDomains("Spotify", "com.spotify.client", null);
    expect(fp.has("spotify.com")).toBe(true);
    expect(classifyHost("api.spotify.com", "Spotify AB", fp)).toBe("first-party");
    expect(classifyHost("updates.spotify.com", "Spotify AB", fp)).toBe("update");
    expect(classifyHost("o123.ingest.sentry.io", "Sentry", fp)).toBe("telemetry");
    expect(classifyHost("stats.g.doubleclick.net", "Google LLC", fp)).toBe("ads");
    expect(classifyHost("d1.cloudfront.net", "Amazon.com, Inc.", fp)).toBe("cdn");
    expect(classifyHost("example.net", "Fastly, Inc.", fp)).toBe("cdn");
    expect(classifyHost("example.org", "Example", fp)).toBe("other");
    expect(firstPartyDomains("Zentty", "be.zenjoy.zentty", "https://releases.zentty.org/appcast.xml")).toEqual(new Set(["zenjoy.be", "zentty.org"]));
    expect(classifyHost("releases.zentty.org", null, firstPartyDomains("Zentty", "be.zenjoy.zentty", "https://releases.zentty.org/appcast.xml"))).toBe("update");
  });
  test("appName mirrors the page: helpers, versions, tags", () => {
    const apps = new Map([["2.1.319", { process: "2.1.319", name: "Claude Code", version: "2.1.319", path: null, bundle_id: null, feed_url: null }]]);
    expect(appName("Google Chrome Helper (Aperitif)", apps)).toBe("Chrome");
    expect(appName("Google Chrome Helper [headless]", apps)).toBe("Chrome (headless)");
    expect(appName("2.1.319", apps)).toBe("Claude Code 2.1.319");
    expect(appName("Spotify Helper", apps)).toBe("Spotify");
  });
});

describe("app report", () => {
  test("merges helpers into one card with classified hosts, companies and launchers", () => {
    const db = new Database(":memory:");
    db.exec(`
      CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, process TEXT, ip TEXT, port INTEGER, proto TEXT, via TEXT);
      CREATE TABLE ip_info (ip TEXT PRIMARY KEY, org TEXT, country TEXT);
      CREATE TABLE ip_name (ip TEXT, name TEXT, source TEXT, last_seen REAL);
      CREATE TABLE apps (process TEXT PRIMARY KEY, path TEXT, bundle_id TEXT, name TEXT, version TEXT, feed_url TEXT, first_seen REAL);
      INSERT INTO ip_info VALUES ('5.5.5.5','Spotify AB','Sweden'),('3.3.3.3','Google LLC','United States'),('2.2.2.2','Datadog, Inc.','United States');
      INSERT INTO ip_name VALUES ('5.5.5.5','api.spotify.com','sni',${NOW}),('3.3.3.3','stats.g.doubleclick.net','sni',${NOW}),('2.2.2.2','intake.datadoghq.com','sni',${NOW});
      INSERT INTO apps VALUES ('Spotify Helper','/Applications/Spotify.app/Contents/Frameworks/x/Spotify Helper','com.spotify.client','Spotify','1.2.3',NULL,${NOW});
      INSERT INTO events (ts, process, ip, port, proto, via) VALUES
        (${NOW - 50},'Spotify Helper','5.5.5.5',443,'TCP',NULL),(${NOW - 40},'Spotify Helper (GPU)','5.5.5.5',443,'TCP',NULL),
        (${NOW - 30},'Spotify Helper','3.3.3.3',443,'TCP',NULL),(${NOW - 20},'Spotify Helper','2.2.2.2',443,'TCP',NULL),
        (${NOW - 10},'curl','5.5.5.5',443,'TCP','Zentty');
    `);
    const r = new AppReportDb(db);
    const list = r.list("1h");
    expect(list.map((a) => a.name)).toEqual(["Spotify", "curl"]);
    const s = list[0]!;
    expect(s).toMatchObject({ opens: 4, hosts: 3, destinations: 3, companies: 3, bundle_id: "com.spotify.client", version: "1.2.3" });
    expect(s.by_class).toMatchObject({ "first-party": 1, ads: 1, telemetry: 1, other: 0 });
    const card = r.card("Spotify", "1h")!;
    expect(card.host_list.map((h) => [h.host, h.cls])).toEqual([["api.spotify.com", "first-party"], ["intake.datadoghq.com", "telemetry"], ["stats.g.doubleclick.net", "ads"]]);
    expect(card.host_list[0]!.opens).toBe(2);
    expect(card.company_list[0]).toMatchObject({ org: "Spotify AB", hosts: 1 });
    expect(card.country_list.map((c) => c.country)).toEqual(["United States", "Sweden"]);
    expect(card.bins.reduce((a, b) => a + b, 0)).toBe(4);
    expect(r.card("curl", "1h")!.via_list).toEqual([{ via: "Zentty", opens: 1 }]);
    expect(r.card("nope", "1h")).toBeNull();
  });
});
