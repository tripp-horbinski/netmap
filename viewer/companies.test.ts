import { describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { CompaniesDb, UNKNOWN_ORG } from "./companies";
import type { Load } from "./sites";

const NOW = Date.now() / 1000;

function fixture() {
  const db = new Database(":memory:");
  db.exec(`
    CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, process TEXT, ip TEXT, port INTEGER, proto TEXT, via TEXT);
    CREATE TABLE ip_info (ip TEXT PRIMARY KEY, org TEXT, country TEXT);
    CREATE TABLE ip_name (ip TEXT, name TEXT, source TEXT, last_seen REAL);
    CREATE TABLE dns (id INTEGER PRIMARY KEY, ts REAL, client TEXT, qname TEXT, qtype INTEGER, rcode INTEGER, answers TEXT, cached INTEGER, ms REAL);
    CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, label TEXT, first_seen REAL, last_seen REAL);
    INSERT INTO ip_info VALUES ('3.3.3.3','Google LLC','US'),('1.1.1.1','Cloudflare, Inc.','US'),('5.5.5.5','Spotify AB','SE');
    INSERT INTO ip_name VALUES ('3.3.3.3','stats.g.doubleclick.net','sni',${NOW}),('5.5.5.5','api.spotify.com','sni',${NOW});
    INSERT INTO devices VALUES ('192.168.1.37',NULL,'Living room TV',${NOW},${NOW});
    INSERT INTO events (ts, process, ip, port, proto) VALUES (${NOW - 60},'Spotify Helper','5.5.5.5',443,'TCP'),(${NOW - 50},'Spotify Helper','3.3.3.3',443,'TCP'),(${NOW - 40},'curl','3.3.3.3',443,'TCP');
    INSERT INTO dns (ts, client, qname, qtype, rcode, answers, cached) VALUES (${NOW - 30},'192.168.1.37','www.google.com',1,0,'3.3.3.3 3.3.3.4',0),(${NOW - 20},'192.168.1.37','1.0.0.1.in-addr.arpa',12,0,'1.1.1.1',0),(${NOW - 10},'192.168.1.37','mystery.example',1,0,'9.9.9.9',0);
  `);
  const loads: Load[] = [{
    app: "Google Chrome Helper", site: "nytimes.com", root: "www.nytimes.com", strong: true, start: NOW - 100, end: NOW - 98,
    hits: [{ name: "www.nytimes.com", domain: "nytimes.com", org: "NYT", country: null, tracker: false, offset: 0, ip: "8.8.8.8" },
           { name: "stats.g.doubleclick.net", domain: "doubleclick.net", org: "Google LLC", country: null, tracker: true, offset: 0.2, ip: "3.3.3.3" },
           { name: "cdnjs.cloudflare.com", domain: "cloudflare.com", org: "Cloudflare, Inc.", country: null, tracker: false, offset: 0.3, ip: "1.1.1.1" }],
  }, {
    app: "Google Chrome Helper", site: "google.com", root: "www.google.com", strong: true, start: NOW - 80, end: NOW - 79,
    hits: [{ name: "www.google.com", domain: "google.com", org: "Google LLC", country: null, tracker: false, offset: 0, ip: "3.3.3.3" }],
  }];
  return new CompaniesDb(db, null, { loads: () => loads });
}

describe("companies", () => {
  test("rolls a company up across apps, sites and devices, ranked by reach", () => {
    const list = fixture().list("1h");
    const google = list.find((c) => c.org === "Google LLC")!;
    expect(list[0]!.org).toBe("Google LLC");
    expect(google).toMatchObject({ sites: 2, third_party_sites: 1, apps: 2, devices: 1, tracker: true, reach: 5 });
    expect(google.hosts).toBe(2); // stats.g.doubleclick.net and www.google.com
    const cf = list.find((c) => c.org === "Cloudflare, Inc.")!;
    expect(cf).toMatchObject({ sites: 1, apps: 0, devices: 0, reach: 1 });
    // the reverse lookup is skipped; the unknown answer IP lands in Unknown network
    expect(list.find((c) => c.org === UNKNOWN_ORG)).toMatchObject({ devices: 1, apps: 0 });
  });

  test("detail lists the sites, apps, devices and hosts behind the number", () => {
    const d = fixture().detail("Google LLC", "1h")!;
    expect(d.site_list.map((s) => [s.site, s.third_party])).toEqual([["nytimes.com", true], ["google.com", false]]);
    expect(d.app_list.map((a) => a.app).sort()).toEqual(["Spotify Helper", "curl"]);
    expect(d.device_list[0]).toMatchObject({ device: "Living room TV", names: 1 });
    expect(d.host_list[0]).toMatchObject({ host: "stats.g.doubleclick.net", tracker: true });
    expect(d.host_list[0]!.via.sort()).toEqual(["app", "site"]);
    expect(fixture().detail("Nobody", "1h")).toBeNull();
  });
});
