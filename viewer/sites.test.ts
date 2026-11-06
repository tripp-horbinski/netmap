import { describe, expect, test } from "bun:test";
import { sessionize, isPlumbing, isNeverRoot, isBrowser, type Open } from "./sites";

const T0 = 1_700_000_000;
let id = 0;
const open = (ts: number, name: string, app = "Google Chrome Helper", org: string | null = null): Open =>
  ({ id: ++id, ts: T0 + ts, app, ip: "1.2.3.4", name, org, country: null });

describe("sessionize", () => {
  test("a burst becomes one load rooted at the first real site", () => {
    const loads = sessionize([
      open(0, "stats.g.doubleclick.net"),      // tracker first: never the root
      open(0.1, "www.nytimes.com"),
      open(0.4, "static01.nyt.com"),
      open(0.9, "cdn.optimizely.com"),
      open(1.2, "mtalk.google.com"),            // plumbing: dropped
      open(1.5, "www.nytimes.com"),             // duplicate host: counted once
      open(2.0, "securepubads.g.doubleclick.net"),
    ]);
    expect(loads).toHaveLength(1);
    const l = loads[0]!;
    expect(l.site).toBe("nytimes.com");
    expect(l.hits.map((h) => h.name)).toEqual([
      "stats.g.doubleclick.net", "www.nytimes.com", "static01.nyt.com", "cdn.optimizely.com", "securepubads.g.doubleclick.net",
    ]);
    expect(l.hits.filter((h) => h.tracker)).toHaveLength(3);
    expect(l.hits[1]!.offset).toBe(0);
    expect(l.hits[2]!.offset).toBeCloseTo(0.3, 5);
  });

  test("quiet gap or the cap starts a new load; apps never mix", () => {
    const loads = sessionize([
      open(0, "a.com"), open(1, "cdn.x.net"),
      open(5, "b.com"), open(6, "cdn.y.net"),        // > GAP after cdn.x.net
      open(6.5, "c.com", "other"),                    // different app
      ...Array.from({ length: 12 }, (_, i) => open(20 + i * 2, `h${i}.d.com`)), // 2 s apart, crosses CAP
    ]);
    const sites = loads.map((l) => `${l.app}:${l.site}`).sort();
    expect(sites).toEqual(["Google Chrome Helper:a.com", "Google Chrome Helper:b.com", "Google Chrome Helper:d.com", "Google Chrome Helper:d.com", "other:c.com"]);
  });

  test("a burst with only trackers, IPs or plumbing is dropped", () => {
    expect(sessionize([open(0, "10.0.0.1"), open(0.1, "clients4.google.com"), open(0.2, "hotjar.com")])).toEqual([]);
  });

  test("unknown-app opens join the active burst, else stand alone", () => {
    const loads = sessionize([
      open(0, "www.bbc.co.uk"),
      open(0.3, "static.files.bbci.co.uk", "(unknown)"),   // lsof missed the app: joins bbc
      open(0.5, "api.anthropic.com", "Claude Helper"),
      open(0.6, "cdn.anthropic.com", "(unknown)"),         // nearest active burst is Claude Helper
      open(30, "www.example.org", "(unknown)"),            // nothing active: its own load
    ]);
    const byApp = Object.fromEntries(loads.map((l) => [`${l.app}:${l.site}`, l.hits.map((h) => h.name)]));
    // Claude Helper is not a browser, so the unknown open does not join it: it joins the live Chrome burst.
    expect(byApp["Google Chrome Helper:bbc.co.uk"]).toEqual(["www.bbc.co.uk", "static.files.bbci.co.uk", "cdn.anthropic.com"]);
    expect(byApp["Claude Helper:anthropic.com"]).toEqual(["api.anthropic.com"]);
    expect(byApp["(unknown):example.org"]).toEqual(["www.example.org"]);
  });

  test("CDNs and DoH never root a load but still count as dependencies", () => {
    const loads = sessionize([
      open(0, "fonts.gstatic.com"), open(0.1, "chrome.cloudflare-dns.com"), open(0.2, "www.wired.com"), open(0.4, "cdn.wired.com"),
    ]);
    expect(loads).toHaveLength(1);
    expect(loads[0]!.site).toBe("wired.com");
    expect(loads[0]!.hits.map((h) => h.name)).toEqual(["fonts.gstatic.com", "www.wired.com", "cdn.wired.com"]);
    expect(isNeverRoot("d1abc.cloudfront.net")).toBe(true);
    expect(isNeverRoot("www.wired.com")).toBe(false);
  });

  test("a www. host of another site inside the gap starts a new load", () => {
    const loads = sessionize([
      open(0, "www.google.com"), open(0.2, "fonts.googleapis.com"),
      open(1.8, "store.myshopify.com"),                  // Shopify hit before the www host: stays with google
      open(2.7, "www.zwift.com"), open(2.9, "cdn.shopify.com"), open(3.1, "www.zwift.com"),
    ]);
    expect(loads.map((l) => l.site).sort()).toEqual(["google.com", "zwift.com"]);
    const z = loads.find((l) => l.site === "zwift.com")!;
    expect(z.hits.map((h) => h.name)).toEqual(["www.zwift.com", "cdn.shopify.com"]);
    expect(isBrowser("Google Chrome Helper (Aperitif)")).toBe(true);
    expect(isBrowser("claude")).toBe(false);
  });

  test("apex hosts and known sites split a burst; subdomains alone do not", () => {
    const opens = [
      open(0, "www.google.com"), open(0.3, "fonts.googleapis.com"),
      open(1.0, "github.com"), open(1.2, "github.githubassets.com"),      // apex: a navigation
      open(2.0, "tripp.horbin.ski"), open(2.1, "cdn.jsdelivr.net"),       // subdomain: ambiguous
    ];
    expect(sessionize(opens).map((l) => l.site).sort()).toEqual(["github.com", "google.com"]);
    const withPin = sessionize(opens, new Set(["horbin.ski"]));
    expect(withPin.map((l) => l.site).sort()).toEqual(["github.com", "google.com", "horbin.ski"]);
    expect(withPin.find((l) => l.site === "horbin.ski")!.hits.map((h) => h.name)).toEqual(["tripp.horbin.ski", "cdn.jsdelivr.net"]);
    expect(withPin.find((l) => l.site === "github.com")!.strong).toBe(true);
    expect(withPin.find((l) => l.site === "horbin.ski")!.strong).toBe(false);
  });

  test("isPlumbing", () => {
    expect(isPlumbing("optimizationguide-pa.googleapis.com")).toBe(true);
    expect(isPlumbing("fonts.googleapis.com")).toBe(false);
    expect(isPlumbing("www.google.com")).toBe(false);
    expect(isPlumbing("anonymous-communication.ghostery.net")).toBe(true);
  });
});
