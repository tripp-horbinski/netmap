import { describe, expect, test } from "bun:test";
import { buildSiteCard } from "./sitecard";
import type { Load } from "./sites";

const T0 = 1_700_000_000;
const req = (name: string, org: string, offset: number, end: number, type: string, bytes: number | null) =>
  ({ name, org, offset, end_offset: end, type, status: 200, bytes, cached: false });
const load = (start: number, rs: ReturnType<typeof req>[]): Load => ({
  app: "Chrome", site: "nytimes.com", root: "www.nytimes.com", strong: true, exact: true, start, end: start + Math.max(...rs.map((r) => r.end_offset!)),
  hits: [], requests: rs,
});

describe("site card", () => {
  test("splits a visit by role and company, with medians across loads", () => {
    const l1 = load(T0, [
      req("www.nytimes.com", "NYT", 0, 0.4, "main_frame", 80_000), req("static01.nyt.com", "Fastly, Inc.", 0.4, 0.9, "script", 300_000),
      req("stats.g.doubleclick.net", "Google LLC", 1.0, 1.1, "xmlhttprequest", 40), req("o1.ingest.sentry.io", "Sentry", 1.2, 1.5, "xmlhttprequest", null),
    ]);
    const l2 = load(T0 + 3600, [req("www.nytimes.com", "NYT", 0, 0.6, "main_frame", 82_000), req("stats.g.doubleclick.net", "Google LLC", 0.8, 2.0, "image", 35)]);
    const heuristic: Load = { app: "Safari", site: "nytimes.com", root: "www.nytimes.com", strong: true, start: T0 + 7200, end: T0 + 7201, hits: [] };
    const c = buildSiteCard("nytimes.com", [l1, l2, heuristic])!;
    expect(c.loads).toBe(2);
    expect(c.requests).toBe(6);
    expect(c.bytes).toBe(80_000 + 300_000 + 40 + 82_000 + 35);
    expect(c.by_class["first-party"]).toEqual({ requests: 2, bytes: 162_000 });
    expect(c.by_class.cdn).toEqual({ requests: 1, bytes: 300_000 });
    expect(c.by_class.ads.requests).toBe(2);
    expect(c.by_class.telemetry.requests).toBe(1);
    expect(c.companies[0]).toMatchObject({ org: "Fastly, Inc.", bytes: 300_000, classes: ["cdn"] });
    expect(c.types[0]!.type).toBe("main_frame");
    expect(c.fp_done).toBeCloseTo(0.6, 5);        // median of 0.4 and 0.6 (upper middle)
    expect(c.trackers_until).toBeCloseTo(2.0, 5);
    expect(c.per_load[0]!.start).toBe(T0 + 3600);
    expect(c.per_load[1]).toMatchObject({ requests: 4, trackers: 2, third_party_bytes: 300_040 });
    expect(buildSiteCard("nytimes.com", [heuristic])).toBeNull();
  });
});
