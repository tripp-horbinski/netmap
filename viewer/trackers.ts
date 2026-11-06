// Ports of netlog's `base_domain` and `is_tracker` SQL helpers (netlog/src/db.rs and
// netlog/src/trackers.rs). bun:sqlite can't register functions, so the viewer applies
// these in TypeScript after grouping by name. Keep the list in step with trackers.rs.

export const TRACKER_DOMAINS: readonly string[] = [
    // Google ads & analytics
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
    "googletagmanager.com", "googletagservices.com", "app-measurement.com", "adservice.google.com",
    "firebaselogging-pa.googleapis.com", "crashlytics.com",
    // Meta, Microsoft, Amazon, TikTok, X, Snap, LinkedIn, Pinterest, Reddit
    "connect.facebook.net", "graph.facebook.com", "pixel.facebook.com", "an.facebook.com",
    "clarity.ms", "bat.bing.com", "amazon-adsystem.com", "analytics.tiktok.com", "ads-twitter.com",
    "analytics.twitter.com", "sc-static.net", "px.ads.linkedin.com", "ct.pinterest.com",
    "events.redditmedia.com",
    // Product analytics & session replay
    "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "heap.io", "heapanalytics.com",
    "fullstory.com", "hotjar.com", "hotjar.io", "mouseflow.com", "logrocket.io", "logrocket.com",
    "posthog.com", "statsig.com", "statsigapi.net", "braze.com",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com", "singular.net", "onesignal.com",
    "intercom.io", "pendo.io", "optimizely.com", "newrelic.com", "nr-data.net", "datadoghq.com",
    "browser-intake-datadoghq.com", "sentry.io", "bugsnag.com", "rollbar.com",
    // Ad tech & data brokers
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com", "rubiconproject.com",
    "pubmatic.com", "openx.net", "casalemedia.com", "scorecardresearch.com", "quantserve.com",
    "demdex.net", "omtrdc.net", "everesttech.net", "bluekai.com", "krxd.net", "exelator.com",
    "rlcdn.com", "liveramp.com", "adsrvr.org", "mathtag.com", "agkn.com", "tapad.com",
    "moatads.com", "doubleverify.com", "adsafeprotected.com", "chartbeat.com", "chartbeat.net",
    "parsely.com", "smartadserver.com", "teads.tv", "yieldmo.com", "3lift.com",
];

function clean(host: string): string {
  return host.replace(/\.+$/, "").toLowerCase();
}

export function isTracker(host: string): boolean {
  const h = clean(host);
  return TRACKER_DOMAINS.some((d) => h === d || h.endsWith(`.${d}`));
}

const TWO_PART = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
  "com.br", "com.cn", "co.in", "co.kr", "com.mx", "com.tr", "co.za", "com.sg", "com.hk",
]);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Registrable-ish domain: "a.b.example.co.uk" -> "example.co.uk". Heuristic, no PSL. */
export function baseDomain(host: string): string {
  const h = clean(host);
  if (IPV4.test(h) || h.includes(":")) return h;
  const labels = h.split(".");
  const n = labels.length;
  if (n <= 2) return h;
  const keep = TWO_PART.has(labels.slice(n - 2).join(".")) ? 3 : 2;
  return labels.slice(Math.max(0, n - keep)).join(".");
}

/** Start of a window like "1h", "24h", "7d"; 0 for "all". Mirrors netlog's since(). */
export function sinceTs(window: string, now = Date.now() / 1000): number {
  if (window === "all") return 0;
  const m = /^(\d+)([smhd])$/.exec(window);
  if (!m) throw new Error(`bad window '${window}'; use 90s, 15m, 1h, 24h, 7d or all`);
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as "s" | "m" | "h" | "d"];
  return now - Number(m[1]) * mult;
}
