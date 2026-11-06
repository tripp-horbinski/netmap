// What a host is to the app that contacted it: its own service, an update check, telemetry,
// advertising, shared infrastructure, or something else. The report card is built on this.
import { baseDomain, isTracker } from "./trackers";
import { isNeverRoot } from "./sites";

export type HostClass = "first-party" | "update" | "telemetry" | "ads" | "cdn" | "other";
export const CLASS_ORDER: HostClass[] = ["first-party", "update", "telemetry", "ads", "cdn", "other"];

/** Crash reporting, product analytics, feature flags: what an app reports about you to a vendor. */
const TELEMETRY = [
  "sentry.io", "datadoghq.com", "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "heap.io", "heapanalytics.com",
  "fullstory.com", "logrocket.io", "logrocket.com", "posthog.com", "statsig.com", "statsigapi.net", "launchdarkly.com",
  "newrelic.com", "nr-data.net", "bugsnag.com", "crashlytics.com", "app-measurement.com", "firebaselogging-pa.googleapis.com",
  "honeycomb.io", "split.io", "pendo.io", "intercom.io", "braze.com", "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
  "singular.net", "onesignal.com", "rudderstack.com", "customer.io", "hotjar.com", "hotjar.io", "clarity.ms",
];
/** Companies whose IPs mean "a CDN or cloud edge", when the host itself gives nothing away. */
const CDN_ORGS = /cloudflare|fastly|akamai|cloudfront|edgecast|limelight|cachefly|stackpath|bunny|cdn77|highwinds/i;
const UPDATE_HOST = /^(updates?|releases?|download|dl|appcast|sparkle|swupdate|swcdn|swdist|mesu|gdmf)\./;

const suffix = (host: string, list: readonly string[]) => list.some((d) => host === d || host.endsWith(`.${d}`));

/** Domains an app can claim as its own: from its bundle id (com.spotify.client -> spotify.com),
 *  its update feed, and a short list for products that spread over several domains. */
export function firstPartyDomains(name: string, bundleId: string | null, feedUrl: string | null): Set<string> {
  const out = new Set<string>();
  if (bundleId) {
    const parts = bundleId.toLowerCase().split(".");
    if (parts.length >= 2) out.add(`${parts[1]}.${parts[0]}`);
  }
  if (feedUrl) { try { out.add(baseDomain(new URL(feedUrl).hostname)); } catch {} }
  const known: Record<string, string[]> = {
    Chrome: ["google.com", "gstatic.com", "googleapis.com", "gvt1.com", "googleusercontent.com", "chromium.org"],
    Spotify: ["spotify.com", "scdn.co", "spotifycdn.com"],
    "Claude Code": ["anthropic.com", "claude.ai"], Claude: ["anthropic.com", "claude.ai"],
    Zentty: ["zentty.org"], "VS Code": ["visualstudio.com", "vscode-cdn.net", "microsoft.com"],
    Safari: ["apple.com", "icloud.com"], gh: ["github.com", "githubusercontent.com"], git: ["github.com"],
  };
  for (const d of known[name.replace(/ \((headless|automated)\)$/, "").replace(/ \d+(\.\d+)+$/, "")] ?? []) out.add(d);
  return out;
}

export function classifyHost(host: string, org: string | null, firstParty: ReadonlySet<string>): HostClass {
  const h = host.toLowerCase();
  const domain = baseDomain(h);
  if (suffix(h, TELEMETRY)) return "telemetry";
  if (isTracker(h)) return "ads";
  if (firstParty.has(domain)) return UPDATE_HOST.test(h) ? "update" : "first-party";
  if (UPDATE_HOST.test(h)) return "update";
  if (isNeverRoot(h) || (org && CDN_ORGS.test(org))) return "cdn";
  return "other";
}
