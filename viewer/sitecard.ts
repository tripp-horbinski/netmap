// A site's report card, from the exact loads the Chrome extension reported: what a visit costs
// in requests and bytes, who gets them, and how long the page's own work takes versus the
// trackers' tail. Heuristic loads have no requests and so no card.
import type { Load } from "./sites";
import { classifyHost, CLASS_ORDER, type HostClass } from "./classify";

export interface SiteCard {
  site: string;
  loads: number;                       // exact loads behind the card
  requests: number; bytes: number;     // totals across those loads
  by_class: Record<HostClass, { requests: number; bytes: number }>;
  companies: { org: string; requests: number; bytes: number; classes: HostClass[] }[];
  types: { type: string; requests: number; bytes: number }[];
  /** Median per load: when the last first-party request finished, when the last tracker/telemetry one did, the whole load. */
  fp_done: number | null; trackers_until: number | null; span: number | null;
  /** Per load, newest first, for the trend. */
  per_load: { start: number; requests: number; bytes: number; third_party_bytes: number; trackers: number; fp_done: number | null; span: number }[];
}

const median = (xs: number[]) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]!; };

export function buildSiteCard(site: string, loads: Load[]): SiteCard | null {
  const exact = loads.filter((l) => l.requests?.length);
  if (!exact.length) return null;
  const own = new Set([site]);
  const by_class = Object.fromEntries(CLASS_ORDER.map((c) => [c, { requests: 0, bytes: 0 }])) as SiteCard["by_class"];
  const companies = new Map<string, { requests: number; bytes: number; classes: Set<HostClass> }>();
  const types = new Map<string, { requests: number; bytes: number }>();
  const fpDone: number[] = [], trackersUntil: number[] = [], spans: number[] = [];
  const per_load: SiteCard["per_load"] = [];
  let requests = 0, bytes = 0;
  for (const l of exact) {
    let lb = 0, ltp = 0, ltr = 0, lfp = 0, ltu = 0;
    for (const r of l.requests!) {
      const cls = (r.cls as HostClass | undefined) ?? classifyHost(r.name, r.org, own);
      const b = r.bytes ?? 0;
      requests++; bytes += b; lb += b;
      by_class[cls].requests++; by_class[cls].bytes += b;
      const org = r.org ?? "Unknown network";
      const c = companies.get(org) ?? companies.set(org, { requests: 0, bytes: 0, classes: new Set() }).get(org)!;
      c.requests++; c.bytes += b; c.classes.add(cls);
      const t = types.get(r.type) ?? types.set(r.type, { requests: 0, bytes: 0 }).get(r.type)!;
      t.requests++; t.bytes += b;
      const end = r.end_offset ?? r.offset;
      if (cls === "first-party") lfp = Math.max(lfp, end); else ltp += b;
      if (cls === "ads" || cls === "telemetry") { ltu = Math.max(ltu, end); ltr++; }
    }
    const span = l.end - l.start;
    spans.push(span);
    if (lfp) fpDone.push(lfp);
    if (ltu) trackersUntil.push(ltu);
    per_load.push({ start: l.start, requests: l.requests!.length, bytes: lb, third_party_bytes: ltp, trackers: ltr, fp_done: lfp || null, span });
  }
  const rank = (c: HostClass) => CLASS_ORDER.indexOf(c);
  return {
    site, loads: exact.length, requests, bytes, by_class,
    companies: [...companies].map(([org, c]) => ({ org, requests: c.requests, bytes: c.bytes, classes: [...c.classes].sort((a, b) => rank(a) - rank(b)) }))
      .sort((a, b) => b.bytes - a.bytes || b.requests - a.requests),
    types: [...types].map(([type, t]) => ({ type, ...t })).sort((a, b) => b.requests - a.requests),
    fp_done: median(fpDone), trackers_until: median(trackersUntil), span: median(spans),
    per_load: per_load.sort((a, b) => b.start - a.start),
  };
}
