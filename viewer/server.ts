// netmap viewer in Bun: serves the overview, map, devices and sites pages in ../static and
// the same three API routes as `netmap.py --viewer` plus the device, site and trace APIs. `netlog record` does the recording.
//
//   bun run server.ts [--port 8765] [--home LAT,LON] [--root /path/to/netmap] [--db PATH]
//
// --root is the netmap checkout holding data/ and static/. It defaults to the repo when run
// from source and to the current directory when run as a compiled binary (`bun run build`),
// which is what the launchd agent's WorkingDirectory provides.
import { parseArgs } from "node:util";
import { join, normalize, resolve } from "node:path";
import { $ } from "bun";
import { networkInterfaces } from "node:os";
import { Geo } from "./geo";
import { NetmapDb } from "./db";
import { LanDb } from "./lan";
import { SitesDb } from "./sites";
import { BrowserDb } from "./browser";
import { FindingsDb } from "./findings";
import { CompaniesDb } from "./companies";
import { AppReportDb } from "./appreport";
import { BlocksDb } from "./blocks";
import { appName as productName } from "./appname";
import { classifyHost } from "./classify";
import { buildSiteCard } from "./sitecard";
import type { Load } from "./sites";
import { Tracer, isIp } from "./trace";

const COMPILED = import.meta.dir.startsWith("/$bunfs");
const INTERVAL = 2.0; // seconds between netlog's lsof polls; the page uses it for the "live" window

const { values: args } = parseArgs({
  options: {
    port: { type: "string", default: "8765" },
    home: { type: "string" },
    root: { type: "string", default: COMPILED ? process.cwd() : resolve(import.meta.dir, "..") },
    db: { type: "string" },
  },
});

const ROOT = resolve(args.root);
const DATA = join(ROOT, "data");
const STATIC = join(ROOT, "static");
const DB_PATH = args.db ?? join(DATA, "netmap.sqlite");

interface Home { lat: number; lon: number; label: string }

async function findHome(override: string | undefined, geo: Geo | null): Promise<Home | null> {
  if (override) {
    const [lat, lon] = override.split(",").map(Number);
    if (lat === undefined || lon === undefined || Number.isNaN(lat) || Number.isNaN(lon)) {
      throw new Error(`--home expects 'lat,lon', got '${override}'`);
    }
    return { lat, lon, label: "This laptop" };
  }
  if (!geo) {
    console.error("no geolocation database in data/; run ./setup.sh to place the home marker");
    return null;
  }
  try {
    const ip = (await $`dig +short myip.opendns.com @resolver1.opendns.com`.quiet().text()).trim();
    const g = geo.lookup(ip);
    if (g.lat !== undefined && g.lon !== undefined) {
      const label = [g.city, g.region].filter(Boolean).join(", ");
      return { lat: g.lat, lon: g.lon, label: `This laptop (~${label})` };
    }
  } catch (e) {
    console.error(`could not geolocate public IP: ${e}`);
  }
  return null;
}

const db = new NetmapDb(DB_PATH);
const geo = await Geo.open(DATA);
const lan = new LanDb(db.db);
const browser = new BrowserDb(db.db, geo);
const sites = new SitesDb(db.db, browser);
const findings = new FindingsDb(db.db, sites);
const companies = new CompaniesDb(db.db, geo, sites);
const reports = new AppReportDb(db.db);
const blocks = new BlocksDb(db.db);
const home = await findHome(args.home, geo);
const tracer = new Tracer(db.db, geo);

/** This machine's LAN IPv4 (what devices must use as their DNS server). Re-read on each call: DHCP moves it. */
function lanIp(): string | null {
  for (const list of Object.values(networkInterfaces())) for (const a of list ?? []) {
    if (a.family === "IPv4" && !a.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address)) return a.address;
  }
  return null;
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function snapshot() {
  const sniffer = db.meta("sniffer");
  return {
    now: Date.now() / 1000,
    interval: INTERVAL,
    home,
    sniffer: sniffer ? `${sniffer} (netlog record)` : "off",
    connections: db.connections(),
    via: db.viaByProcess(),
  };
}

/** Server-sent events: one message per connection open, as it happens. */
function stream(): Response {
  let timer: ReturnType<typeof setInterval> | undefined;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const enc = new TextEncoder();
      let last = db.maxEventId();
      let idle = 0;
      controller.enqueue(enc.encode(": connected\n\n")); // flush headers so EventSource reports open
      timer = setInterval(() => {
        try {
          const events = db.eventsAfter(last);
          for (const e of events) {
            // The page a browser request belonged to, when the Chrome extension reported it.
            const site = browser.siteFor(e.host, e.ts);
            controller.enqueue(enc.encode(`data: ${JSON.stringify(site ? { ...e, site } : e)}\n\n`));
            last = e.id;
          }
          idle = events.length ? 0 : idle + 0.25;
          if (idle >= 15) {
            controller.enqueue(enc.encode(": keepalive\n\n"));
            idle = 0;
          }
        } catch {
          clearInterval(timer);
        }
      }, 250);
    },
    cancel() {
      clearInterval(timer);
    },
  });
  return new Response(body, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store" },
  });
}

/** Tag a load's hosts and requests with what they are to the site (first party = the site's own domain). */
function classifyLoad(l: Load | null): Load | null {
  if (!l) return l;
  const own = new Set([l.site]);
  for (const h of l.hits) h.cls = classifyHost(h.name, h.org, own);
  for (const r of l.requests ?? []) r.cls = classifyHost(r.name, r.org, own);
  return l;
}

function windowOf(req: Request): string {
  return new URL(req.url).searchParams.get("since") ?? "24h";
}

function browsersOnly(req: Request): boolean {
  return new URL(req.url).searchParams.get("apps") !== "all";
}

function withWindow(fn: (window: string) => unknown): (req: Request) => Response {
  return (req) => {
    try {
      return json(fn(windowOf(req)));
    } catch (e) {
      return json({ error: String(e instanceof Error ? e.message : e) }, 400);
    }
  };
}

// ---- app icons: rendered from the bundle's .icns with sips, cached in data/icons ------------------
const ICONS = join(DATA, "icons");
const iconQ = db.db.query<{ path: string | null; name: string | null }, [string, string, string]>(
  "SELECT path, name FROM apps WHERE process = ?1 OR name = ?2 OR name || ' ' || version = ?3 ORDER BY path LIKE '%.app/%' DESC LIMIT 1");
/** Stand-ins when a process has no bundle of its own: Terminal for tools run from a shell, the
 *  generic application icon for daemons and the unknown. */
const TERMINAL_ICNS = "/System/Applications/Utilities/Terminal.app/Contents/Resources/Terminal.icns";
const GENERIC_ICNS = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns";

async function bundleIcns(bundle: string): Promise<string | null> {
  const iconFile = (await $`plutil -extract CFBundleIconFile raw -o - ${join(bundle, "Contents/Info.plist")}`.quiet().nothrow().text()).trim();
  if (!iconFile) return null;
  const icns = join(bundle, "Contents/Resources", iconFile.endsWith(".icns") ? iconFile : `${iconFile}.icns`);
  return (await Bun.file(icns).exists()) ? icns : null;
}

/** The icon for a process, bundle name or "Name version"; `cli` picks the Terminal stand-in over the generic one. */
async function appIcon(req: Request, name: string, cli: boolean): Promise<Response> {
  const base = name.replace(/ \[(headless|automated)\]$/, "").replace(/ \((headless|automated)\)$/, "");
  let row = iconQ.get(base, base, base);
  if (!row) {
    // A product name ("Chrome") that is neither a process nor a bundle name: find a process that displays as it.
    const all = db.apps();
    const byProcess = new Map(all.map((a) => [a.process, a]));
    const match = all.find((a) => productName(a.process, byProcess) === base && a.path?.includes(".app/")) ?? all.find((a) => productName(a.process, byProcess) === base);
    if (match) row = { path: match.path, name: match.name };
  }
  // Claude Code is a bare binary; the Claude desktop app's icon stands in for it when installed.
  let bundle = row?.path?.match(/^(.*?\.app)\//)?.[1]
    ?? (row?.name === "Claude Code" || /^Claude Code/.test(base) ? "/Applications/Claude.app" : undefined);
  // An app that has not connected since the database was last cleared has no row yet; an app
  // launched others (a terminal) still deserves its icon, so look for a bundle by name.
  if (!bundle) {
    for (const dir of ["/Applications", `${process.env.HOME}/Applications`, "/System/Applications", "/System/Applications/Utilities"]) {
      const candidate = join(dir, `${base}.app`);
      if (await Bun.file(join(candidate, "Contents/Info.plist")).exists()) { bundle = candidate; break; }
    }
  }
  const icns = (bundle && (await bundleIcns(bundle))) || (cli ? TERMINAL_ICNS : GENERIC_ICNS);
  const key = new Bun.CryptoHasher("sha1").update(icns).digest("hex").slice(0, 16);
  const png = join(ICONS, `${key}.png`);
  // Revalidate every time (a 304 is cheap) so an app that gains a bundle row is not stuck on
  // the stand-in icon for a day.
  const headers = { "Content-Type": "image/png", "Cache-Control": "no-cache", ETag: `"${key}"` };
  if (req.headers.get("if-none-match") === `"${key}"`) return new Response(null, { status: 304, headers });
  if (!(await Bun.file(png).exists())) {
    await $`mkdir -p ${ICONS}`.quiet().nothrow();
    const r = await $`sips -s format png -z 128 128 ${icns} --out ${png}`.quiet().nothrow();
    if (r.exitCode !== 0 || !(await Bun.file(png).exists())) return new Response("no icon", { status: 404 });
  }
  return new Response(Bun.file(png), { headers });
}

/** The extension posts from a chrome-extension:// origin, which needs CORS headers; nothing else may. */
function cors(req: Request, res: Response): Response {
  const origin = req.headers.get("origin") ?? "";
  if (!/^(chrome|moz)-extension:\/\//.test(origin)) return res;
  res.headers.set("Access-Control-Allow-Origin", origin);
  res.headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return res;
}

async function staticFile(pathname: string): Promise<Response> {
  const rel = normalize(decodeURIComponent(pathname === "/" ? "/index.html" : pathname));
  const path = join(STATIC, rel);
  if (!path.startsWith(STATIC + "/")) return new Response("Not Found", { status: 404 });
  const file = Bun.file(path);
  return (await file.exists()) ? new Response(file) : new Response("Not Found", { status: 404 });
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: Number(args.port),
  idleTimeout: 0, // event streams stay open indefinitely
  routes: {
    "/api/data": { GET: () => json(snapshot()) },
    "/api/apps": { GET: () => json(db.apps()) },
    "/api/apps/icon/:name": { GET: (req) => appIcon(req, decodeURIComponent(req.params.name), new URL(req.url).searchParams.get("cli") === "1") },
    "/api/stream": { GET: () => stream() },
    "/api/reset": { POST: () => { db.reset(); return json({ ok: true }); } },
    "/map": { GET: () => staticFile("/map.html") },
    "/devices": { GET: () => staticFile("/devices.html") },
    "/sites": { GET: () => staticFile("/sites.html") },
    "/companies": { GET: () => staticFile("/companies.html") },
    "/apps": { GET: () => staticFile("/apps.html") },
    "/api/apps/report": { GET: withWindow((w) => reports.list(w)) },
    "/api/apps/report/:name": {
      GET: (req) => {
        try {
          const c = reports.card(decodeURIComponent(req.params.name), windowOf(req));
          return c ? json(c) : json({ error: "no connections from that app in this window" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/companies": { GET: withWindow((w) => companies.list(w)) },
    "/api/companies/:org": {
      GET: (req) => {
        try {
          const d = companies.detail(decodeURIComponent(req.params.org), windowOf(req));
          return d ? json(d) : json({ error: "no such company in this window" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/sites": { GET: (req) => withWindow((w) => sites.sites(w, browsersOnly(req)))(req) },
    "/api/trace/:ip": {
      GET: async (req) => {
        const ip = decodeURIComponent(req.params.ip);
        if (!isIp(ip)) return json({ error: "expected an IP address" }, 400);
        const fresh = new URL(req.url).searchParams.get("fresh") === "1";
        try {
          return json(await tracer.trace(ip, fresh));
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 500);
        }
      },
    },
    "/api/browser/requests": {
      OPTIONS: (req) => cors(req, new Response(null, { status: 204 })),
      POST: async (req) => {
        const origin = req.headers.get("origin");
        if (origin && !/^(chrome|moz)-extension:\/\//.test(origin)) return json({ error: "extension origins only" }, 403);
        const body = (await req.json().catch(() => null)) as { rows?: unknown } | null;
        return cors(req, json({ ok: true, stored: browser.ingest(body?.rows) }));
      },
    },
    "/api/browser/status": { GET: () => json(browser.status()) },
    "/api/findings": { GET: withWindow((w) => findings.report(w)) },
    "/api/blocks": {
      GET: () => json(blocks.list()),
      POST: async (req) => {
        const body = (await req.json().catch(() => null)) as { pattern?: unknown; device?: unknown; note?: unknown } | null;
        if (!body || typeof body.pattern !== "string") return json({ error: "expected {pattern: string, device?: string, note?: string}" }, 400);
        try {
          return json(blocks.add(body.pattern, typeof body.device === "string" ? body.device : "*", typeof body.note === "string" ? body.note : null));
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
      DELETE: async (req) => {
        const body = (await req.json().catch(() => null)) as { pattern?: unknown; device?: unknown } | null;
        if (!body || typeof body.pattern !== "string") return json({ error: "expected {pattern: string, device?: string}" }, 400);
        return json(blocks.remove(body.pattern, typeof body.device === "string" ? body.device : "*"));
      },
    },
    "/api/blocks/refused": { GET: withWindow((w) => blocks.refused(w)) },
    "/api/findings/expect": {
      POST: async (req) => {
        const body = (await req.json().catch(() => null)) as { key?: unknown; title?: unknown; expected?: unknown } | null;
        if (!body || typeof body.key !== "string" || !body.key) return json({ error: "expected {key: string, title?: string, expected?: boolean}" }, 400);
        return json(findings.expect(body.key, typeof body.title === "string" ? body.title : body.key, body.expected !== false));
      },
    },
    "/api/sites/graph": { GET: (req) => withWindow((w) => sites.graph(w, browsersOnly(req)))(req) },
    "/api/sites/:site/card": {
      GET: (req) => {
        try {
          const site = decodeURIComponent(req.params.site);
          const loads = sites.loads(windowOf(req), browsersOnly(req)).filter((l) => l.site === site).map((l) => classifyLoad(l)!);
          const card = buildSiteCard(site, loads);
          return card ? json(card) : json({ error: "no exact loads of that site in this window" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/sites/:site/load/:start": {
      GET: (req) => {
        try {
          const l = classifyLoad(sites.load(decodeURIComponent(req.params.site), Number(req.params.start), windowOf(req), browsersOnly(req)));
          return l ? json(l) : json({ error: "no such load" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/sites/known": {
      GET: () => json(sites.known()),
      POST: async (req) => {
        const body = (await req.json().catch(() => null)) as { name?: unknown; pinned?: unknown } | null;
        if (!body || typeof body.name !== "string" || body.name.trim() === "") return json({ error: "expected {name: string, pinned?: boolean}" }, 400);
        return json(sites.pin(body.name.trim(), body.pinned !== false));
      },
    },
    "/api/sites/:site": {
      GET: (req) => {
        try {
          const detail = sites.site(decodeURIComponent(req.params.site), windowOf(req), browsersOnly(req));
          if (detail) classifyLoad(detail.latest);
          return detail ? json(detail) : json({ error: "no loads of that site in this window" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/devices": { GET: withWindow((w) => ({ ...lan.devices(w), lan_ip: lanIp() })) },
    "/api/devices/:ip": {
      GET: (req) => {
        try {
          const detail = lan.device(decodeURIComponent(req.params.ip), windowOf(req));
          return detail ? json(detail) : json({ error: "no such device" }, 404);
        } catch (e) {
          return json({ error: String(e instanceof Error ? e.message : e) }, 400);
        }
      },
    },
    "/api/devices/:ip/name": {
      POST: async (req) => {
        const body = (await req.json().catch(() => null)) as { label?: unknown } | null;
        if (!body || typeof body.label !== "string") return json({ error: "expected {label: string}" }, 400);
        return lan.rename(decodeURIComponent(req.params.ip), body.label)
          ? json({ ok: true })
          : json({ error: "no such device" }, 404);
      },
    },
  },
  fetch(req) {
    return staticFile(new URL(req.url).pathname);
  },
});

console.log(`netmap viewer running at ${server.url}  (Ctrl-C to stop)`);
