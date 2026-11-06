// netmap viewer in Bun: serves the Leaflet map in ../static and the same three API
// routes as `netmap.py --viewer`. `netlog record` does the recording.
//
//   bun run server.ts [--port 8765] [--home LAT,LON] [--root /path/to/netmap] [--db PATH]
//
// --root is the netmap checkout holding data/ and static/. It defaults to the repo when run
// from source and to the current directory when run as a compiled binary (`bun run build`),
// which is what the launchd agent's WorkingDirectory provides.
import { parseArgs } from "node:util";
import { join, normalize, resolve } from "node:path";
import { $ } from "bun";
import { Geo } from "./geo";
import { NetmapDb } from "./db";
import { LanDb } from "./lan";

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

async function findHome(override: string | undefined): Promise<Home | null> {
  if (override) {
    const [lat, lon] = override.split(",").map(Number);
    if (lat === undefined || lon === undefined || Number.isNaN(lat) || Number.isNaN(lon)) {
      throw new Error(`--home expects 'lat,lon', got '${override}'`);
    }
    return { lat, lon, label: "This laptop" };
  }
  const geo = await Geo.open(DATA);
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
const lan = new LanDb(db.db);
const home = await findHome(args.home);

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
      timer = setInterval(() => {
        try {
          const events = db.eventsAfter(last);
          for (const e of events) {
            controller.enqueue(enc.encode(`data: ${JSON.stringify(e)}\n\n`));
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

function windowOf(req: Request): string {
  return new URL(req.url).searchParams.get("since") ?? "24h";
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
    "/api/stream": { GET: () => stream() },
    "/api/reset": { POST: () => { db.reset(); return json({ ok: true }); } },
    "/devices": { GET: () => staticFile("/devices.html") },
    "/api/devices": { GET: withWindow((w) => lan.devices(w)) },
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
