#!/usr/bin/env python3
"""netmap: watch where this Mac's network connections go and draw them on a map.

Polls `lsof` (no root needed for your own processes), geolocates remote IPs with
the offline DB-IP Lite databases, and serves a live map at http://127.0.0.1:8765.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import maxminddb

from sniff import Sniffer

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
STATIC = ROOT / "static"

SCHEMA = """
CREATE TABLE IF NOT EXISTS conn (
  process TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, samples INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (process, ip, port, proto)
);
CREATE TABLE IF NOT EXISTS ip_info (
  ip TEXT PRIMARY KEY, hostname TEXT, city TEXT, region TEXT, country TEXT,
  lat REAL, lon REAL, asn INTEGER, org TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, process TEXT NOT NULL,
  ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_name (
  ip TEXT NOT NULL, name TEXT NOT NULL, source TEXT NOT NULL, last_seen REAL NOT NULL,
  PRIMARY KEY (ip, name)
);
"""

COLUMNS = ["process", "ip", "port", "proto", "first_seen", "last_seen", "samples",
           "hostname", "city", "region", "country", "lat", "lon", "asn", "org"]


# --- collecting -------------------------------------------------------------

def parse_endpoint(s: str):
    """'1.2.3.4:443' or '[2001:db8::1]:443' -> (ip, port), or None."""
    host, _, port = s.rpartition(":")
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
        return addr, int(port)
    except ValueError:
        return None


def public_ip(addr) -> str | None:
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_global and not addr.is_multicast:
        return str(addr)
    return None


def poll_lsof() -> set[tuple[str, str, int, str]]:
    """Return {(process, remote_ip, remote_port, proto)} for live outbound sockets."""
    out = subprocess.run(
        ["lsof", "-nP", "+c", "0", "-i", "-F", "pcPnT"],
        capture_output=True, text=True, timeout=20,
    ).stdout
    conns: set[tuple[str, str, int, str]] = set()
    cmd = None
    cur: dict | None = None

    def emit(rec):
        if not rec or "->" not in rec.get("n", ""):
            return
        proto = rec.get("P", "?")
        if proto == "TCP" and rec.get("st") not in ("ESTABLISHED", "SYN_SENT"):
            return
        remote = parse_endpoint(rec["n"].split("->", 1)[1])
        if remote:
            ip = public_ip(remote[0])
            if ip:
                conns.add((rec["cmd"], ip, remote[1], proto))

    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            emit(cur)
            cur = None
        elif tag == "c":
            cmd = val
        elif tag == "f":
            emit(cur)
            cur = {"cmd": cmd}
        elif cur is not None:
            if tag == "T":
                if val.startswith("ST="):
                    cur["st"] = val[3:]
            else:
                cur[tag] = val
    emit(cur)
    return conns


# --- enrichment -------------------------------------------------------------

def open_db(prefix: str):
    found = sorted(DATA.glob(f"{prefix}-*.mmdb"))
    return maxminddb.open_database(str(found[-1])) if found else None


def _en(d) -> str | None:
    return (d or {}).get("names", {}).get("en")


class Geo:
    def __init__(self):
        self.city = open_db("dbip-city-lite")
        self.asn = open_db("dbip-asn-lite")
        if not self.city:
            sys.exit("No geolocation database in data/. Run ./setup.sh first.")

    def lookup(self, ip: str) -> dict:
        info: dict = {}
        c = self.city.get(ip)
        if c:
            loc = c.get("location") or {}
            subs = c.get("subdivisions") or [{}]
            info.update(city=_en(c.get("city")), region=_en(subs[0]),
                        country=_en(c.get("country")),
                        lat=loc.get("latitude"), lon=loc.get("longitude"))
        a = self.asn.get(ip) if self.asn else None
        if a:
            info.update(asn=a.get("autonomous_system_number"),
                        org=a.get("autonomous_system_organization"))
        return info


def find_home(geo: Geo, override: str | None):
    if override:
        lat, lon = (float(x) for x in override.split(","))
        return {"lat": lat, "lon": lon, "label": "This laptop"}
    try:
        ip = subprocess.run(
            ["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        g = geo.lookup(ip)
        if g.get("lat") is not None:
            label = ", ".join(x for x in (g.get("city"), g.get("region")) if x)
            return {"lat": g["lat"], "lon": g["lon"], "label": f"This laptop (~{label})"}
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


# --- app --------------------------------------------------------------------

class NetMap:
    def __init__(self, db_path: Path, interval: float, home_override: str | None, sniff: bool = True):
        self.db = sqlite3.connect(str(db_path), check_same_thread=False, timeout=5)
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()
        self.geo = Geo()
        self.dns = ThreadPoolExecutor(max_workers=8)
        self.interval = interval
        self.known = {r[0] for r in self.db.execute("SELECT ip FROM ip_info")}
        self.home = find_home(self.geo, home_override)
        self.sniffer = Sniffer(self.learn_name) if sniff else None
        if self.sniffer:
            threading.Thread(target=self.sniffer.run, daemon=True).start()

    def learn_name(self, ip: str, name: str, source: str):
        with self.lock:
            # SNI is what the app actually connected to; don't let a DNS answer downgrade it.
            self.db.execute(
                """INSERT INTO ip_name VALUES (?,?,?,?)
                   ON CONFLICT(ip, name) DO UPDATE SET last_seen=excluded.last_seen,
                     source=CASE WHEN ip_name.source='sni' THEN 'sni' ELSE excluded.source END""",
                (ip, name, source, time.time()),
            )

    def run(self):
        while True:
            try:
                self.tick()
            except Exception as e:  # keep polling through transient lsof failures
                print(f"poll failed: {e}", file=sys.stderr)
            time.sleep(self.interval)

    def tick(self):
        now = time.time()
        conns = poll_lsof()
        new_ips = []
        with self.lock:
            for proc, ip, port, proto in conns:
                self.db.execute(
                    """INSERT INTO conn VALUES (?,?,?,?,?,?,1)
                       ON CONFLICT(process, ip, port, proto)
                       DO UPDATE SET last_seen=excluded.last_seen, samples=samples+1""",
                    (proc, ip, port, proto, now, now),
                )
                if ip not in self.known:
                    self.known.add(ip)
                    g = self.geo.lookup(ip)
                    self.db.execute(
                        """INSERT INTO ip_info (ip, city, region, country, lat, lon, asn, org)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (ip, g.get("city"), g.get("region"), g.get("country"),
                         g.get("lat"), g.get("lon"), g.get("asn"), g.get("org")),
                    )
                    new_ips.append(ip)
            self.db.commit()
        for ip in new_ips:
            self.dns.submit(self.resolve, ip)

    def resolve(self, ip: str):
        try:
            host = socket.gethostbyaddr(ip)[0]
        except OSError:
            host = ""
        with self.lock:
            self.db.execute("UPDATE ip_info SET hostname=? WHERE ip=?", (host, ip))
            self.db.commit()

    def snapshot(self) -> dict:
        with self.lock:
            rows = self.db.execute(
                """SELECT c.process, c.ip, c.port, c.proto, c.first_seen, c.last_seen, c.samples,
                          i.hostname, i.city, i.region, i.country, i.lat, i.lon, i.asn, i.org
                   FROM conn c LEFT JOIN ip_info i USING (ip)"""
            ).fetchall()
            name_rows = self.db.execute(
                """SELECT ip, name FROM ip_name WHERE ip IN (SELECT ip FROM conn)
                   ORDER BY ip, source='sni' DESC, last_seen DESC"""
            ).fetchall()
        names: dict[str, list[str]] = {}
        for ip, name in name_rows:
            if len(names.setdefault(ip, [])) < 3:
                names[ip].append(name)
        conns = [dict(zip(COLUMNS, r)) for r in rows]
        for c in conns:
            c["names"] = names.get(c["ip"], [])
        return {"now": time.time(), "interval": self.interval, "home": self.home,
                "sniffer": self.sniffer_status(),
                "connections": conns}

    def max_event_id(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]

    def events_after(self, after: int) -> list[dict]:
        """Connection opens newer than `after`, held ~1s so their TLS hostname can land."""
        with self.lock:
            rows = self.db.execute(
                """SELECT e.id, e.ts, e.process, e.ip, e.port, e.proto,
                     (SELECT n.name FROM ip_name n WHERE n.ip = e.ip
                        ORDER BY n.source = 'sni' DESC, n.last_seen DESC LIMIT 1),
                     i.org, i.city, i.country, i.lat, i.lon
                   FROM events e LEFT JOIN ip_info i USING (ip)
                   WHERE e.id > ? ORDER BY e.id LIMIT 200""", (after,)).fetchall()
        out, cutoff = [], time.time() - 1.0
        for r in rows:
            if r[1] > cutoff:
                break
            out.append(dict(zip(["id", "ts", "app", "ip", "port", "proto", "host",
                                 "org", "city", "country", "lat", "lon"], r)))
        return out

    def sniffer_status(self) -> str:
        if self.sniffer:
            return self.sniffer.status
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE key='sniffer'").fetchone()
        return f"{row[0]} (netlog record)" if row else "off"

    def reset(self):
        with self.lock:
            self.db.execute("DELETE FROM conn")
            self.db.commit()


def make_handler(app: NetMap):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(STATIC), **kw)

        def _json(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def stream(self):
            """Server-sent events: one message per connection open, as it happens."""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            last, idle = app.max_event_id(), 0.0
            try:
                while True:
                    events = app.events_after(last)
                    for e in events:
                        self.wfile.write(f"data: {json.dumps(e)}\n\n".encode())
                        last = e["id"]
                    idle = 0.0 if events else idle + 0.25
                    if idle >= 15:
                        self.wfile.write(b": keepalive\n\n")
                        idle = 0.0
                    self.wfile.flush()
                    time.sleep(0.25)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if self.path.startswith("/api/stream"):
                self.stream()
            elif self.path.startswith("/api/data"):
                self._json(app.snapshot())
            else:
                super().do_GET()

        def do_POST(self):
            if self.path == "/api/reset":
                app.reset()
                self._json({"ok": True})
            else:
                self.send_error(404)

        def log_message(self, *a):
            pass

    return Handler


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--interval", type=float, default=2.0, help="seconds between lsof polls")
    p.add_argument("--home", help="your location as 'lat,lon' (default: geolocate public IP)")
    p.add_argument("--db", type=Path, default=DATA / "netmap.sqlite")
    p.add_argument("--no-sniff", action="store_true", help="skip DNS/TLS hostname capture")
    p.add_argument("--viewer", action="store_true",
                   help="only serve the map; let `netlog record` do the recording")
    args = p.parse_args()

    app = NetMap(args.db, args.interval, args.home, sniff=not (args.no_sniff or args.viewer))
    if not args.viewer:
        threading.Thread(target=app.run, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(app))
    server.daemon_threads = True  # don't hang on Ctrl-C with open event streams
    print(f"netmap running at http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
