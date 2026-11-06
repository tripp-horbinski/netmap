// Offline geolocation with the DB-IP Lite mmdb files in ../data, used only to place the
// home marker. Connection rows are geolocated by `netlog record`, not here.
import { readdirSync } from "node:fs";
import { join } from "node:path";
import maxmind, { type CityResponse, type AsnResponse, type Reader } from "maxmind";

export interface GeoInfo {
  city?: string; region?: string; country?: string;
  lat?: number; lon?: number; asn?: number; org?: string;
}

function latest(dir: string, prefix: string): string | null {
  const found = readdirSync(dir).filter((f) => f.startsWith(`${prefix}-`) && f.endsWith(".mmdb")).sort();
  return found.length ? join(dir, found[found.length - 1]!) : null;
}

export class Geo {
  private constructor(private city: Reader<CityResponse>, private asn: Reader<AsnResponse> | null) {}

  static async open(dataDir: string): Promise<Geo | null> {
    const cityPath = latest(dataDir, "dbip-city-lite");
    if (!cityPath) return null;
    const asnPath = latest(dataDir, "dbip-asn-lite");
    return new Geo(
      await maxmind.open<CityResponse>(cityPath),
      asnPath ? await maxmind.open<AsnResponse>(asnPath) : null,
    );
  }

  lookup(ip: string): GeoInfo {
    const info: GeoInfo = {};
    const c = this.city.get(ip);
    if (c) {
      info.city = c.city?.names?.en;
      info.region = c.subdivisions?.[0]?.names?.en;
      info.country = c.country?.names?.en;
      info.lat = c.location?.latitude;
      info.lon = c.location?.longitude;
    }
    const a = this.asn?.get(ip);
    if (a) {
      info.asn = a.autonomous_system_number;
      info.org = a.autonomous_system_organization;
    }
    return info;
  }
}
