import { describe, expect, test } from "bun:test";
import { isIp, isPrivate, parseLine } from "./trace";

describe("trace helpers", () => {
  test("parseLine handles answered, silent and banner lines", () => {
    expect(parseLine("traceroute to 1.2.3.4 (1.2.3.4), 24 hops max, 48 byte packets")).toBeNull();
    expect(parseLine(" 1  *")).toEqual({ n: 1, ip: null, rtt_ms: null });
    expect(parseLine(" 2  172.16.16.1  8.807 ms")).toEqual({ n: 2, ip: "172.16.16.1", rtt_ms: 8.807 });
    expect(parseLine("12  2001:4860::1  13.2 ms")).toEqual({ n: 12, ip: "2001:4860::1", rtt_ms: 13.2 });
    expect(parseLine(" 5  10.0.0.1  7.4 ms !N")).toEqual({ n: 5, ip: "10.0.0.1", rtt_ms: 7.4 });
  });

  test("isPrivate covers RFC 1918, CGNAT and link-local", () => {
    for (const ip of ["10.1.2.3", "172.16.16.1", "172.31.0.9", "192.168.1.254", "100.64.0.1", "100.127.255.1", "169.254.1.1", "fe80::1", "fd00::5"]) {
      expect(isPrivate(ip)).toBe(true);
    }
    for (const ip of ["172.32.0.1", "100.128.0.1", "8.8.8.8", "151.101.65.140", "2606:4700::1111"]) {
      expect(isPrivate(ip)).toBe(false);
    }
  });

  test("isIp rejects hostnames and shell junk", () => {
    expect(isIp("151.101.65.140")).toBe(true);
    expect(isIp("2606:4700:4700::1111")).toBe(true);
    expect(isIp("example.com")).toBe(false);
    expect(isIp("1.2.3.4; rm -rf /")).toBe(false);
    expect(isIp("999.1.1.1")).toBe(false);
  });
});
