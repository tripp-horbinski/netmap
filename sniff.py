"""Passive hostname learning: read DNS answers and TLS SNI off the wire.

Runs `tcpdump -w -` (needs BPF access: the Wireshark cask's ChmodBPF grants it)
and parses the raw pcap stream itself, so it doesn't depend on tcpdump's text format.
"""
from __future__ import annotations

import ipaddress
import struct
import subprocess
import time

# DNS responses, plus outbound HTTPS segments big enough to carry data (skips bare ACKs).
FILTER = "udp src port 53 or (tcp dst port 443 and greater 100)"


def default_interface() -> str:
    out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split()[1]
    return "en0"


def read_name(m: bytes, pos: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return (name, position after it)."""
    labels, end, hops = [], None, 0
    while True:
        n = m[pos]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | m[pos + 1]
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
        elif n == 0:
            return ".".join(labels).lower(), end if end is not None else pos + 1
        else:
            labels.append(m[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n


def parse_dns(m: bytes):
    """Yield (ip, queried_name) for each A/AAAA answer in a DNS response."""
    flags, qd, an = struct.unpack("!HHH", m[2:8])
    if not flags & 0x8000:
        return
    pos, qname = 12, None
    for _ in range(qd):
        name, pos = read_name(m, pos)
        pos += 4
        qname = qname or name
    if not qname:
        return
    for _ in range(an):
        _, pos = read_name(m, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", m[pos:pos + 10])
        pos += 10
        rdata = m[pos:pos + rdlen]
        pos += rdlen
        if (rtype == 1 and rdlen == 4) or (rtype == 28 and rdlen == 16):
            yield str(ipaddress.ip_address(rdata)), qname


def parse_sni(h: bytes) -> str | None:
    """Pull server_name out of a TLS ClientHello handshake message."""
    if h[0] != 1:
        return None
    p = 4 + 2 + 32                                        # header, version, random
    p += 1 + h[p]                                         # session id
    p += 2 + struct.unpack("!H", h[p:p + 2])[0]           # cipher suites
    p += 1 + h[p]                                         # compression methods
    end = p + 2 + struct.unpack("!H", h[p:p + 2])[0]
    p += 2
    while p + 4 <= end:
        etype, elen = struct.unpack("!HH", h[p:p + 4])
        p += 4
        if etype == 0:                                    # server_name
            nlen = struct.unpack("!H", h[p + 3:p + 5])[0]
            return h[p + 5:p + 5 + nlen].decode("ascii", "replace").lower()
        p += elen
    return None


class Sniffer:
    def __init__(self, on_name):
        self.on_name = on_name      # on_name(ip, hostname, source)
        self.pending: dict = {}     # flow -> partial ClientHello bytes
        self.status = "starting"

    def run(self):
        while True:
            iface = default_interface()
            try:
                self.capture(iface)
            except Exception as e:
                self.status = f"off ({e})"
            time.sleep(5)           # interface changed or tcpdump died: retry

    def capture(self, iface: str):
        p = subprocess.Popen(
            ["tcpdump", "-i", iface, "-n", "-U", "-s", "0", "-w", "-", FILTER],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        f = p.stdout
        hdr = f.read(24)
        if len(hdr) < 24:
            err = p.stderr.read().decode(errors="replace").strip().splitlines()
            raise RuntimeError(err[-1] if err else "tcpdump exited")
        if hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif hdr[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise RuntimeError("not a pcap stream")
        linktype = struct.unpack(e + "I", hdr[20:24])[0]
        self.status = f"capturing DNS + TLS names on {iface}"
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            pkt = f.read(struct.unpack(e + "IIII", rh)[2])
            try:
                self.packet(linktype, pkt)
            except (IndexError, ValueError, struct.error):
                pass                # truncated or odd packet; skip it
        p.wait()
        self.status = "tcpdump stopped; retrying"

    def packet(self, linktype: int, pkt: bytes):
        if linktype == 1:                                 # Ethernet / Wi-Fi
            etype, off = struct.unpack("!H", pkt[12:14])[0], 14
            if etype == 0x8100:                           # VLAN tag
                etype, off = struct.unpack("!H", pkt[16:18])[0], 18
            if etype not in (0x0800, 0x86DD):
                return
        elif linktype in (0, 108):                        # utun / loopback (VPNs)
            off = 4
        elif linktype in (12, 101):                       # raw IP
            off = 0
        else:
            return
        ip = pkt[off:]
        version = ip[0] >> 4
        if version == 4:
            ihl, proto = (ip[0] & 0xF) * 4, ip[9]
            total = struct.unpack("!H", ip[2:4])[0]
            src, dst = ip[12:16], ip[16:20]
            body = ip[ihl:total] if total else ip[ihl:]
        elif version == 6:
            proto, src, dst = ip[6], ip[8:24], ip[24:40]
            body = ip[40:40 + struct.unpack("!H", ip[4:6])[0]]
        else:
            return
        if proto == 17 and struct.unpack("!H", body[0:2])[0] == 53:
            for addr, name in parse_dns(body[8:]):
                self.on_name(addr, name, "dns")
        elif proto == 6:
            self.tls(src, dst, body)

    def tls(self, src: bytes, dst: bytes, seg: bytes):
        sport, dport = struct.unpack("!HH", seg[:4])
        data = seg[(seg[12] >> 4) * 4:]
        if not data:
            return
        flow = (src, sport, dst, dport)
        buf = self.pending.pop(flow, None)
        if buf is not None:
            buf += data
        elif len(data) >= 6 and data[0] == 0x16 and data[1] == 3 and data[5] == 1:
            buf = bytearray(data)     # start of a TLS ClientHello
        else:
            return
        need = 5 + struct.unpack("!H", buf[3:5])[0]
        if len(buf) < need:           # big (post-quantum) hellos span segments
            if len(self.pending) > 1000:
                self.pending.clear()
            self.pending[flow] = buf
            return
        sni = parse_sni(bytes(buf[5:need]))
        if sni:
            self.on_name(str(ipaddress.ip_address(dst)), sni, "sni")
