#!/usr/bin/env python3
"""Write the committed fuzz seeds to fuzz/seeds/<target>/.

Use:
    python3 scripts/make-fuzz-seeds.py

The seeds are synthetic: names under example.com, example.net, example.org and .lan, IPv4
addresses from 192.0.2.0/24 and 198.51.100.0/24, IPv6 addresses from 2001:db8::/32. Each
seed follows the input layout in the comment at the top of its fuzz target. The script
removes the old seed files of each target that it writes, so the folder agrees with it.

Three targets get their seeds from CI instead (the write_fixture example of rusthole-import):
teleporter_zip, pihole_toml and config_parse. pem_load has no seed: a seed needs a private
key, and the repository holds no private key. cache_ops and stats_events take op codes, and
random bytes reach their code.
"""

import base64
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent / "fuzz" / "seeds"


def name_wire(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def opt_rr(size: int = 1232) -> bytes:
    # Root name, type OPT (41), class = UDP size, TTL 0, no data.
    return b"\x00" + struct.pack(">HHIH", 41, size, 0, 0)


def query(qid: int, name: str, qtype: int, edns: bool = True, rd: bool = True) -> bytes:
    flags = 0x0100 if rd else 0
    head = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    body = name_wire(name) + struct.pack(">HH", qtype, 1)
    return head + body + (opt_rr() if edns else b"")


def rr(owner: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return owner + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def reply(qid: int, name: str, qtype: int, answers: list, rcode: int = 0) -> bytes:
    flags = 0x8180 | rcode
    head = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 1)
    body = name_wire(name) + struct.pack(">HH", qtype, 1)
    return head + body + b"".join(answers) + opt_rr()


PTR_QNAME = b"\xc0\x0c"  # A pointer to the question name.
A, NS, CNAME, PTR, MX, TXT, AAAA, HTTPS = 1, 2, 5, 12, 15, 16, 28, 65


def ipv4(text: str) -> bytes:
    return bytes(int(p) for p in text.split("."))


def ipv6_doc(last: int) -> bytes:
    return bytes.fromhex("20010db8") + bytes(11) + bytes([last])


def write(target: str, files: dict) -> None:
    folder = ROOT / target
    folder.mkdir(parents=True, exist_ok=True)
    for old in folder.iterdir():
        old.unlink()
    for name, data in files.items():
        if isinstance(data, str):
            data = data.encode()
        (folder / name).write_bytes(data)


def dns_request_seeds() -> dict:
    # Input: flags, query length (u16 big endian), query, upstream reply.
    def seed(flags: int, q: bytes, r: bytes = b"") -> bytes:
        return bytes([flags]) + struct.pack(">H", len(q)) + q + r

    www = "www.example.com"
    cdn = "cdn.example.org"
    return {
        "udp-a": seed(0, query(0x1001, www, A), reply(0x2001, www, A, [rr(PTR_QNAME, A, 300, ipv4("192.0.2.1"))])),
        "udp-cname-chain": seed(
            0,
            query(0x1002, cdn, A),
            reply(
                0x2002,
                cdn,
                A,
                [
                    rr(PTR_QNAME, CNAME, 60, name_wire("edge.example.net")),
                    rr(name_wire("edge.example.net"), A, 60, ipv4("192.0.2.2")),
                ],
            ),
        ),
        "tcp-aaaa": seed(1, query(0x1003, www, AAAA), reply(0x2003, www, AAAA, [rr(PTR_QNAME, AAAA, 300, ipv6_doc(1))])),
        "udp-nxdomain": seed(0, query(0x1004, "missing.example.net", A), reply(0x2004, "missing.example.net", A, [], rcode=3)),
        "udp-no-edns": seed(0, query(0x1005, www, TXT, edns=False), reply(0x2005, www, TXT, [rr(PTR_QNAME, TXT, 30, b"\x05hello")])),
        "local-record": seed(0, query(0x1006, "nas.lan", A)),
        "local-cname": seed(0, query(0x1007, "media.lan", A)),
        "local-aaaa-nodata": seed(0, query(0x1008, "nas.lan", AAAA)),
        "forward-ptr": seed(
            0,
            query(0x1009, "7.100.51.198.in-addr.arpa", PTR),
            reply(0x2009, "7.100.51.198.in-addr.arpa", PTR, [rr(PTR_QNAME, PTR, 300, name_wire("host.corp"))]),
        ),
        "forward-domain": seed(0, query(0x100A, "files.corp", A), reply(0x200A, "files.corp", A, [rr(PTR_QNAME, A, 300, ipv4("198.51.100.20"))])),
        "off-net-client": seed(2, query(0x100B, www, A)),
        "upstream-timeout": seed(4, query(0x100C, www, A)),
        "doh-https": seed(8, query(0, www, HTTPS), reply(0x200D, www, HTTPS, [])),
        "udp-mx": seed(0, query(0x100E, "example.com", MX), reply(0x200E, "example.com", MX, [rr(PTR_QNAME, MX, 300, b"\x00\x0a" + name_wire("mail.example.com"))])),
    }


def doh_request_seeds() -> dict:
    # Input: flags, then 1-byte length fields: raw method, path, query, content type, content
    # length; then the body. Flags: bits 0-1 method (GET, POST, PUT, raw), bit 2 query, bit 3
    # content type, bit 4 content length, bit 5 the real path /dns-query.
    def field(b: bytes) -> bytes:
        return bytes([len(b)]) + b

    def seed(flags, method=b"", path=b"/dns-query", query_s=b"", ctype=b"", clen=b"", body=b""):
        return bytes([flags]) + field(method) + field(path) + field(query_s) + field(ctype) + field(clen) + body

    q = query(0, "www.example.com", A)
    dns_param = base64.urlsafe_b64encode(q).rstrip(b"=")
    ct = b"application/dns-message"
    return {
        "get": seed(0x24, query_s=b"dns=" + dns_param),
        "get-extra-params": seed(0x24, query_s=b"ct=&dns=" + dns_param + b"&x=1"),
        "post": seed(0x39, ctype=ct, clen=str(len(q)).encode(), body=q),
        "post-no-length": seed(0x29, ctype=ct, body=q),
        "post-wrong-type": seed(0x39, ctype=b"text/plain", clen=str(len(q)).encode(), body=q),
        "put": seed(0x22),
        "raw-head": seed(0x23, method=b"HEAD"),
        "other-path": seed(0x04, path=b"/resolve", query_s=b"dns=" + dns_param),
        "max-age-reply": seed(0x00, body=reply(0, "www.example.com", A, [rr(PTR_QNAME, A, 120, ipv4("192.0.2.1"))])),
    }


def dot_frames_seeds() -> dict:
    # Input: a chunk size seed, then a byte stream of frames (a 2-byte length and a message).
    def frame(m: bytes) -> bytes:
        return struct.pack(">H", len(m)) + m

    q1 = query(1, "www.example.com", A)
    q2 = query(2, "nas.lan", AAAA)
    return {
        "one-frame": b"\x01" + frame(q1),
        "two-frames-small-chunks": b"\x00" + frame(q1) + frame(q2),
        "two-frames-big-chunks": b"\x7f" + frame(q1) + frame(q2),
        "partial-frame": b"\x05" + frame(q1) + frame(q2)[:7],
    }


def api_json_seeds() -> dict:
    # Input: a selector byte (the endpoint, modulo 22), then the JSON body.
    bodies = {
        0: {"url": "https://lists.example.com/hosts.txt", "kind": "block", "enabled": True, "groups": [0], "comment": "seed"},
        1: {"enabled": False, "comment": "off", "groups": [0, 1]},
        2: {"kind": "regex", "action": "deny", "pattern": "(^|\\.)ads\\.example\\.com$", "groups": [0]},
        3: {"enabled": True, "action": "allow", "kind": "exact", "pattern": "ok.example.com"},
        4: {"kind": "regex", "pattern": "^ads\\.", "domain": "ads.example.com"},
        5: {"name": "kids", "enabled": True, "comment": "seed group"},
        6: {"name": "family", "enabled": False},
        7: {"match": "192.0.2.5", "groups": [0, 1], "comment": "tablet"},
        8: {"match": "02:00:00:00:00:01", "groups": [0]},
        9: {"name": "nas.lan", "type": "A", "address": "192.0.2.9", "enabled": True},
        10: {"address": "2001:db8::9", "type": "AAAA"},
        11: {"name": "media.lan", "target": "nas.lan"},
        12: {"target": "files.lan", "enabled": False},
        13: {"domain": "corp", "servers": ["192.0.2.1", "198.51.100.0/24"], "enabled": True},
        14: {"servers": ["192.0.2.53"], "enabled": False},
        15: {"upstreams": {"servers": ["udp://192.0.2.1:53"], "timeout_ms": 1500}},
        16: {"enabled": False, "duration_seconds": 300},
        17: {"name": "ci-token", "password": "seed-password"},
        18: {"password": "seed-password", "totp": "123456"},
        19: {"password": "seed-password", "code": "123456"},
        20: {"password": "new-seed-password"},
        21: {"code": "123456"},
    }
    return {f"sel-{sel:02}": bytes([sel]) + json.dumps(body).encode() for sel, body in bodies.items()}


def main() -> None:
    write(
        "regex_rules",
        {
            "pi-hole-style": "(\\.|^)ads\\.example\\.com$\n^tracker[0-9]*\\.\n(^|\\.)telemetry\\.example\\.net$\n"
            "^a\\.b$\n[a-z]{3,10}\\.example\\.org\n^xn--\n.*\\.lan$\n^(www\\.)?example\\.(com|net)$\n",
            "classes-and-repeats": "^ad[sx]?[0-9]{0,3}\\.\n(?i)^TRACK\n\\bads\\b\n^[^.]+\\.example\\.com$\n"
            "(a|b|c)+\\.(x|y)$\n^.{1,20}$\n[[:alpha:]]+\\.net\n\\d+\\.\\d+\n",
            "bad-patterns": "(\n[a-\n*ads\n(?P<n>x)\\k<n>\n\\\nx{99999}\n(?<=a)b\n\n",
            "unicode": "^xn--bcher-kva\\.example$\n^bücher\\.example$\n\\p{L}+\\.example\n^ä\n",
        },
    )
    write(
        "policy_check",
        {
            "rules-lists-queries": "gd\neads.example.com\nEok.ads.example.com\nr(^|\\.)tracker\\.example\\.net$\n"
            "R^safe\\.tracker\\.example\\.net$\n00.0.0.0 banner.example.com\n0# a comment\n"
            "0ads.example.org\n1kids-only.example.org\n2||abp.example.net^\n2@@||ok.abp.example.net^\n"
            "qads.example.com\nqok.ads.example.com\nqtracker.example.net\nqsafe.tracker.example.net\n"
            "qbanner.example.com\nqkids-only.example.org\nqabp.example.net\nqok.abp.example.net\n"
            "qwww.example.com\n",
            "groups-and-allow-list": "gk\neads.kids.example\ngo\neoff.example\ngdk\nRallowed\\.example\\.com$\n"
            "a\n3allowed.example.com\n3cdn.example.net\n0allowed.example.com\n0cdn.example.net\n"
            "1games.example.org\nqads.kids.example\nqoff.example\nqallowed.example.com\nqcdn.example.net\n"
            "qgames.example.org\n",
            "idn-and-wildcards": "ebücher.example\nr^xn--\n0xn--bcher-kva.example\n0*.wild.example.com\n"
            "2||sub.example.org^$important\n2/regex-in-abp/\nqBÜCHER.example\nqxn--bcher-kva.example\n"
            "qa.wild.example.com\nqsub.example.org\nqx.sub.example.org\nq.\nqa..b\n",
        },
    )
    write(
        "domain_parse",
        {
            "simple": "www.example.com",
            "trailing-dot": "ads.example.net.",
            "upper": "A.B.EXAMPLE.ORG",
            "idn": "xn--bcher-kva.example",
            "underscore": "_dmarc.example.com",
            "long-label": "a" * 63 + ".example.com",
            "long-name": ".".join(["abcdefghi"] * 25) + ".example",
            "single": "localhost",
            "reverse": "7.100.51.198.in-addr.arpa",
        },
    )
    write(
        "list_parse",
        {
            "hosts": "# hosts format\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net # inline\n"
            "::1 v6.example.org\n0.0.0.0 a.example.com b.example.com\n192.0.2.1 localhost\n",
            "domains": "# domains format\nads.example.com\n*.wild.example.net\ntelemetry.example.org\n"
            "bad_name..example\nxn--bcher-kva.example\nsingle\n",
            "abp": "[Adblock Plus 2.0]\n! comment\n||ads.example.com^\n||tracker.example.net^$third-party\n"
            "@@||ok.example.com^\n/regex/\n||sub.example.org^$important\nexample.com##.banner\n",
            "mixed-crlf": "ads.example.com\r\n0.0.0.0 b.example.com\r\n||c.example.org^\r\n",
        },
    )
    meta = {
        "version": 1,
        "url": "https://lists.example.com/hosts.txt",
        "etag": '"abc123"',
        "last_modified": "Tue, 17 Nov 2026 08:00:00 GMT",
        "body_hash": "0" * 63 + "1",
        "size_bytes": 1234,
        "entries": {"valid": 10, "invalid": 1, "skipped": 2},
        "last_success": 1794902400,
        "last_attempt": 1794902400,
        "changed_at": 1794816000,
        "last_error": None,
    }
    failed = dict(meta, body_hash=None, last_error="HTTP 503", last_success=None, etag=None)
    write(
        "list_meta",
        {
            "full": json.dumps(meta, indent=2) + "\n",
            "after-failure": json.dumps(failed, indent=2) + "\n",
        },
    )
    write(
        "arp_parse",
        {
            "proc-net-arp": "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.0.2.10       0x1         0x2         02:00:00:00:00:01     *        eth0\n"
            "192.0.2.11       0x1         0x0         00:00:00:00:00:00     *        eth0\n"
            "192.0.2.12       0x1         0x2         02:00:00:00:00:02     *        wlan0\n"
            "198.51.100.5     0x1         0x6         02:00:00:00:00:03     *        br0\n",
        },
    )
    write(
        "host_header",
        {
            "ip-port": "192.0.2.2:8443",
            "name": "rusthole.lan",
            "name-port": "rusthole.lan:8443",
            "ipv6": "[2001:db8::2]:8443",
            "wrong-port": "rusthole.lan:443",
            "upper-dot": "RUSTHOLE.LAN.",
        },
    )
    write("dns_request", dns_request_seeds())
    write("doh_request", doh_request_seeds())
    write("dot_frames", dot_frames_seeds())
    write("api_json", api_json_seeds())


if __name__ == "__main__":
    main()
