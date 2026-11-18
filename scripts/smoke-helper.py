#!/usr/bin/env python3
"""Small DNS tools for scripts/smoke-test.sh. Python standard library only.

Use:
  smoke-helper.py serve PORT         fake upstream on 127.0.0.1:PORT (UDP). Each A query gets
                                     192.0.2.1, other types get NODATA. It stops after 600 s
                                     without a query.
  smoke-helper.py query NAME FILE    write a DNS query (type A, RFC 8484 ID 0) to FILE
  smoke-helper.py answer FILE        print "rcode=N a=IP,IP" for the DNS reply in FILE
  smoke-helper.py notify PATH FILE   fake systemd notification socket at PATH (Unix
                                     datagram). Appends each message to FILE. It stops
                                     after 600 s without a message.
"""

import socket
import struct
import sys

FAKE_ANSWER = "192.0.2.1"
IDLE_LIMIT_SECONDS = 600


def build_query(name, qtype=1, qid=0):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    labels = [label for label in name.rstrip(".").split(".") if label]
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return header + qname + struct.pack(">HH", qtype, 1)


def skip_name(buf, off):
    # A name has at most 128 labels, so this loop has a bound.
    for _ in range(128):
        length = buf[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += length + 1
    raise ValueError("name too long")


def parse_reply(buf):
    _qid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    for _ in range(qdcount):
        off = skip_name(buf, off) + 4
    addrs = []
    for _ in range(ancount):
        off = skip_name(buf, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off : off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            addrs.append(socket.inet_ntoa(buf[off : off + 4]))
        off += rdlen
    return flags & 0x000F, addrs


def serve(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(IDLE_LIMIT_SECONDS)
    # A service loop on purpose: it answers until the smoke test kills it, or until no
    # query comes for IDLE_LIMIT_SECONDS.
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            return
        try:
            qid, flags = struct.unpack(">HH", data[:4])
            qend = skip_name(data, 12)
            qtype = struct.unpack(">H", data[qend : qend + 2])[0]
        except (ValueError, IndexError, struct.error):
            continue
        question = data[12 : qend + 4]
        answers = 1 if qtype == 1 else 0
        reply = struct.pack(">HHHHHH", qid, 0x8180 | (flags & 0x0100), 1, answers, 0, 0)
        reply += question
        if answers:
            reply += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(FAKE_ANSWER)
        sock.sendto(reply, peer)


def notify_listen(path, out):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(path)
    sock.settimeout(IDLE_LIMIT_SECONDS)
    # A service loop on purpose, like serve(): the smoke test kills it.
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            return
        with open(out, "ab") as f:
            f.write(data)


def main(argv):
    if len(argv) == 3 and argv[1] == "serve":
        serve(int(argv[2]))
    elif len(argv) == 4 and argv[1] == "query":
        with open(argv[3], "wb") as f:
            f.write(build_query(argv[2]))
    elif len(argv) == 4 and argv[1] == "notify":
        notify_listen(argv[2], argv[3])
    elif len(argv) == 3 and argv[1] == "answer":
        with open(argv[2], "rb") as f:
            rcode, addrs = parse_reply(f.read())
        print(f"rcode={rcode} a={','.join(addrs)}")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
