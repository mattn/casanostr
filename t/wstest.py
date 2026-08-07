#!/usr/bin/env python3
"""Minimal raw-socket websocket client + casanostr integration test.

usage: wstest.py PORT EV1 EV2 BAD META_OLD META_NEW DEL_TARGET DEL_EVENT
(all events as compact JSON strings, see t/run.sh)
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WS:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0]
        assert b"101" in status, status
        expect = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        assert expect.encode() in head, head

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed")
        self.buf += chunk

    def _take(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_text(self, text):
        payload = text.encode()
        mask = os.urandom(4)
        head = bytearray([0x81])
        n = len(payload)
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126)
            head += struct.pack(">H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack(">Q", n)
        head += mask
        head += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(head))

    def recv_text(self):
        message = b""
        while True:
            b0, b1 = self._take(2)
            op = b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                (n,) = struct.unpack(">H", self._take(2))
            elif n == 127:
                (n,) = struct.unpack(">Q", self._take(8))
            mask = self._take(4) if b1 & 0x80 else None
            payload = self._take(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if op == 0x9:  # ping -> masked pong
                self.sock.sendall(bytes([0x8A, 0x80]) + b"\x00" * 4)
                continue
            if op == 0xA:  # pong
                continue
            if op == 0x8:
                raise RuntimeError("closed by server: %r" % payload)
            message += payload
            if b0 & 0x80:  # FIN
                return message.decode()


def jsend(ws, obj):
    ws.send_text(json.dumps(obj))


def jrecv(ws):
    return json.loads(ws.recv_text())


def main():
    port = int(sys.argv[1])
    ev1, ev2, bad = (json.loads(a) for a in sys.argv[2:5])

    a = WS("127.0.0.1", port)

    # publish
    jsend(a, ["EVENT", ev1])
    r = jrecv(a)
    assert r[:3] == ["OK", ev1["id"], True], r
    print("publish: ok")

    # duplicate
    jsend(a, ["EVENT", ev1])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is True and r[3].startswith("duplicate"), r
    print("duplicate: ok")

    # tampered event must be rejected
    jsend(a, ["EVENT", bad])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False, r
    print("reject invalid: ok")

    # a second "content" is signed as one value but read as another by
    # last-wins parsers, so the whole event must be rejected
    dup = json.dumps(["EVENT", ev2]).replace('"id":', '"content":"SPOOFED","id":', 1)
    a.send_text(dup)
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False and "duplicate" in r[3], r
    print("reject duplicate member: ok")

    # REQ: stored event comes back, then EOSE
    jsend(a, ["REQ", "s1", {"authors": [ev1["pubkey"]], "kinds": [1]}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[1] == "s1" and r[2]["id"] == ev1["id"], r
    r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s1", r
    print("req/eose: ok")

    # live: publish ev2 on another connection, subscription s1 receives it
    b = WS("127.0.0.1", port)
    jsend(b, ["EVENT", ev2])
    r = jrecv(b)
    assert r[:3] == ["OK", ev2["id"], True], r
    r = jrecv(a)
    assert r[0] == "EVENT" and r[1] == "s1" and r[2]["id"] == ev2["id"], r
    print("live broadcast: ok")

    # tag filter query
    jsend(a, ["REQ", "s2", {"#t": ["casanostr"]}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[1] == "s2" and r[2]["id"] == ev2["id"], r
    r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s2", r
    print("tag filter: ok")

    meta_old, meta_new, del_target, del_ev = (
        json.loads(x) for x in sys.argv[5:9]
    )

    # replaceable: once the newer kind-0 is stored, the older one loses
    jsend(a, ["EVENT", meta_new])
    r = jrecv(a)
    assert r[2] is True, r
    jsend(a, ["EVENT", meta_old])
    r = jrecv(a)
    assert r[2] is True and r[3].startswith("duplicate"), r
    jsend(a, ["REQ", "s3", {"kinds": [0], "authors": [meta_new["pubkey"]]}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[2]["id"] == meta_new["id"], r
    r = jrecv(a)
    assert r[0] == "EOSE", r
    print("replaceable: ok")

    # NIP-09: deletion removes the target event
    jsend(a, ["CLOSE", "s1"])  # avoid live delivery interleaving below
    jsend(a, ["EVENT", del_target])
    r = jrecv(a)
    assert r[2] is True, r
    jsend(a, ["EVENT", del_ev])
    r = jrecv(a)
    assert r[2] is True, r
    jsend(a, ["REQ", "s4", {"ids": [del_target["id"]]}])
    r = jrecv(a)
    assert r[0] == "EOSE", ("event was not deleted", r)
    print("nip-09 deletion: ok")

    print("wstest: all assertions passed")


if __name__ == "__main__":
    main()
