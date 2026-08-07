#!/usr/bin/env python3
"""Minimal raw-socket websocket client + casanostr integration test.

usage: wstest.py PORT EV1 EV2 BAD META_OLD META_NEW DEL_TARGET DEL_EVENT
       EXPIRED EXPSOON FUTURE
(all events as compact JSON strings, see t/run.sh)
"""
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time

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
    """Next message, skipping the NIP-42 challenge the relay sends on connect.

    The challenge is kept on the connection so the auth test can answer it.
    """
    while True:
        m = json.loads(ws.recv_text())
        if m[0] == "AUTH":
            ws.challenge = m[1]
            continue
        return m


def jrecv_for(ws, subid):
    """Next EVENT/EOSE/CLOSED for one subscription, skipping other traffic.

    A connection can still be receiving live events for an earlier
    subscription, so the next frame is not necessarily the answer.
    """
    while True:
        m = jrecv(ws)
        if m[0] in ("EVENT", "EOSE", "CLOSED") and m[1] != subid:
            continue
        return m


def jrecv_ok(ws):
    """Next OK frame, skipping any subscription traffic still in flight."""
    while True:
        m = jrecv(ws)
        if m[0] == "OK":
            return m


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

    # a subscriber that vanishes without CLOSE leaves the broadcast holding a
    # reference to it; delivery to the remaining subscribers must still work
    gone = WS("127.0.0.1", port)
    jsend(gone, ["REQ", "sx", {}])
    jrecv(gone)  # EOSE
    gone.sock.close()

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

    # a limit of zero asks for no stored events, unlike an unset limit
    jsend(a, ["REQ", "s2a", {"limit": 0}])
    r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s2a", ("limit 0 returned events", r)
    print("limit zero: ok")

    # only single-letter keys are tag filters; a longer one is an unknown key
    # and must be ignored rather than silently matching nothing
    jsend(a, ["REQ", "s2b", {"#nonsense": ["casanostr"]}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[1] == "s2b", ("unknown key was not ignored", r)
    while r[0] == "EVENT":
        r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s2b", r
    print("multi-letter tag key ignored: ok")

    # both match everything live, so drop them before the checks below
    jsend(a, ["CLOSE", "s2a"])
    jsend(a, ["CLOSE", "s2b"])

    # one message must not be able to ask for an unbounded amount of work
    jsend(a, ["REQ", "s2c"] + [{}] * 33)
    r = jrecv(a)
    assert r[0] == "CLOSED" and r[1] == "s2c" and "too many" in r[2], r
    print("filter count cap: ok")

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

    exp_past, exp_soon, future = (json.loads(x) for x in sys.argv[9:12])

    # NIP-40: an already expired event and a far-future created_at are
    # both rejected outright
    jsend(a, ["EVENT", exp_past])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False, r
    jsend(a, ["EVENT", future])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False, r
    print("reject expired/future: ok")

    # NIP-40: served while valid, hidden once the expiration passes
    jsend(a, ["EVENT", exp_soon])
    r = jrecv(a)
    assert r[2] is True, r
    jsend(a, ["REQ", "s5", {"ids": [exp_soon["id"]]}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[2]["id"] == exp_soon["id"], r
    r = jrecv(a)
    assert r[0] == "EOSE", r
    jsend(a, ["CLOSE", "s5"])
    time.sleep(3)
    jsend(a, ["REQ", "s6", {"ids": [exp_soon["id"]]}])
    r = jrecv(a)
    assert r[0] == "EOSE", ("expired event still served", r)
    print("nip-40 expiration: ok")

    # NIP-45 COUNT: ev1 and ev2 survive (del_target was deleted)
    jsend(a, ["COUNT", "c1", {"kinds": [1], "authors": [ev1["pubkey"]]}])
    r = jrecv(a)
    assert r[0] == "COUNT" and r[1] == "c1" and r[2]["count"] == 2, r
    print("nip-45 count: ok")

    # NIP-42: the relay challenges every connection, and a kind 22242 event
    # echoing that challenge authenticates it
    sk, gen_event = sys.argv[12], sys.argv[13]
    d = WS("127.0.0.1", port)
    jsend(d, ["REQ", "wake", {"limit": 0}])
    jrecv(d)  # EOSE; jrecv stashed the challenge on the way past
    assert d.challenge, "relay sent no AUTH challenge"

    def auth_event(challenge, relay="ws://127.0.0.1:%d" % port):
        out = subprocess.run(
            [gen_event, "-s", sk, "-k", "22242", "-c", "",
             "-t", "challenge=" + challenge, "-t", "relay=" + relay],
            capture_output=True, text=True, check=True)
        return json.loads(out.stdout)

    wrong = auth_event("0" * 32)
    jsend(d, ["AUTH", wrong])
    r = jrecv(d)
    assert r[0] == "OK" and r[2] is False, ("wrong challenge was accepted", r)

    good = auth_event(d.challenge)
    jsend(d, ["AUTH", good])
    r = jrecv(d)
    assert r[0] == "OK" and r[2] is True, r

    # the challenge is single-use, so replaying the same event must fail
    jsend(d, ["AUTH", good])
    r = jrecv(d)
    assert r[0] == "OK" and r[2] is False, ("challenge was reusable", r)
    print("nip-42 auth: ok")

    # NIP-70: a protected event needs an authenticated connection owned by
    # its author. d is authenticated as that author from the test above.
    protected = json.loads(sys.argv[14])
    e = WS("127.0.0.1", port)
    jsend(e, ["EVENT", protected])
    r = jrecv(e)
    assert r[0] == "OK" and r[2] is False and r[3].startswith("auth-required"), r
    jsend(d, ["EVENT", protected])
    r = jrecv(d)
    assert r[0] == "OK" and r[2] is True, ("author could not publish it", r)
    print("nip-70 protected: ok")

    # NIP-26: an event signed by a delegate carries a delegation tag signed
    # by the delegator over nostr:delegation:<pubkey>:<conditions>
    delegator = os.urandom(32).hex()

    def delegated(conditions, kind="1"):
        out = subprocess.run(
            [gen_event, "-k", kind, "-c", "delegated",
             "-d", delegator, "-C", conditions],
            capture_output=True, text=True, check=True)
        return json.loads(out.stdout)

    ok_ev = delegated("kind=1&created_at>1000")
    jsend(a, ["EVENT", ok_ev])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is True, r

    # conditions that exclude this kind must make the whole event invalid
    bad_kind = delegated("kind=7")
    jsend(a, ["EVENT", bad_kind])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False and "delegation" in r[3], r

    # created_at bounds are checked too. (A tampered delegation signature is
    # not worth asserting here: editing the tag changes the event id, so the
    # rejection would come from the id check rather than from the delegation.)
    expired = delegated("kind=1&created_at<1000")
    jsend(a, ["EVENT", expired])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is False and "delegation" in r[3], r
    print("nip-26 delegation: ok")
    # NIP-50: search matches content as a substring, case-insensitively for
    # ASCII, and agrees between the stored query and live delivery
    jsend(a, ["REQ", "s5", {"search": "SAYS HELLO"}])
    r = jrecv(a)
    assert r[0] == "EVENT" and r[2]["id"] == ev1["id"], ("search missed", r)
    while r[0] == "EVENT":
        r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s5", r

    jsend(a, ["REQ", "s6", {"search": "no such words here"}])
    r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s6", ("search matched too much", r)

    # a search term full of LIKE wildcards must not turn into match-all
    jsend(a, ["REQ", "s7", {"search": "%"}])
    r = jrecv(a)
    assert r[0] == "EOSE" and r[1] == "s7", ("wildcard leaked into LIKE", r)
    print("nip-50 search: ok")

    # NIP-17/59: a gift wrap only reaches an authenticated recipient
    recipient_sk = os.urandom(32).hex()
    recipient = json.loads(subprocess.run(
        [gen_event, "-s", recipient_sk, "-k", "1", "-c", "who am i"],
        capture_output=True, text=True, check=True).stdout)["pubkey"]
    wrap = json.loads(subprocess.run(
        [gen_event, "-s", sk, "-k", "1059", "-c", "sealed",
         "-t", "p=" + recipient],
        capture_output=True, text=True, check=True).stdout)
    jsend(a, ["EVENT", wrap])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is True, r

    # an unauthenticated connection must not see it
    g = WS("127.0.0.1", port)
    jsend(g, ["REQ", "gw", {"kinds": [1059]}])
    r = jrecv_for(g, "gw")
    assert r[0] == "EOSE", ("gift wrap served without auth", r)

    # nor must someone authenticated as the wrong pubkey (d is the author).
    # d still holds the match-everything subscription from the auth test.
    jsend(d, ["CLOSE", "wake"])
    jsend(d, ["REQ", "gw2", {"kinds": [1059]}])
    r = jrecv_for(d, "gw2")
    assert r[0] == "EOSE", ("gift wrap served to a non-recipient", r)

    # the recipient authenticates and does see it
    h = WS("127.0.0.1", port)
    jsend(h, ["REQ", "wake", {"limit": 0}])
    jrecv(h)
    ra = subprocess.run(
        [gen_event, "-s", recipient_sk, "-k", "22242", "-c", "",
         "-t", "challenge=" + h.challenge,
         "-t", "relay=ws://127.0.0.1:%d" % port],
        capture_output=True, text=True, check=True).stdout
    jsend(h, ["AUTH", json.loads(ra)])
    r = jrecv(h)
    assert r[0] == "OK" and r[2] is True, r
    jsend(h, ["REQ", "gw3", {"kinds": [1059]}])
    r = jrecv_for(h, "gw3")
    assert r[0] == "EVENT" and r[2]["id"] == wrap["id"], \
        ("recipient could not read the gift wrap", r)
    print("nip-17/59 gift wrap: ok")

    # NIP-62: a vanish request aimed at this relay drops the author's events
    v_sk = os.urandom(32).hex()
    for i in range(2):
        e = json.loads(subprocess.run(
            [gen_event, "-s", v_sk, "-k", "1", "-c", "to vanish %d" % i],
            capture_output=True, text=True, check=True).stdout)
        jsend(a, ["EVENT", e])
        r = jrecv(a)
        assert r[0] == "OK" and r[2] is True, r
    author = e["pubkey"]

    # aimed at some other relay: nothing happens here
    elsewhere = json.loads(subprocess.run(
        [gen_event, "-s", v_sk, "-k", "62", "-c", "",
         "-t", "relay=wss://somewhere.example"],
        capture_output=True, text=True, check=True).stdout)
    jsend(a, ["EVENT", elsewhere])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is True, r
    jsend(a, ["REQ", "v1", {"authors": [author], "kinds": [1]}])
    seen = 0
    r = jrecv_for(a, "v1")
    while r[0] == "EVENT":
        seen += 1
        r = jrecv_for(a, "v1")
    assert seen == 2, ("a request for another relay vanished events", seen)

    # aimed at us: the kind-1 events go, the request itself stays
    ours = json.loads(subprocess.run(
        [gen_event, "-s", v_sk, "-k", "62", "-c", "",
         "-t", "relay=ws://127.0.0.1:%d/" % port],
        capture_output=True, text=True, check=True).stdout)
    jsend(a, ["EVENT", ours])
    r = jrecv(a)
    assert r[0] == "OK" and r[2] is True, r
    jsend(a, ["REQ", "v2", {"authors": [author], "kinds": [1]}])
    r = jrecv_for(a, "v2")
    assert r[0] == "EOSE", ("events survived the vanish request", r)
    jsend(a, ["REQ", "v3", {"authors": [author], "kinds": [62]}])
    r = jrecv_for(a, "v3")
    assert r[0] == "EVENT", ("the vanish request deleted itself", r)
    while r[0] == "EVENT":
        r = jrecv_for(a, "v3")
    for sub in ("v1", "v2", "v3"):
        jsend(a, ["CLOSE", sub])
    print("nip-62 vanish: ok")

    # NIP-66: a monitor's events are ordinary addressable / replaceable ones,
    # which is the whole of the relay-side obligation
    m_sk = os.urandom(32).hex()

    def monitor(kind, extra):
        return json.loads(subprocess.run(
            [gen_event, "-s", m_sk, "-k", str(kind), "-c", ""] + extra,
            capture_output=True, text=True, check=True).stdout)

    old = monitor(30166, ["-t", "d=wss://relay.example", "-T", "3000"])
    new = monitor(30166, ["-t", "d=wss://relay.example", "-T", "4000"])
    other = monitor(30166, ["-t", "d=wss://other.example", "-T", "4000"])
    for e in (old, new, other):
        jsend(a, ["EVENT", e])
        r = jrecv_ok(a)
        assert r[2] is True, r
    jsend(a, ["REQ", "m1", {"kinds": [30166], "authors": [new["pubkey"]]}])
    got = []
    r = jrecv_for(a, "m1")
    while r[0] == "EVENT":
        got.append(r[2]["id"])
        r = jrecv_for(a, "m1")
    assert new["id"] in got and other["id"] in got, ("30166 lost", got)
    assert old["id"] not in got, ("30166 was not replaced by d tag", got)

    ann1 = monitor(10166, ["-T", "3000"])
    ann2 = monitor(10166, ["-T", "4000"])
    for e in (ann1, ann2):
        jsend(a, ["EVENT", e])
        r = jrecv_ok(a)
        assert r[2] is True, r
    jsend(a, ["REQ", "m2", {"kinds": [10166], "authors": [ann2["pubkey"]]}])
    got = []
    r = jrecv_for(a, "m2")
    while r[0] == "EVENT":
        got.append(r[2]["id"])
        r = jrecv_for(a, "m2")
    assert got == [ann2["id"]], ("10166 did not replace", got)
    print("nip-66 monitor events: ok")

    print("wstest: all assertions passed")


if __name__ == "__main__":
    main()
