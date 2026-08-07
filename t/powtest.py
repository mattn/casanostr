#!/usr/bin/env python3
"""NIP-13: a relay started with -P refuses events below that difficulty.

usage: powtest.py PORT SECKEY GEN_EVENT
"""
import json
import subprocess
import sys

sys.path.insert(0, "t")
from wstest import WS, jrecv, jsend  # noqa: E402


def gen(gen_event, sk, content):
    out = subprocess.run([gen_event, "-s", sk, "-k", "1", "-c", content],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def main():
    port, sk, gen_event = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    w = WS("127.0.0.1", port)

    jsend(w, ["EVENT", gen(gen_event, sk, "no work done")])
    r = jrecv(w)
    assert r[0] == "OK" and r[2] is False and r[3].startswith("pow:"), r

    # mine until the id starts with two zero nibbles, i.e. 8 leading zero bits
    for i in range(200000):
        ev = gen(gen_event, sk, "mined %d" % i)
        if ev["id"].startswith("00"):
            break
    else:
        raise SystemExit("could not mine an event")
    jsend(w, ["EVENT", ev])
    r = jrecv(w)
    assert r[0] == "OK" and r[2] is True, ("mined event was refused", r)
    print("nip-13 pow: ok")


if __name__ == "__main__":
    main()
