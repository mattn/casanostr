#!/bin/sh
set -e
cd "$(dirname "$0")/.."

PORT=${PORT:-7899}
DB=${DB:-$(mktemp -u /tmp/casanostr-test-XXXXXX.db)}
CASANOSTR=${CASANOSTR:-./casanostr}
GEN_EVENT=${GEN_EVENT:-./t/gen_event}

"$CASANOSTR" -p "$PORT" -d "$DB" &
PID=$!
cleanup() {
  kill "$PID" 2>/dev/null || true
  rm -f "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT
sleep 1

SK=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
EV1=$("$GEN_EVENT" -s "$SK" -k 1 -c "casanostr says hello")
EV2=$("$GEN_EVENT" -s "$SK" -k 1 -c "with a tag" -t t=casanostr)
BAD=$(printf '%s' "$EV1" | sed 's/casanostr says hello/tampered/')
META_OLD=$("$GEN_EVENT" -s "$SK" -k 0 -T 1000 -c '{"name":"old"}')
META_NEW=$("$GEN_EVENT" -s "$SK" -k 0 -T 2000 -c '{"name":"new"}')
EV3=$("$GEN_EVENT" -s "$SK" -k 1 -c "to be deleted")
ID3=$(printf '%s' "$EV3" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
EVD=$("$GEN_EVENT" -s "$SK" -k 5 -c "" -t "e=$ID3")
NOW=$(date +%s)
EV_EXPIRED=$("$GEN_EVENT" -s "$SK" -k 42 -c "already expired" -t "expiration=$((NOW - 100))")
EV_EXPSOON=$("$GEN_EVENT" -s "$SK" -k 42 -c "expiring soon" -t "expiration=$((NOW + 2))")
EV_FUTURE=$("$GEN_EVENT" -s "$SK" -k 1 -c "from the future" -T $((NOW + 9999)))
# NIP-70: a bare ["-"] tag marks the event as publishable only by its author
EV_PROTECTED=$("$GEN_EVENT" -s "$SK" -k 1 -c "protected" -t "-")

python3 t/wstest.py "$PORT" "$EV1" "$EV2" "$BAD" \
  "$META_OLD" "$META_NEW" "$EV3" "$EVD" \
  "$EV_EXPIRED" "$EV_EXPSOON" "$EV_FUTURE" \
  "$SK" "$GEN_EVENT" "$EV_PROTECTED"

curl -sf -H 'Accept: application/nostr+json' "http://127.0.0.1:$PORT/" |
  grep -q '"name":"casanostr"'
echo "nip-11: ok"

# NIP-13 needs a relay that demands proof of work, so run a second one
POW_PORT=$((PORT + 1))
POW_DB=$(mktemp -u /tmp/casanostr-pow-XXXXXX.db)
"$CASANOSTR" -p "$POW_PORT" -d "$POW_DB" -P 8 &
POW_PID=$!
pow_cleanup() {
  kill "$POW_PID" 2>/dev/null || true
  rm -f "$POW_DB" "$POW_DB-wal" "$POW_DB-shm"
  cleanup
}
trap pow_cleanup EXIT
sleep 1
curl -sf -H 'Accept: application/nostr+json' "http://127.0.0.1:$POW_PORT/" |
  grep -q '"min_pow_difficulty":8'
python3 t/powtest.py "$POW_PORT" "$SK" "$GEN_EVENT"

echo "all tests passed"
