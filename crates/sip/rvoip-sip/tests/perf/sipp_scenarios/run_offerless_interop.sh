#!/usr/bin/env bash
# Delayed-offer (offerless) interop check: sipp drives RFC 3261 §14.2 against
# rvoip acting as the UAS.
#
# Why this exists. The offerless path regressed in the upstream merge
# (6fe45748) and was fixed in cdecbd8c. Its only coverage was
# `offerless_initial_invite_answers_the_200_offer_in_ack`, which is rvoip
# talking to rvoip -- two ends that can share the same misreading of the
# offer/answer contract. sipp is an independent implementation of it.
#
# The scenario asserts, not just observes: `check_it="true"` fails the call
# when the 200 OK carries no `Content-Type: application/sdp` or no SDP body,
# and the 2 s pause after the ACK means a teardown like the regression's
# (a BYE ~250 ms in) lands inside the scenario as an unexpected message.
#
# Verified both ways on 2026-09-02:
#   HEAD (fixed)    -> Successful call 1, Failed call 0
#   8ee6af7c (pre)  -> Successful call 0, Failed call 1, with
#                      `Reason: SIP ;cause=488 ;text="Delayed offer negotiation failed"`
#                      on a BYE rvoip sent during the pause.
#
#   ./run_offerless_interop.sh [SIP_PORT] [SIPP_PORT]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../../../.." && pwd)"
SIP_PORT="${1:-35060}"
SIPP_PORT="${2:-5061}"
SIPP_IMAGE="${SIPP_IMAGE:-local-sipp}"
OUT_DIR="${RVOIP_OFFERLESS_OUT:-$SCRIPT_DIR/results/offerless}"

if ! docker image inspect "$SIPP_IMAGE" >/dev/null 2>&1; then
  echo "[offerless] building $SIPP_IMAGE"
  docker build -t "$SIPP_IMAGE" "$SCRIPT_DIR"
fi

echo "[offerless] building the rvoip UAS"
cargo build --manifest-path "$ROOT/Cargo.toml" -p rvoip-sip --example perf_listener

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/*.log

echo "[offerless] starting the UAS on 0.0.0.0:$SIP_PORT"
"$ROOT/target/debug/examples/perf_listener" "$SIP_PORT" 127.0.0.1 \
  > "$OUT_DIR/listener.log" 2>&1 &
LISTENER_PID=$!
cleanup() { kill "$LISTENER_PID" 2>/dev/null || true; }
trap cleanup EXIT

# The listener binds before it prints, but the bind is what matters here.
for _ in $(seq 1 30); do
  ss -uln 2>/dev/null | grep -q ":$SIP_PORT " && break
  sleep 0.5
done

echo "[offerless] driving one offerless call with sipp"
set +e
docker run --rm --network host \
  -v "$SCRIPT_DIR:/scenarios:ro" \
  -v "$OUT_DIR:/out" \
  -w /out \
  "$SIPP_IMAGE" \
  -sf /scenarios/uac_offerless.xml \
  -i 127.0.0.1 -p "$SIPP_PORT" \
  -m 1 -r 1 -nostdin \
  -trace_msg -message_file /out/msg.log \
  "127.0.0.1:$SIP_PORT" > "$OUT_DIR/sipp.log" 2>&1
STATUS=$?
set -e

grep -E "Successful call|Failed call" "$OUT_DIR/sipp.log" | tail -2 || true
if [[ $STATUS -ne 0 ]]; then
  echo "[offerless] FAIL — evidence in $OUT_DIR (sipp.log, msg.log, listener.log)" >&2
  exit 1
fi
echo "[offerless] PASS — wire trace in $OUT_DIR/msg.log"
