#!/bin/sh
# Loopback drop-rate benchmark: runs net-analyzer on lo while iperf3 pushes
# traffic, then prints the analyzer's ring/kernel drop summary.
#
# usage: sudo scripts/bench_loopback.sh [SECONDS]
# env:   SLOTS="8 256 1024"  PORT=45201  BIN=build/net-analyzer
set -eu

SECS=${1:-5}
SLOTS=${SLOTS:-"8 256 1024"}
PORT=${PORT:-45201}
BIN=${BIN:-build/net-analyzer}

command -v iperf3 >/dev/null || { echo "iperf3 not installed" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing; run make first" >&2; exit 1; }

run() {   # run LABEL SLOTS OUTPUT_MODE IPERF_ARGS...
    label=$1 slots=$2 mode=$3
    shift 3
    log=$(mktemp)
    if [ "$mode" = quiet ]; then
        "$BIN" -i lo -q -b "$slots" 2>"$log" &
    else
        "$BIN" -i lo -b "$slots" >/dev/null 2>"$log" &
    fi
    pid=$!
    sleep 0.5
    iperf3 -s -1 -p "$PORT" >/dev/null 2>&1 &
    srv=$!
    sleep 0.3
    rate=$(iperf3 -c 127.0.0.1 -p "$PORT" -t "$SECS" -f m "$@" 2>&1 |
           awk '/sender|receiver/ {r=$7" "$8} END {print r}')
    wait "$srv" 2>/dev/null || true
    kill -INT "$pid"
    wait "$pid" || true
    printf '%-22s slots=%-5s output=%-6s iperf3=%s\n' "$label" "$slots" "$mode" "$rate"
    grep -E '^(ring|kernel)' "$log" | sed 's/^/    /'
    rm -f "$log"
}

for s in $SLOTS; do
    run "TCP max"             "$s" quiet
    run "TCP max"             "$s" print
    run "UDP 64B unlimited"   "$s" quiet -u -b 0 -l 64
    run "UDP 64B unlimited"   "$s" print -u -b 0 -l 64
done
