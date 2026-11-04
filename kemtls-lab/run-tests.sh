#!/usr/bin/env bash
# KEMTLS-lab regression tests for the KEM-SIG and SIG-KEM message flows.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
LAB=$ROOT/kemtls-lab
BIN=${BIN:-$ROOT/.build/kemtls-lab}
GOROOT=${GOROOT:-$ROOT/.build/extracted/go_kemtls}
GOMODCACHE=${GOMODCACHE:-$ROOT/.build/gomodcache-sm2auth}
GOCACHE=${GOCACHE:-$ROOT/.build/gocache-kemtls-fix}
export GOROOT GOMODCACHE GOCACHE
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=mod

CERTS=$ROOT/packaging/tls-source/kemtls
S=$CERTS/cloudflare_server/pqcerts
C=$CERTS/cloudflare_client/pqcerts
TMP=$(mktemp -d)
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

pass=0
fail=0
check() {
    local name=$1
    shift
    if "$@"; then
        echo "PASS: $name"
        pass=$((pass+1))
    else
        echo "FAIL: $name"
        fail=$((fail+1))
    fi
}

(cd "$LAB" && "$GOROOT/bin/go" build -o "$BIN" .)

start_server() {
    local port=$1 mode=$2 cert=$3 peer=$4 keyflag=$5 key=$6 log=$7
    "$BIN" -server -mode "$mode" -listen "127.0.0.1:$port" \
        -cert "$cert" -peer-cert "$peer" "$keyflag" "$key" >"$log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 50); do
        if ss -ltn 2>/dev/null | grep -q ":$port "; then return 0; fi
        sleep 0.1
    done
    echo "server failed to listen on $port" >&2
    cat "$log" >&2
    return 1
}

wait_client() {
    local port=$1 mode=$2 cert=$3 peer=$4 keyflag=$5 key=$6 log=$7
    timeout 20 "$BIN" -mode "$mode" -connect "127.0.0.1:$port" \
        -cert "$cert" -peer-cert "$peer" "$keyflag" "$key" >"$log" 2>&1
}

positive() {
    local mode=$1 port=$2 server_keyflag=$3 server_key=$4 client_keyflag=$5 client_key=$6
    start_server "$port" "$mode" "$S/end-entity.pem" "$C/end-entity.pem" "$server_keyflag" "$server_key" "$TMP/$mode-server.log"
    wait_client "$port" "$mode" "$C/end-entity.pem" "$S/end-entity.pem" "$client_keyflag" "$client_key" "$TMP/$mode-client.log"
    wait
    grep -q '^PASS: server' "$TMP/$mode-server.log"
    grep -q '^PASS: client' "$TMP/$mode-client.log"
}

negative_kemsig() {
    local port=$1
    start_server "$port" kemsig "$S/end-entity.pem" "$C/end-entity.pem" -sig-key "$S/end-entity-pq-key.bin" "$TMP/neg-kemsig-server.log"
    if wait_client "$port" kemsig "$C/end-entity.pem" "$S/end-entity.pem" -kem-key "$TMP/missing-kem.bin" "$TMP/neg-kemsig-client.log"; then
        return 1
    fi
    grep -q 'decapsulate static client KEM' "$TMP/neg-kemsig-client.log"
}

negative_sigkem() {
    local port=$1
    start_server "$port" sigkem "$S/end-entity.pem" "$C/end-entity.pem" -kem-key "$TMP/missing-kem.bin" "$TMP/neg-sigkem-server.log"
    if wait_client "$port" sigkem "$C/end-entity.pem" "$S/end-entity.pem" -sig-key "$C/end-entity-pq-key.bin" "$TMP/neg-sigkem-client.log"; then
        return 1
    fi
    grep -q 'decapsulate static server KEM' "$TMP/neg-sigkem-server.log"
}

check 'KEM-SIG positive' positive kemsig 9451 -sig-key "$S/end-entity-pq-key.bin" -kem-key "$C/end-entity-pq-key-KEM.bin"
check 'SIG-KEM positive' positive sigkem 9452 -kem-key "$S/end-entity-pq-key-KEM.bin" -sig-key "$C/end-entity-pq-key.bin"
check 'KEM-SIG missing client KEM key fails' negative_kemsig 9453
check 'SIG-KEM missing server KEM key fails' negative_sigkem 9454

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
