#!/usr/bin/env bash
# KEMTLS-lab regression tests for the KEM-SIG and SIG-KEM message flows.
# Runs both flows for Dilithium2/3/5 and all six SLH-DSA-SHA2 parameter sets.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
LAB=$ROOT/kemtls-lab
BIN=${BIN:-$ROOT/.build/kemtls-lab}
PQKEY=${PQKEY:-$ROOT/.build/pqkey}
GOROOT=${GOROOT:-$ROOT/.build/extracted/go_kemtls}
GOMODCACHE=${GOMODCACHE:-$ROOT/.build/gomodcache-sm2auth}
GOCACHE=${GOCACHE:-$ROOT/.build/gocache-kemtls-fix}
export GOROOT GOMODCACHE GOCACHE
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=1

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
(cd "$ROOT/pqsig" && "$GOROOT/bin/go" build -o "$PQKEY" ./cmd/pqkey)

ALGS=(
    Dilithium2 Dilithium3 Dilithium5
    SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f
    SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f
    SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f
)
for alg in "${ALGS[@]}"; do
    "$PQKEY" -alg "$alg" -out "$TMP/server-$alg" >/dev/null
    "$PQKEY" -alg "$alg" -out "$TMP/client-$alg" >/dev/null
done

start_server() {
    local port=$1 log=$2
    shift 2
    "$BIN" -server -listen "127.0.0.1:$port" "$@" >"$log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 80); do
        if ss -ltn 2>/dev/null | grep -q ":$port "; then return 0; fi
        sleep 0.1
    done
    echo "server failed to listen on $port" >&2
    cat "$log" >&2
    return 1
}

wait_client() {
    local port=$1 log=$2
    shift 2
    timeout 60 "$BIN" -connect "127.0.0.1:$port" "$@" >"$log" 2>&1
}

run_kemsig() {
    local alg=$1 port=$2
    local sl=$TMP/kemsig-$alg-server.log cl=$TMP/kemsig-$alg-client.log
    start_server "$port" "$sl" -mode kemsig -sig-alg "$alg" \
        -sig-key "$TMP/server-$alg.priv" -peer-cert "$C/end-entity.pem"
    wait_client "$port" "$cl" -mode kemsig -cert "$C/end-entity.pem" \
        -kem-key "$C/end-entity-pq-key-KEM.bin" -sig-alg "$alg" \
        -peer-sig-pub "$TMP/server-$alg.pub"
    wait
    grep -q '^PASS: server' "$sl" && grep -q '^PASS: client' "$cl"
}

run_sigkem() {
    local alg=$1 port=$2
    local sl=$TMP/sigkem-$alg-server.log cl=$TMP/sigkem-$alg-client.log
    start_server "$port" "$sl" -mode sigkem -cert "$S/end-entity.pem" \
        -kem-key "$S/end-entity-pq-key-KEM.bin" -sig-alg "$alg" \
        -peer-sig-pub "$TMP/client-$alg.pub"
    wait_client "$port" "$cl" -mode sigkem -peer-cert "$S/end-entity.pem" \
        -sig-alg "$alg" -sig-key "$TMP/client-$alg.priv"
    wait
    grep -q '^PASS: server' "$sl" && grep -q '^PASS: client' "$cl"
}

negative_kemsig() {
    local port=$1
    local sl=$TMP/neg-kemsig-server.log cl=$TMP/neg-kemsig-client.log
    start_server "$port" "$sl" -mode kemsig -sig-alg Dilithium2 \
        -sig-key "$TMP/server-Dilithium2.priv" -peer-cert "$C/end-entity.pem"
    if wait_client "$port" "$cl" -mode kemsig -cert "$C/end-entity.pem" \
        -kem-key "$TMP/missing-kem.bin" -sig-alg Dilithium2 \
        -peer-sig-pub "$TMP/server-Dilithium2.pub"; then
        return 1
    fi
    grep -q 'decapsulate static client KEM' "$cl"
}

negative_sigkem() {
    local port=$1
    local sl=$TMP/neg-sigkem-server.log cl=$TMP/neg-sigkem-client.log
    start_server "$port" "$sl" -mode sigkem -cert "$S/end-entity.pem" \
        -kem-key "$TMP/missing-kem.bin" -sig-alg Dilithium2 \
        -peer-sig-pub "$TMP/client-Dilithium2.pub"
    if wait_client "$port" "$cl" -mode sigkem -peer-cert "$S/end-entity.pem" \
        -sig-alg Dilithium2 -sig-key "$TMP/client-Dilithium2.priv"; then
        return 1
    fi
    grep -q 'decapsulate static server KEM' "$sl"
}

port=9460
for alg in "${ALGS[@]}"; do
    check "KEM-SIG $alg" run_kemsig "$alg" "$port"
    port=$((port+1))
    check "SIG-KEM $alg" run_sigkem "$alg" "$port"
    port=$((port+1))
done

check 'KEM-SIG missing client KEM key fails' negative_kemsig 9490
check 'SIG-KEM missing server KEM key fails' negative_sigkem 9491

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
