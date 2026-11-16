#!/usr/bin/env bash
# Exercise the patched TLS handshake with each PQ signature algorithm.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
BASE=$ROOT/.build/slh-tls
SERVER=$BASE/server/server-slh
CLIENT=$BASE/client/client-slh
PQKEY=$ROOT/.build/pqkey
PQCert=$ROOT/.build/pqcertlab
OUT=$ROOT/.build/tls-matrix
ALGS=(
    Dilithium2 Dilithium3 Dilithium5
    SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f
    SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f
    SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f
)
[ -x "$SERVER" ] && [ -x "$CLIENT" ] || { echo "build .build/slh-tls first" >&2; exit 2; }
[ -x "$PQKEY" ] && [ -x "$PQCert" ] || { echo "build pqkey/pqcertlab first" >&2; exit 2; }
rm -rf "$OUT"; mkdir -p "$OUT"

pass=0; fail=0
for alg in "${ALGS[@]}"; do
    dir=$OUT/$alg
    mkdir -p "$dir/server/pqcerts" "$dir/client/pqcerts"
    "$PQKEY" -alg "$alg" -out "$dir/sig" >/dev/null
    "$PQCert" -alg "$alg" -pub "$dir/sig.pub" -out "$dir/certs" >/dev/null
    for side in server client; do
        cp "$dir/certs/root.crt" "$dir/$side/pqcerts/root-ca.pem"
        cp "$dir/certs/$side.crt" "$dir/$side/pqcerts/end-entity.pem"
        cp "$dir/certs/$side.key" "$dir/$side/pqcerts/end-entity-key.pem"
    done
    # Start from a clean port; the server binary reads pqcerts from its cwd.
    pkill -f "$SERVER" 2>/dev/null || true
    for _ in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ':8443 ' || break
        sleep 0.1
    done
    (cd "$dir/server" && KEMTLS_SIG_ALG="$alg" KEMTLS_SIG_KEY="$dir/sig.priv" \
        "$SERVER" > "$dir/server.log" 2>&1 & echo $! > "$dir/server.pid")
    for _ in $(seq 1 100); do
        ss -ltn 2>/dev/null | grep -q ':8443 ' && break
        sleep 0.1
    done
    if (cd "$dir/client" && KEMTLS_CONNECTIONS=1 timeout 40 "$CLIENT" > "$dir/client.log" 2>&1); then
        if grep -q 'TLS handshake OK' "$dir/client.log" && grep -q 'PQ server CertificateVerify' "$dir/server.log"; then
            echo "PASS: TLS handshake $alg"
            pass=$((pass+1))
        else
            echo "FAIL: TLS handshake $alg (missing marker)"
            fail=$((fail+1))
        fi
    else
        echo "FAIL: TLS handshake $alg (client exit)"
        fail=$((fail+1))
    fi
    kill "$(cat "$dir/server.pid")" 2>/dev/null || true
    for _ in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ':8443 ' || break
        sleep 0.1
    done
done

# Negative: server cannot sign without its SLH-DSA private key.
neg=$OUT/negative
mkdir -p "$neg/server" "$neg/client"
cp -a "$OUT/SLH-DSA-SHA2-128s/server/pqcerts" "$neg/server/"
cp -a "$OUT/SLH-DSA-SHA2-128s/client/pqcerts" "$neg/client/"
pkill -f "$SERVER" 2>/dev/null || true
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ':8443 ' || break; sleep 0.1; done
(cd "$neg/server" && KEMTLS_SIG_ALG=SLH-DSA-SHA2-128s KEMTLS_SIG_KEY="$neg/missing.priv"     "$SERVER" > "$neg/server.log" 2>&1 & echo $! > "$neg/server.pid")
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ':8443 ' && break; sleep 0.1; done
if (cd "$neg/client" && KEMTLS_CONNECTIONS=1 timeout 30 "$CLIENT" > "$neg/client.log" 2>&1); then
    echo "FAIL: missing SLH-DSA key was accepted"
    fail=$((fail+1))
elif grep -q 'SLH-DSA sign failed' "$neg/server.log"; then
    echo "PASS: missing SLH-DSA key fails"
    pass=$((pass+1))
else
    echo "FAIL: missing SLH-DSA key failed for the wrong reason"
    fail=$((fail+1))
fi
kill "$(cat "$neg/server.pid")" 2>/dev/null || true

echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
