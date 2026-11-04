#!/usr/bin/env bash
# 交付运行包（pqc-gateway）服务端冒烟：check + serve + probe，验证混合 KEX、SM2+ML-DSA 双签认证、mTLS 与 HTTP。
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
ZIP=${ZIP:-$(ls "$ROOT"/dist/pqc-gateway-hybrid-mlkem-*.zip 2>/dev/null | tail -1)}
WORK=${WORK:-$ROOT/.build/delivery}
PKG_DIR=${PKG_DIR:-$(ls -d "$WORK"/pqc-gateway-hybrid-mlkem-* 2>/dev/null | tail -1)}
if [ ! -x "$PKG_DIR/bin/pqc-gateway" ]; then
    [ -f "$ZIP" ] || { echo "未找到交付运行包：$ZIP" >&2; exit 1; }
    mkdir -p "$WORK" && unzip -q -o "$ZIP" -d "$WORK"
    PKG_DIR=$(ls -d "$WORK"/pqc-gateway-hybrid-mlkem-* | tail -1)
fi
GW="$PKG_DIR/bin/pqc-gateway"
OUT=${OUT:-$ROOT/tls-test-scripts/results/delivery-smoke-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT" "$PKG_DIR/certs/44"
cp -f "$PKG_DIR"/demo/44/server.crt "$PKG_DIR"/demo/44/server.key "$PKG_DIR"/demo/44/server.pq.key "$PKG_DIR"/demo/44/root.crt "$PKG_DIR/certs/44/" 2>/dev/null
cd "$PKG_DIR"
{
  echo "\$ $GW version"; "$GW" version
  echo "\$ $GW check -config config/gateway-44.json"; "$GW" check -config config/gateway-44.json
} > "$OUT/check.out" 2>&1
( cd "$OUT" && python3 -m http.server 9000 > backend.log 2>&1 ) & BPID=$!
"$GW" serve -config config/gateway-44.json > "$OUT/gateway.log" 2>&1 & GPID=$!
sleep 2
{
  echo "\$ $GW probe -url https://127.0.0.1:8443/ -server-name gateway.factory.local -auth sm2-mldsa-44 -kex SM2MLKEM512 ..."
  "$GW" probe -url https://127.0.0.1:8443/ -server-name gateway.factory.local \
      -ca certs/44/root.crt -auth sm2-mldsa-44 -kex SM2MLKEM512 \
      -cert demo/44/client.crt -key demo/44/client.key -pq-key demo/44/client.pq.key \
      -client-ca certs/44/root.crt 2>&1
} | tee "$OUT/probe.out"
kill $GPID $BPID 2>/dev/null || true
grep -q "negotiated_kex=SM2MLKEM512" "$OUT/probe.out" && R1=PASS || R1=FAIL
grep -q "certificate_verified=true" "$OUT/probe.out" && R2=PASS || R2=FAIL
grep -q "authenticated_signature=sm2-mldsa-44" "$OUT/probe.out" && R3=PASS || R3=FAIL
grep -q "client_cert_verified=true" "$OUT/gateway.log" && R4=PASS || R4=FAIL
{ echo "用例: 交付运行包服务端冒烟"; echo "运行包: $PKG_DIR";
  echo "$R1 混合 KEX SM2MLKEM512"; echo "$R2 服务端证书校验";
  echo "$R3 SM2+ML-DSA-44 双签认证"; echo "$R4 客户端证书校验（mTLS）";
  [ "$R1$R2$R3$R4" = PASSPASSPASSPASS ] && echo "结论: PASS" || echo "结论: FAIL";
  echo "结果目录: $OUT"; } | tee "$OUT/summary.txt"
