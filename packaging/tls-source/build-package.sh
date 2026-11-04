#!/usr/bin/env bash
# 开发者侧：生成源码部署包 dist/pqc-tls-source-<日期>.tar.gz
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
DATE=${DATE:-$(date +%Y%m%d)}
STAGE=$ROOT/.build/pkgstage/pqc-tls-source-$DATE
OUT=$ROOT/dist/pqc-tls-source-$DATE.tar.gz
echo "组装 $STAGE"
rm -rf "$STAGE"; mkdir -p "$STAGE/src" "$STAGE/bin"
cp -a "$ROOT/tls-hybrid" "$STAGE/src/"
cp -a "$ROOT/tools" "$STAGE/src/"
cp -a "$ROOT/tls-test-scripts" "$STAGE/src/"
rm -rf "$STAGE/src/tls-test-scripts/results" "$STAGE/src/tls-test-scripts/results-client"* "$STAGE/src/tls-test-scripts/endpoints" "$STAGE/src/tools/__pycache__"
for b in server client e2e tlsbench server_hqc client_hqc e2e_hqc tlsbench_hqc; do
    [ -x "$ROOT/.build/$b" ] && cp -a "$ROOT/.build/$b" "$STAGE/bin/"
done
cp -a "$ROOT/.build/certs" "$STAGE/bin/certs"
cp -a "$ROOT/.build/liboqs" "$STAGE/bin/liboqs"
[ -f "$ROOT/.build/go-min.tgz" ] || tar -czf "$ROOT/.build/go-min.tgz" -C "$ROOT/.build/go" bin src pkg/tool pkg/include lib api VERSION go.env
cp -a "$ROOT/.build/go-min.tgz" "$STAGE/bin/go-min.tgz"
cp -a "$ROOT/.build/go-kemtls-min.tgz" "$STAGE/bin/go-kemtls-min.tgz"
cp -a "$ROOT/packaging/tls-source/kemtls" "$STAGE/src/"
cp -a "$ROOT/packaging/tls-source/deploy.sh" "$ROOT/packaging/tls-source/run-tests.sh" "$ROOT/packaging/tls-source/README.md" "$STAGE/"
cp -a "$ROOT/packaging/tls-source/patches" "$STAGE/"
cp -a "$ROOT"/packaging/tls-source/验证结果*.md "$STAGE/"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "打包 $OUT"
tar -czf "$OUT" -C "$(dirname "$STAGE")" "$(basename "$STAGE")"
sha256sum "$OUT" > "$OUT.sha256"
ls -lh "$OUT" "$OUT.sha256"
