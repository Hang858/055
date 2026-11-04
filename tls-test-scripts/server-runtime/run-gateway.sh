#!/usr/bin/env bash
# 启动打包的运行包服务端（pqc-gateway），供"服务端跑编译好的程序"场景使用。
# 用法：
#   bash tls-test-scripts/server-runtime/run-gateway.sh [config.json]
# 环境变量：
#   GATEWAY_BIN   pqc-gateway 路径（默认取 dist 下最新运行包）
#   LISTEN/UPSTREAM/CERT/KEY/CLIENT_CA/KEX  未给配置文件时用于生成临时配置
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
# 默认使用最新交付运行包（可执行程序包，无源码）
PKG_DIR=${PKG_DIR:-$(ls -d "$ROOT"/.build/delivery/pqc-gateway-hybrid-mlkem-* 2>/dev/null | tail -1)}
if [ ! -x "$PKG_DIR/bin/pqc-gateway" ]; then
    ZIP=$(ls "$ROOT"/dist/pqc-gateway-hybrid-mlkem-*.zip 2>/dev/null | tail -1)
    [ -n "$ZIP" ] && mkdir -p "$ROOT/.build/delivery" && unzip -q -o "$ZIP" -d "$ROOT/.build/delivery"
    PKG_DIR=$(ls -d "$ROOT"/.build/delivery/pqc-gateway-hybrid-mlkem-* 2>/dev/null | tail -1)
fi
GATEWAY_BIN=${GATEWAY_BIN:-$PKG_DIR/bin/pqc-gateway}
[ -x "$GATEWAY_BIN" ] || { echo "未找到 pqc-gateway，请设置 GATEWAY_BIN 或 PKG_DIR" >&2; exit 1; }
CONFIG=${1:-}
if [ -z "$CONFIG" ]; then
    CONFIG=${CONFIG_OUT:-$ROOT/.build/gwtest/gateway.json}
    mkdir -p "$(dirname "$CONFIG")"
    cat > "$CONFIG" <<JSON
{
  "listen": "${LISTEN:-127.0.0.1:9443}",
  "upstream": "${UPSTREAM:-http://127.0.0.1:9081}",
  "auth": "${AUTH:-sm2-mldsa-44}",
  "cert": "${CERT:-$PKG_DIR/certs/44/server.crt}",
  "key": "${KEY:-$PKG_DIR/certs/44/server.key}",
  "pq_key": "${PQ_KEY:-$PKG_DIR/certs/44/server.pq.key}",
  "root_ca": "${ROOT_CA:-$PKG_DIR/certs/44/root.crt}",
  "server_name": "${SERVER_NAME:-gateway.factory.local}",
  "kex": [${KEX:-'"SM2MLKEM512"'}],
  "client_ca": "${CLIENT_CA:-$PKG_DIR/certs/44/root.crt}"
}
JSON
fi
echo "使用配置：$CONFIG"
exec "$GATEWAY_BIN" serve -config "$CONFIG"
