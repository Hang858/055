#!/usr/bin/env bash
# 1.5-RTT ServerKeyGen 流程冒烟测试
# 依赖 deploy.sh 构建的 cloudflare_server_keygen / cloudflare_client_keygen。
set -euo pipefail

PROJECT_ROOT=${PROJECT_ROOT:-$(cd -- "$(dirname -- "$0")/.." && pwd)}
EXT=${EXT:-$PROJECT_ROOT/.build/extracted}
SERVER_DIR=$EXT/cloudflare_server_keygen
CLIENT_DIR=$EXT/cloudflare_client_keygen
SERVER_BIN=$SERVER_DIR/server-keygen-linux
CLIENT_BIN=$CLIENT_DIR/client-keygen-linux
PORT=${PORT:-8443}
TMP=$(mktemp -d)
PID=""

cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$SERVER_BIN" ] || { echo "SKIP: 缺少 $SERVER_BIN，请先执行 deploy.sh"; exit 77; }
[ -x "$CLIENT_BIN" ] || { echo "SKIP: 缺少 $CLIENT_BIN，请先执行 deploy.sh"; exit 77; }
command -v timeout >/dev/null || { echo "缺少 timeout"; exit 1; }

if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    echo "FAIL: 端口 $PORT 已被占用"
    exit 1
fi

(cd "$SERVER_DIR" && exec "$SERVER_BIN") > "$TMP/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    if (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    echo "FAIL: 服务端未监听 $PORT"
    tail -30 "$TMP/server.log"
    exit 1
fi

set +e
(cd "$CLIENT_DIR" && timeout 60 "$CLIENT_BIN") > "$TMP/client.log" 2>&1
RC=$?
set -e

if [ "$RC" -ne 0 ]; then
    echo "FAIL: 客户端退出码 $RC"
    tail -30 "$TMP/client.log"
    tail -30 "$TMP/server.log"
    exit 1
fi

for pattern in '总次数: 100' 'TLS handshake OK' 'ServerHello sent and flushed' '等待抗量子密文信息'; do
    if ! grep -q "$pattern" "$TMP/server.log" "$TMP/client.log"; then
        echo "FAIL: 日志缺少：$pattern"
        tail -40 "$TMP/server.log"
        tail -40 "$TMP/client.log"
        exit 1
    fi
done

if grep -qi 'HelloRetryRequest' "$TMP/server.log" "$TMP/client.log"; then
    echo "FAIL: 出现了 HelloRetryRequest"
    exit 1
fi

echo "PASS: 1.5-RTT ServerKeyGen 流程，100 次握手成功，未触发 HRR"
