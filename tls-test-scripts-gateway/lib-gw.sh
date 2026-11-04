#!/usr/bin/env bash
# 交付运行包（pqc-gateway，仅可执行程序）版测试公共函数。
# 服务端：bin/pqc-gateway 或 bin/pqc-gateway-hqc  serve -config
# 客户端：bin/pqc-gateway 或 bin/pqc-gateway-hqc  probe
GW_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export RESULTS_ROOT=${RESULTS_ROOT:-$GW_SCRIPT_DIR/results}
source "$GW_SCRIPT_DIR/../tls-test-scripts/lib.sh"

GW_PKG_DIR=${GW_PKG_DIR:-$(ls -d "$PROJECT_ROOT"/.build/delivery/pqc-gateway-hybrid-mlkem-* 2>/dev/null | tail -1)}
if [ ! -x "$GW_PKG_DIR/bin/pqc-gateway" ]; then
    ZIP=$(ls "$PROJECT_ROOT"/dist/pqc-gateway-hybrid-mlkem-*.zip 2>/dev/null | tail -1)
    mkdir -p "$PROJECT_ROOT/.build/delivery"
    [ -n "$ZIP" ] && unzip -q -o "$ZIP" -d "$PROJECT_ROOT/.build/delivery"
    GW_PKG_DIR=$(ls -d "$PROJECT_ROOT"/.build/delivery/pqc-gateway-hybrid-mlkem-* 2>/dev/null | tail -1)
fi
GW_BIN=${GW_BIN:-$GW_PKG_DIR/bin/pqc-gateway}
GW_HQC_BIN=${GW_HQC_BIN:-$GW_PKG_DIR/bin/pqc-gateway-hqc}
GW_PORT=${GW_PORT:-8443}
GW_UPSTREAM_PORT=${GW_UPSTREAM_PORT:-9000}
GW_SERVER_NAME=${GW_SERVER_NAME:-gateway.factory.local}
GW_BACKEND_PID=""

gw_prepare() {
    [ -x "$GW_BIN" ] || { echo "未找到交付包：$GW_PKG_DIR" >&2; exit 1; }
    mkdir -p "$GW_PKG_DIR/certs/44" "$GW_PKG_DIR/certs/87"
    cp -f "$GW_PKG_DIR"/demo/44/server.crt "$GW_PKG_DIR"/demo/44/server.key \
          "$GW_PKG_DIR"/demo/44/server.pq.key "$GW_PKG_DIR"/demo/44/root.crt "$GW_PKG_DIR/certs/44/" 2>/dev/null
    cp -f "$GW_PKG_DIR"/demo/87/server.crt "$GW_PKG_DIR"/demo/87/server.key \
          "$GW_PKG_DIR"/demo/87/server.pq.key "$GW_PKG_DIR"/demo/87/root.crt "$GW_PKG_DIR/certs/87/" 2>/dev/null
    ( cd "$CASE_DIR" && python3 -m http.server "$GW_UPSTREAM_PORT" > backend.log 2>&1 ) &
    GW_BACKEND_PID=$!
    sleep 0.5
}

gw_init() {
    ensure_capture_env
    init_case "$1" "$2"
    gw_prepare
    trap 'gw_stop; cleanup' EXIT
}

# gw_serve <名称> <kex JSON> [auth] [44|87] [gateway|hqc]
gw_serve() {
    local name=$1 kex=$2 auth=${3:-sm2-mldsa-44} lvl=${4:-44} kind=${5:-gateway}
    local bin=$GW_BIN
    [ "$kind" = hqc ] && bin=$GW_HQC_BIN
    local cfg="$CASE_DIR/gateway-$name.json"
    cat > "$cfg" <<JSON
{
  "listen": "127.0.0.1:$GW_PORT",
  "upstream": "http://127.0.0.1:$GW_UPSTREAM_PORT",
  "auth": "$auth",
  "cert": "$GW_PKG_DIR/certs/$lvl/server.crt",
  "key": "$GW_PKG_DIR/certs/$lvl/server.key",
  "pq_key": "$GW_PKG_DIR/certs/$lvl/server.pq.key",
  "root_ca": "$GW_PKG_DIR/certs/$lvl/root.crt",
  "intermediates": [],
  "server_name": "$GW_SERVER_NAME",
  "kex": $kex,
  "client_ca": "$GW_PKG_DIR/certs/$lvl/root.crt"
}
JSON
    record_cmd "启动交付包服务端" "$bin serve -config $cfg"
    server_start "$name" "cd '$GW_PKG_DIR' && exec '$bin' serve -config '$cfg'"
    wait_port "$GW_PORT" 10 || true
}

# gw_probe_cmd <kex> [auth] [44|87] [gateway|hqc]
gw_probe_cmd() {
    local kex=$1 auth=${2:-sm2-mldsa-44} lvl=${3:-44} kind=${4:-gateway}
    local bin=$GW_BIN
    [ "$kind" = hqc ] && bin=$GW_HQC_BIN
    echo "$bin probe -url https://127.0.0.1:$GW_PORT/ -server-name $GW_SERVER_NAME -ca '$GW_PKG_DIR/certs/$lvl/root.crt' -auth $auth -kex $kex -cert '$GW_PKG_DIR/demo/$lvl/client.crt' -key '$GW_PKG_DIR/demo/$lvl/client.key' -pq-key '$GW_PKG_DIR/demo/$lvl/client.pq.key' -client-ca '$GW_PKG_DIR/certs/$lvl/root.crt'"
}

gw_stop() {
    server_stop
    if [ -n "${GW_BACKEND_PID:-}" ] && kill -0 "$GW_BACKEND_PID" 2>/dev/null; then
        kill "$GW_BACKEND_PID" 2>/dev/null || true
        wait "$GW_BACKEND_PID" 2>/dev/null || true
    fi
    GW_BACKEND_PID=""
}
