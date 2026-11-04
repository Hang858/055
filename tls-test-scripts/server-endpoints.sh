#!/usr/bin/env bash
# 服务端侧：预启动客户端用例使用的固定端口端点（只需在服务端执行一次）
# 用法：bash tls-test-scripts/server-endpoints.sh {start|stop|status}
set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PREFIX=$(cd -- "$SCRIPT_DIR/.." && pwd)
BIN=$PREFIX/.build
CERTS=$BIN/certs
STATE=$PREFIX/endpoints
mkdir -p "$STATE"

# 端口 8080 全部非 HQC 组；8181 全部 HQC 组；8082 协商策略；8099 压测；8111 过期证书
PORTS="8080 8181 8082 8099 8111"

port_pid() {
    ss -ltnp "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2
}

start_one() {
    local port=$1
    shift
    local pidf="$STATE/$port.pid" log="$STATE/$port.log" pid
    pid=$(port_pid "$port")
    if [ -n "$pid" ]; then
        echo "$pid" > "$pidf"
        echo "$port 已在监听（PID $pid），跳过启动"
        return 0
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        echo "$port 已在监听但无权限读取 PID（可能由 root 启动），请用 sudo 运行本脚本" >&2
        return 1
    fi
    rm -f "$pidf"
    ( cd "$PREFIX" && setsid "$@" >>"$log" 2>&1 </dev/null & )
    sleep 0.6
    pid=$(port_pid "$port")
    if [ -n "$pid" ]; then
        echo "$pid" > "$pidf"
        echo "$port 已启动（PID $pid，日志 endpoints/$port.log）"
    else
        echo "$port 启动失败，见 endpoints/$port.log" >&2
    fi
}

stop_one() {
    local port=$1 pid pidf
    pidf="$STATE/$port.pid"
    pid=$(port_pid "$port")
    if [ -z "$pid" ]; then
        rm -f "$pidf"
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            echo "$port 在监听但无权限读取 PID（可能由 root 启动），请用 sudo 运行本脚本" >&2
            return 1
        fi
        echo "$port 未在监听"
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$pidf"
    echo "$port 已停止（PID $pid）"
}

status_one() {
    local port=$1
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        echo "$port 监听中"
    else
        echo "$port 未监听"
    fi
}

start_all() {
    [ -x "$BIN/server" ] || { echo "未找到 $BIN/server" >&2; exit 1; }
    start_one 8080 "$BIN/server" -addr :8080 -cert "$CERTS/server_root_cert1.pem" -key "$CERTS/server_root_key1.pem"
    if [ -x "$BIN/server_hqc" ]; then
        start_one 8181 "$BIN/server_hqc" -addr :8181 -cert "$CERTS/server_root_cert1.pem" -key "$CERTS/server_root_key1.pem"
    else
        echo "未找到 server_hqc，跳过 8181（HQC 用例将失败）" >&2
    fi
    start_one 8082 "$BIN/server" -addr :8082 -kex X25519,X25519Kyber1024Draft00 -cert "$CERTS/server_root_cert1.pem" -key "$CERTS/server_root_key1.pem"
    start_one 8099 "$BIN/tlsbench" -mode server -addr :8099 -cert "$CERTS/server_root_cert1.pem" -key "$CERTS/server_root_key1.pem"
    start_one 8111 "$BIN/server" -addr :8111 -cert "$PREFIX/tls-hybrid/server/server_root_cert1.pem" -key "$PREFIX/tls-hybrid/server/server_root_key1.pem"
}

case "${1:-start}" in
    start)  start_all ;;
    stop)   for p in $PORTS; do stop_one "$p"; done ;;
    status) for p in $PORTS; do status_one "$p"; done ;;
    *)      echo "用法：$0 {start|stop|status}" >&2; exit 2 ;;
esac
