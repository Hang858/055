#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-2-5" "服务器资源消耗"
gw_serve res '["SM2MLKEM512"]'
PID=$SERVER_PID
record_cmd "服务端进程号" "服务端PID=$PID"
run_sh 1 "空载采样 CPU/内存/线程" "pidstat -p $PID 1 3; grep -E 'VmRSS|Threads' /proc/$PID/status"
capture_start tls-2-5-load "$GW_PORT"
( for i in $(seq 1 "${LOAD_LOOPS:-30}"); do "$GW_BIN" probe -url https://127.0.0.1:$GW_PORT/ -server-name "$GW_SERVER_NAME" -ca "$GW_PKG_DIR/certs/44/root.crt" -auth sm2-mldsa-44 -kex SM2MLKEM512 -cert "$GW_PKG_DIR/demo/44/client.crt" -key "$GW_PKG_DIR/demo/44/client.key" -pq-key "$GW_PKG_DIR/demo/44/client.pq.key" -client-ca "$GW_PKG_DIR/certs/44/root.crt" >/dev/null 2>&1; done ) &
LOAD_PID=$!
sleep 3
run_sh 2 "负载中采样 CPU/内存/线程" "pidstat -p $PID 1 3; grep -E 'VmRSS|VmHWM|Threads' /proc/$PID/status; ps -o pid,pcpu,pmem,rss,vsz,etime -p $PID"
sleep 5
capture_stop
wait "$LOAD_PID" 2>/dev/null || true
run_sh 3 "确认服务端存活" "kill -0 $PID && echo 服务端存活"
expect_text 3 "服务端存活" "服务端存活"
server_stop
finish_case
