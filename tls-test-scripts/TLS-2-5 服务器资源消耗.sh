#!/usr/bin/env bash
# 服务端侧用例：必须在服务端本机执行（读取服务端进程 CPU/内存/线程）
export MODE=server CAPTURE_IFACE=lo
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-2-5" "服务器资源消耗"

server_start bench ".build/tlsbench -mode server -addr :8199 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00"
wait_port 8199 || true
PID=$SERVER_PID
# 优先用系统 pidstat；若服务器离线未装 sysstat，则用交付目录内私有解压的版本
PIDSTAT_BIN=${PIDSTAT:-pidstat}
if ! command -v "$PIDSTAT_BIN" >/dev/null 2>&1; then
    PIDSTAT_BIN="$PROJECT_ROOT/tools/sysstat/usr/bin/pidstat"
fi
record_cmd "服务端进程号" "服务端PID=$PID"
run_sh 1 "空载采样 CPU/内存/线程" "$PIDSTAT_BIN -p $PID 1 3; grep -E 'VmRSS|Threads' /proc/$PID/status"
expect_text 1 "采样到进程内存与线程数" "VmRSS"
expect_text 1 "采样到线程数" "Threads"
capture_start tls-2-5-load 8199
( for i in $(seq 1 "${LOAD_LOOPS}"); do .build/tlsbench -mode client -addr localhost:8199 -kex X25519Kyber1024Draft00 -n 20 >/dev/null 2>&1; done ) &
LOAD_PID=$!
record_cmd "持续负载" "for i in \$(seq 1 ${LOAD_LOOPS}); do .build/tlsbench -mode client ... -n 20; done &（PID $LOAD_PID）"
sleep 3
run_sh 2 "负载中采样 CPU/内存/线程" "$PIDSTAT_BIN -p $PID 1 3; grep -E 'VmRSS|VmHWM|Threads' /proc/$PID/status; ps -o pid,pcpu,pmem,rss,vsz,etime -p $PID"
expect_text 2 "负载中采样到内存峰值" "VmHWM"
expect_text 2 "采样到进程 RSS（ps 输出）" "RSS"
sleep 7
capture_stop
wait "$LOAD_PID" 2>/dev/null || true
run_sh 3 "确认服务端仍存活、端口未释放" "kill -0 $PID && echo 服务端存活"
expect_text 3 "服务端存活" "服务端存活"
server_stop
finish_case
