#!/usr/bin/env bash
# 客户端视角：本机压测客户端访问服务端 tlsbench 端点 8099
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-2-3" "X25519Kyber1024Draft00单连接建立耗时"
require_server "$SERVER_PORT_BENCH" "tlsbench 端点" || exit 1

capture_start tls-2-3-perf "$SERVER_PORT_BENCH"
run_sh 1 "压测客户端建立 ${PERF_N} 次连接" ".build/tlsbench -mode client -addr $SERVER_HOST:$SERVER_PORT_BENCH -kex X25519Kyber1024Draft00 -n ${PERF_N}"
expect_text 1 "全部成功" "成功 ${PERF_N} / 失败 0"
expect_text 1 "输出平均/分位耗时" "平均=|P95="
capture_stop
run_sh 2 "解析抓包（组 0xfe36）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-2-3-perf.pcap' $SERVER_PORT_BENCH --expect X25519Kyber1024Draft00"
finish_case
