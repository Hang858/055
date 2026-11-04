#!/usr/bin/env bash
# 客户端视角：本机并发压测访问服务端 tlsbench 端点 8099
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-2-4" "并发多个TLS连接建立耗时"
require_server "$SERVER_PORT_BENCH" "tlsbench 端点" || exit 1

capture_start tls-2-4-concurrency "$SERVER_PORT_BENCH"
run_sh 1 "并发 ${CONCURRENCY_C}、共 ${CONCURRENCY_N} 次连接" ".build/tlsbench -mode client -addr $SERVER_HOST:$SERVER_PORT_BENCH -kex X25519Kyber1024Draft00 -c ${CONCURRENCY_C} -n ${CONCURRENCY_N}"
expect_text 1 "全部成功" "成功 ${CONCURRENCY_N} / 失败 0"
expect_text 1 "输出连接速率与分位耗时" "连接/秒|P95="
capture_stop
run_sh 2 "解析抓包（组 0xfe36）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-2-4-concurrency.pcap' $SERVER_PORT_BENCH --expect X25519Kyber1024Draft00"
finish_case
