#!/usr/bin/env bash
# 客户端视角：客户端输出协商结果事件（CFEvent），并与抓包交叉验证
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-3-1" "协商结果事件记录验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-3-1-negotiatedkex "$SERVER_PORT"
run_sh 1 "客户端握手并输出 CFEvent 协商结果" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519Kyber768Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "事件记录为 X25519Kyber768Draft00" "Used X25519Kyber768Draft00"
capture_stop
run_sh 2 "解析抓包（0x6399）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-3-1-negotiatedkex.pcap' $SERVER_PORT --expect X25519Kyber768Draft00"
expect_text 2 "ServerHello 选中 0x6399" "0x6399"
finish_case
