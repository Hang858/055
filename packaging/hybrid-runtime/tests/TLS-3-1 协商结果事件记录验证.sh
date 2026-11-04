#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-3-1" "协商结果事件记录验证"
gw_serve k768 '["X25519Kyber768Draft00"]'
capture_start tls-3-1-negotiatedkex "$GW_PORT"
run_sh 1 "probe 输出协商结果" "$(gw_probe_cmd X25519Kyber768Draft00)"
expect_text 1 "记录为 X25519Kyber768Draft00" "negotiated_kex=X25519Kyber768Draft00"
capture_stop
run_sh 2 "解析抓包（0x6399）" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-3-1-negotiatedkex.pcap' --expect X25519Kyber768Draft00"
expect_text 2 "ServerHello 选中 0x6399" "0x6399"
server_stop
finish_case
