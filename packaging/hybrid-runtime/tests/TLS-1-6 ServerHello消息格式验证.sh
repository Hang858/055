#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-6" "ServerHello消息格式验证"
gw_serve sh '["SM2Kyber512Draft00"]'
capture_start tls-1-6-serverhello "$GW_PORT"
run_sh 1 "probe（抓取 ServerHello）" "$(gw_probe_cmd SM2Kyber512Draft00)"
expect_text 1 "握手成功" "certificate_verified=true"
capture_stop; server_stop
run_sh 2 "解析 ServerHello" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-6-serverhello.pcap' --expect SM2Kyber512Draft00"
expect_text 2 "ServerHello 选中 0xfe34" "0xfe34"
expect_text 2 "SH 长度 897" "897"
finish_case
