#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-5" "ClientHello消息格式验证"
gw_serve ch '["SM2Kyber512Draft00"]'
capture_start tls-1-5-clienthello "$GW_PORT"
run_sh 1 "probe（抓取 ClientHello）" "$(gw_probe_cmd SM2Kyber512Draft00)"
expect_text 1 "握手与 HTTP 成功" "http_status= 200|certificate_verified=true"
capture_stop; server_stop
run_sh 2 "解析 ClientHello" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-5-clienthello.pcap'"
expect_text 2 "抓到 ClientHello 且含 supported_groups" "ClientHello"
expect_text 2 "supported_groups 已解析" "supported_groups"
expect_text 2 "含 TLS 1.3" "TLS 1\\.3"
finish_case
