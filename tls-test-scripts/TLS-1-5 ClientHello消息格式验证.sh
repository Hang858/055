#!/usr/bin/env bash
# 客户端视角：本机客户端握手，抓取本机发出的 ClientHello
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-5" "ClientHello消息格式验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-5-clienthello "$SERVER_PORT"
run_sh 1 "客户端握手（默认启用全部组，抓取 ClientHello）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成握手" "Server response"
capture_stop
run_sh 2 "解析 ClientHello" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-5-clienthello.pcap' $SERVER_PORT"
expect_text 2 "抓到 ClientHello 且含 supported_groups" "ClientHello"
expect_text 2 "supported_groups 已解析" "supported_groups"
expect_text 2 "含 TLS 1.3 版本" "TLS 1\\.3"
finish_case
