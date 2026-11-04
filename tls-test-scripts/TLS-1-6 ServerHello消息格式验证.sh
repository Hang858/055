#!/usr/bin/env bash
# 客户端视角：本机客户端握手，抓取服务端返回的 ServerHello
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-6" "ServerHello消息格式验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-6-serverhello "$SERVER_PORT"
run_sh 1 "客户端握手（抓取 ServerHello）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成握手" "Server response"
capture_stop
run_sh 2 "解析 ServerHello" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-6-serverhello.pcap' $SERVER_PORT --expect SM2Kyber512Draft00"
expect_text 2 "ServerHello 选中 0xfe34" "0xfe34"
expect_text 2 "SH key_share 长度 897" "SH key_share:.*长度=897"
finish_case
