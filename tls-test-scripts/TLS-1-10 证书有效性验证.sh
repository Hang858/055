#!/usr/bin/env bash
# 客户端视角：本机客户端校验证书
#   8111 端点提供过期证书；8080 端点提供有效证书
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-10" "证书有效性验证"
require_server "$SERVER_PORT_EXPIRED" "过期证书端点" || exit 1
require_server "$SERVER_PORT" "有效证书端点" || exit 1

capture_start tls-1-10-cert "port $SERVER_PORT_EXPIRED or port $SERVER_PORT"
run_sh_fail 1 "过期证书 + -verify（应校验失败）" ".build/client -addr $SERVER_HOST:$SERVER_PORT_EXPIRED -verify -ca tls-hybrid/server/server_root_cert1.pem"
expect_text 1 "客户端报证书过期" "expired|not yet valid"
run_sh_fail 2 "有效证书 + 无关 CA（应校验失败）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -verify -ca .build/certs/other.crt"
expect_text 2 "客户端报未知签发者" "unknown authority|unknown certificate"
run_sh 3 "有效证书 + 对应 CA（应校验通过）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -verify -ca .build/certs/server_root_cert1.pem"
expect_text 3 "证书校验通过并完成通信" "Server response|代码执行时间"
capture_stop
run_sh 4 "统计抓包中的记录类型" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-10-cert.pcap' $SERVER_PORT"
expect_text 4 "抓包中存在 ClientHello" "ClientHello"
finish_case
