#!/usr/bin/env bash
# 客户端视角：端点 8082 仅启用 X25519,X25519Kyber1024Draft00，验证按服务端偏好选组
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-7" "多密钥交换组协商策略验证"
require_server "$SERVER_PORT_POLICY" || exit 1

capture_start tls-1-7-negotiation "$SERVER_PORT_POLICY"
run_sh 1 "客户端按自身优先级发起（X25519Kyber768Draft00,X25519）" ".build/client -addr $SERVER_HOST:$SERVER_PORT_POLICY -kex X25519Kyber768Draft00,X25519 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "按服务端偏好选中 X25519" "Used X25519"
capture_stop
run_sh 2 "解析抓包（应为 0x001d）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-7-negotiation.pcap' $SERVER_PORT_POLICY --expect X25519"
expect_text 2 "最终协商 0x001d" "0x001d"
finish_case
