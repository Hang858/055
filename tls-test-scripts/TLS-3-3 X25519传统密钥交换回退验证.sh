#!/usr/bin/env bash
# 客户端视角：客户端仅提供 X25519，验证回退到传统密钥交换
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-3-3" "X25519传统密钥交换回退验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-3-3-fallback "$SERVER_PORT"
run_sh 1 "客户端仅用 X25519 握手" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "回退到 X25519" "Used X25519"
capture_stop
run_sh 2 "解析抓包（0x001d，32 字节）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-3-3-fallback.pcap' $SERVER_PORT --expect X25519"
expect_text 2 "key_share 组 0x001d、长度 32" "0x001d"
finish_case
