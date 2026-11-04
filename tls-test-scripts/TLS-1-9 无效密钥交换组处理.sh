#!/usr/bin/env bash
# 客户端视角：本机客户端首选服务端不支持的组，验证 HelloRetryRequest 回退
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-9" "无效密钥交换组处理"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-9-hrr "$SERVER_PORT"
run_sh 1 "客户端首选不支持的 DummyKex，保留 X25519" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex DummyKex,X25519 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "触发 HelloRetryRequest 后握手成功" "Used X25519"
capture_stop
run_sh 2 "解析抓包（应含 HRR）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-9-hrr.pcap' $SERVER_PORT --expect X25519"
expect_text 2 "出现 HelloRetryRequest 与两条 ServerHello" "HelloRetryRequest"
expect_text 2 "ServerHello 共 2 条（HRR + 正式）" "共 2 条"
finish_case
