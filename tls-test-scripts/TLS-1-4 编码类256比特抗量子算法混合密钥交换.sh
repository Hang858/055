#!/usr/bin/env bash
# 客户端视角：本机客户端访问服务端 HQC 端点 8081（全部 HQC 组）
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-4" "编码类256比特抗量子算法混合密钥交换"
require_server "$SERVER_PORT_HQC" || exit 1

capture_start tls-1-4-hqc256 "$SERVER_PORT_HQC"
run_sh 1 "客户端握手（SM2HQC-256）" ".build/client_hqc -addr $SERVER_HOST:$SERVER_PORT_HQC -kex SM2HQC-256 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成 HQC-256 握手" "Used .*HQC"
capture_stop
run_sh 2 "解析抓包（SM2HQC-256）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-4-hqc256.pcap' $SERVER_PORT_HQC --expect SM2HQC-256"
expect_text 2 "协商组为 0xfe3b" "0xfe3b"

capture_start tls-1-4-x25519hqc256 "$SERVER_PORT_HQC"
run_sh 3 "客户端握手（X25519HQC-256）" ".build/client_hqc -addr $SERVER_HOST:$SERVER_PORT_HQC -kex X25519HQC-256 -ca .build/certs/server_root_cert1.pem"
expect_text 3 "客户端完成 HQC-256 握手" "Used .*HQC"
capture_stop
run_sh 4 "解析抓包（X25519HQC-256）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-4-x25519hqc256.pcap' $SERVER_PORT_HQC --expect X25519HQC-256"
expect_text 4 "协商组为 0xfe39" "0xfe39"
finish_case
