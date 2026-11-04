#!/usr/bin/env bash
# 客户端视角：本机客户端访问服务端 HQC 端点 8081（全部 HQC 组）
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-3" "编码类128比特抗量子算法混合密钥交换"
require_server "$SERVER_PORT_HQC" || exit 1

capture_start tls-1-3-hqc128 "$SERVER_PORT_HQC"
run_sh 1 "客户端握手（SM2HQC-128）" ".build/client_hqc -addr $SERVER_HOST:$SERVER_PORT_HQC -kex SM2HQC-128 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成 HQC-128 握手" "Used .*HQC"
capture_stop
run_sh 2 "解析抓包（SM2HQC-128）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-3-hqc128.pcap' $SERVER_PORT_HQC --expect SM2HQC-128"
expect_text 2 "协商组为 0xfe3a" "0xfe3a"

capture_start tls-1-3-x25519hqc128 "$SERVER_PORT_HQC"
run_sh 3 "客户端握手（X25519HQC-128）" ".build/client_hqc -addr $SERVER_HOST:$SERVER_PORT_HQC -kex X25519HQC-128 -ca .build/certs/server_root_cert1.pem"
expect_text 3 "客户端完成 HQC-128 握手" "Used .*HQC"
capture_stop
run_sh 4 "解析抓包（X25519HQC-128）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-3-x25519hqc128.pcap' $SERVER_PORT_HQC --expect X25519HQC-128"
expect_text 4 "协商组为 0xfe38" "0xfe38"
finish_case
