#!/usr/bin/env bash
# 客户端视角：本机客户端访问服务端固定端点 8080（全部非 HQC 组）
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-2" "格类256比特抗量子算法混合密钥交换"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-2-kyber1024 "$SERVER_PORT"
run_sh 1 "客户端握手（SM2Kyber1024Draft00）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex SM2Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成 256 比特档握手" "Used .*Kyber1024"
capture_stop
run_sh 2 "解析抓包（SM2Kyber1024Draft00）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-2-kyber1024.pcap' $SERVER_PORT --expect SM2Kyber1024Draft00"
expect_text 2 "协商组为 0xfe37" "0xfe37"

capture_start tls-1-2-x25519kyber1024 "$SERVER_PORT"
run_sh 3 "客户端握手（X25519Kyber1024Draft00）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 3 "客户端完成 256 比特档握手" "Used .*Kyber1024"
capture_stop
run_sh 4 "解析抓包（X25519Kyber1024Draft00）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-2-x25519kyber1024.pcap' $SERVER_PORT --expect X25519Kyber1024Draft00"
expect_text 4 "协商组为 0xfe36" "0xfe36"
finish_case
