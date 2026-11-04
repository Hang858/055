#!/usr/bin/env bash
# 客户端视角：本机客户端访问服务端固定端点 8080（全部非 HQC 组）
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-1" "格类128比特抗量子算法混合密钥交换"
require_server "$SERVER_PORT" || exit 1

# 场景 A：国密分量 SM2 + Kyber-512
capture_start tls-1-1-kyber512 "$SERVER_PORT"
run_sh 1 "客户端握手（SM2Kyber512Draft00）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex SM2Kyber512Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "客户端完成握手并输出协商结果" "Used .*Kyber512"
capture_stop
run_sh 2 "解析抓包（SM2Kyber512Draft00）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-1-kyber512.pcap' $SERVER_PORT --expect SM2Kyber512Draft00"
expect_text 2 "协商组为 0xfe34" "0xfe34"
expect_text 2 "CH key_share 长度 865" "CH key_share:.*长度=865"
expect_text 2 "SH key_share 长度 897" "SH key_share:.*长度=897"

# 场景 B：经典分量 X25519 + Kyber-512
capture_start tls-1-1-x25519kyber512 "$SERVER_PORT"
run_sh 3 "客户端握手（X25519Kyber512Draft00）" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519Kyber512Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 3 "客户端完成握手" "Used .*Kyber512"
capture_stop
run_sh 4 "解析抓包（X25519Kyber512Draft00）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-1-x25519kyber512.pcap' $SERVER_PORT --expect X25519Kyber512Draft00"
expect_text 4 "协商组为 0xfe30" "0xfe30"
if command -v tshark >/dev/null 2>&1 && tshark -G fields 2>/dev/null | grep -q 'tls.handshake.extensions_key_share_key_exchange_length'; then
    run_sh 5 "tshark 独立复核 CH key_share 长度" "tshark -r '$CASE_DIR/captures/tls-1-1-kyber512.pcap' -d tcp.port==$SERVER_PORT,tls -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_key_share_key_exchange_length"
    expect_text 5 "tshark 读到 CH 长度 865" "^865$"
    run_sh 6 "tshark 独立复核 SH key_share 长度" "tshark -r '$CASE_DIR/captures/tls-1-1-kyber512.pcap' -d tcp.port==$SERVER_PORT,tls -Y 'tls.handshake.type==2' -T fields -e tls.handshake.extensions_key_share_key_exchange_length"
    expect_text 6 "tshark 读到 SH 长度 897" "^897$"
else
    skip_step 5 "tshark 独立复核 key_share 长度" "未安装 tshark 或版本不支持 key_exchange_length 字段"
fi
finish_case
