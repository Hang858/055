#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-7" "多密钥交换组协商策略验证"
# 交付包按配置顺序选择服务端偏好组：配置首位为 SM2Kyber512Draft00
gw_serve multi '["SM2Kyber512Draft00","X25519Kyber1024Draft00"]'
capture_start tls-1-7-negotiation "$GW_PORT"
run_sh 1 "probe 按相反优先级发起（X25519Kyber1024Draft00,SM2Kyber512Draft00）" "$(gw_probe_cmd 'X25519Kyber1024Draft00,SM2Kyber512Draft00')"
expect_text 1 "按服务端偏好选中 SM2Kyber512Draft00" "negotiated_kex=SM2Kyber512Draft00"
capture_stop; server_stop
run_sh 2 "解析抓包（0xfe34）" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-7-negotiation.pcap' --expect SM2Kyber512Draft00"
expect_text 2 "最终协商 0xfe34" "0xfe34"
finish_case
