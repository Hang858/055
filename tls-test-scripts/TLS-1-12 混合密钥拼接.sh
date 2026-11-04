#!/usr/bin/env bash
# 客户端视角：逐组握手，解析 ClientHello/ServerHello 的 key_share 拼接长度
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-12" "混合密钥拼接"
require_server "$SERVER_PORT" || exit 1
require_server "$SERVER_PORT_HQC" "HQC 端点" || exit 1

run_group() {
    local grp=$1 bin=$2 ch=$3 sh=$4 port=$5 n=$6
    capture_start "tls-1-12-$grp" "$port"
    run_sh "$n" "客户端握手（$grp）" "$bin -addr $SERVER_HOST:$port -kex $grp -ca .build/certs/server_root_cert1.pem"
    expect_text "$n" "握手完成并输出协商组" "Used"
    capture_stop
    n=$((n+1))
    run_sh "$n" "解析 $grp 的 key_share 拼接长度（期望 CH $ch / SH $sh）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-1-12-$grp.pcap' $port --expect $grp"
    expect_text "$n" "CH key_share 长度 $ch" "CH key_share:.*长度=$ch"
    expect_text "$n" "SH key_share 长度 $sh" "SH key_share:.*长度=$sh"
}

run_group SM2Kyber512Draft00      .build/client     865  897   "$SERVER_PORT"     1
run_group X25519Kyber512Draft00   .build/client     832  800   "$SERVER_PORT"     3
run_group X25519Kyber768Draft00   .build/client     1216 1120  "$SERVER_PORT"     5
run_group X25519Kyber1024Draft00  .build/client     1600 1600  "$SERVER_PORT"     7
run_group X25519HQC-128           .build/client_hqc 2281 4465  "$SERVER_PORT_HQC" 9
run_group X25519HQC-256           .build/client_hqc 7277 14453 "$SERVER_PORT_HQC" 11
finish_case
