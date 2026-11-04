#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-2" "格类256比特抗量子算法混合密钥交换"
n=1
for spec in "SM2Kyber1024Draft00:0xfe37:1633" "X25519Kyber1024Draft00:0xfe36:1600"; do
    grp=${spec%%:*}; rest=${spec#*:}; cp=${rest%%:*}; ch=${rest##*:}
    gw_serve "srv-$grp" "[\"$grp\"]"
    capture_start "tls-1-2-$grp" "$GW_PORT"
    run_sh "$n" "probe $grp" "$(gw_probe_cmd "$grp")"
    expect_text "$n" "协商 $grp" "negotiated_kex=$grp"
    expect_text "$n" "证书校验通过" "certificate_verified=true"
    capture_stop; server_stop; n=$((n+1))
    run_sh "$n" "解析 $grp 抓包" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-2-$grp.pcap' --expect $grp"
    expect_text "$n" "CH key_share 长度 $ch" "$ch"
    n=$((n+1))
done
finish_case
