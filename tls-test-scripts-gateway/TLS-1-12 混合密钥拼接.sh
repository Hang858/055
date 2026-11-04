#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-12" "混合密钥拼接"
n=1
while IFS=: read -r grp ch sh kind; do
    [ -z "$grp" ] && continue
    if [ "$kind" = hqc ]; then
        gw_serve "srv-$grp" "[\"$grp\"]" sm2-mldsa-44 44 hqc
    else
        gw_serve "srv-$grp" "[\"$grp\"]"
    fi
    capture_start "tls-1-12-$grp" "$GW_PORT"
    if [ "$kind" = hqc ]; then
        run_sh "$n" "probe $grp" "$(gw_probe_cmd "$grp" sm2-mldsa-44 44 hqc)"
    else
        run_sh "$n" "probe $grp" "$(gw_probe_cmd "$grp")"
    fi
    expect_text "$n" "协商 $grp" "negotiated_kex=$grp"
    capture_stop; server_stop; n=$((n+1))
    run_sh "$n" "解析 $grp（期望 CH $ch / SH $sh）" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-12-$grp.pcap' --expect $grp"
    expect_text "$n" "CH key_share 长度 $ch" "$ch"
    expect_text "$n" "SH key_share 长度 $sh" "$sh"
    n=$((n+1))
done <<'GROUPS'
SM2Kyber512Draft00:865:897:gateway
X25519Kyber512Draft00:832:800:gateway
X25519Kyber768Draft00:1216:1120:gateway
X25519Kyber1024Draft00:1600:1600:gateway
X25519HQC-128:2281:4465:hqc
X25519HQC-256:7277:14453:hqc
GROUPS
finish_case
