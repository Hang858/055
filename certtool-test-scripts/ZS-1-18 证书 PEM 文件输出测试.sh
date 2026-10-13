#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-18
# 步骤：四种模式各生成根、中间、用户证书，检查 PEM 块和解析能力。
for mode in pure-pq rsa-hybrid sm2-hybrid sm2; do
    if test "$mode" = sm2; then
        case_config "$mode" "$mode" SM2 SM2 SM2 1
    else
        case_config "$mode" "$mode" ML-DSA-44 ML-DSA-44 ML-KEM-512 1
    fi
    case_run
    for name in root inter1 user; do
        assert_pem "$name.crt" CERTIFICATE
        openssl x509 -in "$OUT_DIR/$name.crt" -noout -subject > "$CASE_DIR/$mode-$name.subject.txt"
    done
done
case_pass '四类证书均输出可解析的 CERTIFICATE PEM'
