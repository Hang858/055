#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-11
# 步骤：生成 RSA、SM2 混合证书，检查 PQ 公钥扩展及内置验签。
for mode in rsa-hybrid sm2-hybrid; do
    case_config "$mode" "$mode" ML-DSA-44 ML-DSA-65 ML-KEM-512 1
    case_run
    assert_oid user.crt 1.3.6.1.4.1.54321.1.1
    assert_oid user.crt 2.16.840.1.101.3.4.4.1
    assert_pem user.pub PQC\ PUBLIC\ KEY
done
case_pass '两种混合证书均包含可验签的 PQ 公钥扩展'
