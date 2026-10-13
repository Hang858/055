#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-12
# 步骤：检查混合证书的 PQ 签名扩展及签发者标准算法标识。
for mode in rsa-hybrid sm2-hybrid; do
    case_config "$mode" "$mode" ML-DSA-44 ML-DSA-65 ML-KEM-512 1
    case_run
    assert_oid user.crt 1.3.6.1.4.1.54321.1.2
    assert_oid user.crt 2.16.840.1.101.3.4.3.18
done
case_pass 'PQ 签名扩展存在，内置验签通过'
