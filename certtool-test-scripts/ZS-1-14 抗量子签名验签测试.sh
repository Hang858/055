#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-14
# 步骤：分别生成 RSA、SM2 混合证书，verify 提取扩展后对原始 TBS 执行 ML-DSA 验签。
for mode in rsa-hybrid sm2-hybrid; do
    case_config "$mode" "$mode" ML-DSA-44 ML-DSA-87 ML-KEM-1024 1
    case_run
    assert_oid user.crt 1.3.6.1.4.1.54321.1.2
    assert_oid user.crt 2.16.840.1.101.3.4.3.19
done
case_pass 'RSA、SM2 混合证书的 PQ 扩展签名均通过'
