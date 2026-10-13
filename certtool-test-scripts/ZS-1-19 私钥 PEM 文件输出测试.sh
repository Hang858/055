#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-19

# 步骤1：生成纯 PQ 证书链，检查 ML-DSA 与 ML-KEM 私钥。
case_config pure-pq pure-pq ML-DSA-44 ML-DSA-44 ML-KEM-512 1
case_run
for name in root inter1 user; do assert_pem "$name.key" 'PQC PRIVATE KEY'; done

# 步骤2：生成 SLH-DSA 证书链，检查哈希签名私钥。
case_config slh slh-dsa SLH-DSA-SHA2-128s SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f 1
case_run
for name in root inter1 user; do assert_pem "$name.key" 'PQC PRIVATE KEY'; done

# 步骤3：生成 RSA 和 SM2 混合链，分别检查传统私钥及 PQ 私钥。
for mode in rsa-hybrid sm2-hybrid; do
    case_config "$mode" "$mode" ML-DSA-44 ML-DSA-44 ML-KEM-512 1
    case_run
    for name in root inter1 user; do
        assert_pem "$name.key" 'PRIVATE KEY'
        assert_pem "$name.pq.key" 'PQC PRIVATE KEY'
    done
done

# 验收：每种私钥存在且非空，PEM 类型与当前程序一致，证书链验签通过。
case_pass 'ML-DSA、ML-KEM、SLH-DSA、RSA、SM2 私钥均按当前格式输出并完成验签'
