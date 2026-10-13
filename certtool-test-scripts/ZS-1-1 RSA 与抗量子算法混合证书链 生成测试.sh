#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-1
# 步骤1：配置两级中间 CA，生成 RSA + ML-DSA/ML-KEM 混合链并逐级验签。
case_config rsa rsa-hybrid ML-DSA-44 ML-DSA-44 ML-KEM-512 2
case_run
# 步骤2：验收四级证书、传统 RSA 链及抗量子扩展。
for name in root inter1 inter2 user; do assert_pem "$name.crt" CERTIFICATE; assert_pem "$name.key" PRIVATE\ KEY; assert_pem "$name.pq.key" PQC\ PRIVATE\ KEY; done
assert_rsa_chain
assert_oid user.crt 1.3.6.1.4.1.54321.1.1
assert_oid user.crt 1.3.6.1.4.1.54321.1.2
assert_report_algorithm user ML-KEM-512
case_pass 'RSA 链、两项 PQ 扩展及四级输出符合预期'
