#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-2
# 步骤1：生成根 CA、两级中间 CA 和用户的 SM2 混合链；verify 同时校验 SM2 与 PQ 签名。
case_config sm2 sm2-hybrid ML-DSA-44 ML-DSA-65 ML-KEM-512 2
case_run
# 步骤2：验收两类私钥、用户扩展和签发关系。
for name in root inter1 inter2 user; do assert_pem "$name.crt" CERTIFICATE; assert_pem "$name.key" PRIVATE\ KEY; assert_pem "$name.pq.key" PQC\ PRIVATE\ KEY; done
assert_oid user.crt 1.3.6.1.4.1.54321.1.1
assert_oid user.crt 1.3.6.1.4.1.54321.1.2
assert_report_algorithm user ML-KEM-512
case_pass 'SM2 与 PQ 双重验签及输出符合预期'
