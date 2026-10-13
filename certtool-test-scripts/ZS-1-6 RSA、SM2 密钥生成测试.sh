#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-6
# 步骤：分别生成 RSA 与 SM2 混合链，检查私钥并验签。
case_config rsa rsa-hybrid ML-DSA-44 ML-DSA-44 ML-KEM-512 1
case_run
assert_pem root.key PRIVATE\ KEY
assert_pem user.key PRIVATE\ KEY
openssl rsa -in "$OUT_DIR/root.key" -noout -check > "$CASE_DIR/rsa-key-check.txt"
assert_rsa_chain
case_config sm2 sm2-hybrid ML-DSA-44 ML-DSA-44 ML-KEM-512 1
case_run
assert_pem root.key PRIVATE\ KEY
assert_pem user.key PRIVATE\ KEY
assert_report_algorithm user ML-KEM-512
case_pass 'RSA、SM2 私钥输出并用于签发和验签'
