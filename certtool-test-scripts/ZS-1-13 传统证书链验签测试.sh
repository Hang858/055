#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-13
# 步骤1：RSA 两级中间 CA 链用工具和 OpenSSL 双重验签。
case_config rsa rsa-hybrid ML-DSA-44 ML-DSA-44 ML-KEM-512 2
case_run
assert_rsa_chain
# 步骤2：SM2 两级中间 CA 链使用工具内置 CheckSignatureFrom 验签。
case_config sm2 sm2-hybrid ML-DSA-44 ML-DSA-44 ML-KEM-512 2
case_run
for name in root inter1 inter2 user; do assert_pem "$name.crt" CERTIFICATE; done
case_pass 'RSA 与 SM2 传统签发链均有效'
