#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-7
# 步骤：三档 ML-DSA 各生成签名密钥、证书，并复核签名型用户链。
for dsa in 44 65 87; do
    alg=ML-DSA-$dsa
    case_config "key$dsa" pure-pq "$alg" "$alg" "$alg" 1
    case_run
    for name in root inter1 user; do assert_pem "$name.key" PQC\ PRIVATE\ KEY; assert_pem "$name.crt" CERTIFICATE; done
    assert_report_algorithm user "$alg"
done
case_pass '三档 ML-DSA 密钥均用于成功签发和验签'
