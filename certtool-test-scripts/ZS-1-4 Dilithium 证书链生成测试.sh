#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-4
# 步骤：分别生成 ML-DSA-44/65/87 根、中间及用户签名型证书链。
for pair in '44 17' '65 18' '87 19'; do
    read -r dsa oid <<< "$pair"
    case_config "dsa$dsa" pure-pq "ML-DSA-$dsa" "ML-DSA-$dsa" "ML-DSA-$dsa" 1
    case_run
    for name in root inter1 user; do assert_pem "$name.crt" CERTIFICATE; assert_pem "$name.key" PQC\ PRIVATE\ KEY; assert_oid "$name.crt" "2.16.840.1.101.3.4.3.$oid"; done
    assert_report_algorithm user "ML-DSA-$dsa"
done
case_pass '三档标准 ML-DSA 签名链均通过'
