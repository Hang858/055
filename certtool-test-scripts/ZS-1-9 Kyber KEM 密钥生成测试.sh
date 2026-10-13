#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-9
# 步骤：在一条纯 PQ 签名链下签发三档 ML-KEM 用户证书。
case_config kems pure-pq ML-DSA-87 ML-DSA-87 ML-KEM-512 1
case_add_leaf user768 ML-KEM-768
case_add_leaf user1024 ML-KEM-1024
case_run
for pair in 'user 512 1' 'user768 768 2' 'user1024 1024 3'; do
    read -r name kem oid <<< "$pair"
    assert_pem "$name.key" PQC\ PRIVATE\ KEY
    assert_pem "$name.crt" CERTIFICATE
    assert_report_algorithm "$name" "ML-KEM-$kem"
    assert_oid "$name.crt" "2.16.840.1.101.3.4.4.$oid"
done
case_pass '三档 ML-KEM 密钥和用户证书均有效'
