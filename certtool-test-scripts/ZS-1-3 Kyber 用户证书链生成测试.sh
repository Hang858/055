#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-3
# 步骤：逐档生成以标准 ML-KEM 公钥为主体的用户证书；旧 Kyber 配置名由工具映射。
for pair in '512 44' '768 65' '1024 87'; do
    read -r kem dsa <<< "$pair"
    case_config "kem$kem" pure-pq "ML-DSA-$dsa" "ML-DSA-$dsa" "ML-KEM-$kem" 1
    case_run
    assert_pem user.crt CERTIFICATE
    assert_pem user.key PQC\ PRIVATE\ KEY
    assert_report_algorithm user "ML-KEM-$kem"
    case "$kem" in 512) oid=1;;768) oid=2;;1024) oid=3;; esac
    assert_oid user.crt "2.16.840.1.101.3.4.4.$oid"
done
case_pass '512、768、1024 三档用户证书和签名链均通过'
