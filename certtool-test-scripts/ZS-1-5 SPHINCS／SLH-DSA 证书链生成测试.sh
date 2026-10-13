#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-5
# 步骤：六档 SHA2 SLH-DSA 各生成一条根、中间、用户证书链。
for level in 128s 128f 192s 192f 256s 256f; do
    alg=SLH-DSA-SHA2-$level
    case_config "slh$level" slh-dsa "$alg" "$alg" "$alg" 1
    case_run
    for name in root inter1 user; do assert_pem "$name.crt" CERTIFICATE; done
    assert_report_algorithm user "$alg"
done
case_pass '六档 SLH-DSA 证书链均可生成和验签'
