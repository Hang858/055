#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-8
# 步骤：覆盖六档 SLH-DSA 密钥生成、证书签发及验签。
for level in 128s 128f 192s 192f 256s 256f; do
    alg=SLH-DSA-SHA2-$level
    case_config "key$level" slh-dsa "$alg" "$alg" "$alg" 1
    case_run
    for name in root inter1 user; do assert_pem "$name.key" PQC\ PRIVATE\ KEY; done
    assert_report_algorithm user "$alg"
done
case_pass '六档 SLH-DSA 私钥输出并完成签发、验签'
