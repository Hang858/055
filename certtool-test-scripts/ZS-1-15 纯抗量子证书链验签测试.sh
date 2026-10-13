#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-15
# 步骤：分别验收 ML-KEM 用户链、ML-DSA 签名链和 SLH-DSA 签名链。
case_config kem pure-pq ML-DSA-44 ML-DSA-44 ML-KEM-512 1
case_run
assert_report_algorithm user ML-KEM-512
case_config dsa pure-pq ML-DSA-87 ML-DSA-87 ML-DSA-87 1
case_run
assert_report_algorithm user ML-DSA-87
case_config slh slh-dsa SLH-DSA-SHA2-256s SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f 1
case_run
assert_report_algorithm user SLH-DSA-SHA2-256f
case_pass '三类纯 PQ 链的根、中间和用户签名均通过'
