#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-17
# 步骤：导入带算法标记的标准 ML-DSA-44 公钥，由本地根 CA 签发用户证书。
case_config import-pq pure-pq ML-DSA-44 ML-DSA-44 ML-DSA-44 0
case_set_import "$CERTTOOL_DATA_DIR/mldsa44.pub"
case_run
assert_pem root.crt CERTIFICATE
assert_pem user.crt CERTIFICATE
assert_absent user.key
cmp "$CERTTOOL_DATA_DIR/mldsa44.pub" "$OUT_DIR/user.pub"
assert_oid user.crt 2.16.840.1.101.3.4.3.17
case_pass '外部 ML-DSA 公钥原样写入证书，私钥未输出，签名链通过'
