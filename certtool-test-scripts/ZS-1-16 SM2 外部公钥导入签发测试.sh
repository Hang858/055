#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-16
# 步骤：从独立 SM2 公钥文件导入用户公钥，由本地 SM2 根证书签发。
case_config import-sm2 sm2 SM2 SM2 SM2 0
case_set_import "$CERTTOOL_DATA_DIR/sm2_public_key.txt"
case_run
assert_pem root.crt CERTIFICATE
assert_pem user.crt CERTIFICATE
assert_pem user.pub PUBLIC\ KEY
assert_absent user.key
openssl x509 -in "$OUT_DIR/user.crt" -noout -pubkey > "$CASE_DIR/user-from-cert.pub"
openssl pkey -pubin -in "$OUT_DIR/user.pub" -pubout > "$CASE_DIR/user-normalized.pub"
cmp "$CASE_DIR/user-from-cert.pub" "$CASE_DIR/user-normalized.pub"
case_pass '用户公钥与外部文件相符，私钥未输出，证书验签通过'
