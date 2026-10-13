#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-1-10
# 步骤：生成 RSA 混合链并解析根、中间、终端证书基础字段。
case_config fields rsa-hybrid ML-DSA-44 ML-DSA-65 ML-KEM-512 1
case_run
for name in root inter1 user; do
    openssl x509 -in "$OUT_DIR/$name.crt" -noout -text > "$CASE_DIR/$name.x509.txt"
    for field in 'Version: 3' 'Serial Number' 'Issuer:' 'Subject:' 'Not Before:' 'Not After :' 'Basic Constraints' 'Key Usage'; do
        grep -Fq "$field" "$CASE_DIR/$name.x509.txt"
    done
done
grep -Fq 'CA:TRUE' "$CASE_DIR/root.x509.txt"
grep -Fq 'CA:TRUE' "$CASE_DIR/inter1.x509.txt"
grep -Fq 'CA:FALSE' "$CASE_DIR/user.x509.txt"
case_pass '版本、序列号、名称、有效期、CA 和 Key Usage 字段符合预期'
