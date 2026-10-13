#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-3-1
# 步骤：依次覆盖 RSA 混合、SM2 混合、KEM 用户链、ML-DSA 链、SLH-DSA 链及两类外部公钥导入。
for kind in rsa-hybrid sm2-hybrid kem dsa slh import-sm2 import-pq; do
    case "$kind" in
        rsa-hybrid|sm2-hybrid) case_config "$kind" "$kind" ML-DSA-44 ML-DSA-65 ML-KEM-512 1;;
        kem) case_config "$kind" pure-pq ML-DSA-87 ML-DSA-87 ML-KEM-1024 1;;
        dsa) case_config "$kind" pure-pq ML-DSA-44 ML-DSA-65 ML-DSA-87 1;;
        slh) case_config "$kind" slh-dsa SLH-DSA-SHA2-256s SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f 1;;
        import-sm2) case_config "$kind" sm2 SM2 SM2 SM2 0; case_set_import "$CERTTOOL_DATA_DIR/sm2_public_key.txt";;
        import-pq) case_config "$kind" pure-pq ML-DSA-44 ML-DSA-44 ML-DSA-44 0; case_set_import "$CERTTOOL_DATA_DIR/mldsa44.pub";;
    esac
    case_run
    assert_pem user.crt CERTIFICATE
done
case_pass '七种组合全部生成且验签通过'
