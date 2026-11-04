#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-10" "证书有效性验证"
gw_serve v '["SM2MLKEM512"]'
run_sh 1 "有效证书 + 对应 CA（应通过）" "$(gw_probe_cmd SM2MLKEM512)"
expect_text 1 "证书校验通过并完成 HTTP 请求" "certificate_verified=true"
expect_text 1 "HTTP 200" "http_status= 200"
run_sh_fail 2 "有效证书 + 无关 CA（应失败）" "$GW_BIN probe -url https://127.0.0.1:$GW_PORT/ -server-name $GW_SERVER_NAME -ca '$GW_PKG_DIR/certs/87/root.crt' -auth sm2-mldsa-44 -kex SM2MLKEM512 -cert '$GW_PKG_DIR/demo/44/client.crt' -key '$GW_PKG_DIR/demo/44/client.key' -pq-key '$GW_PKG_DIR/demo/44/client.pq.key' -client-ca '$GW_PKG_DIR/certs/44/root.crt'"
expect_text 2 "无关 CA 被拒绝（输出校验类错误）" "mismatch|certificate|authority|verify|fail"
skip_step 3 "过期证书场景" "交付包 demo 证书均在有效期；无过期证书材料（证书工具未提供生成过期证书的配置）"
server_stop
finish_case
