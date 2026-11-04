#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-3-3" "X25519传统密钥交换回退验证"
# 交付包配置校验：kex 只接受抗量子组，纯 X25519 被拒绝
CFG="$CASE_DIR/gateway-x25519.json"
cat > "$CFG" <<JSON
{
  "listen": "127.0.0.1:$GW_PORT",
  "upstream": "http://127.0.0.1:$GW_UPSTREAM_PORT",
  "auth": "sm2-mldsa-44",
  "cert": "$GW_PKG_DIR/certs/44/server.crt",
  "key": "$GW_PKG_DIR/certs/44/server.key",
  "pq_key": "$GW_PKG_DIR/certs/44/server.pq.key",
  "root_ca": "$GW_PKG_DIR/certs/44/root.crt",
  "intermediates": [],
  "server_name": "$GW_SERVER_NAME",
  "kex": ["X25519"],
  "client_ca": "$GW_PKG_DIR/certs/44/root.crt"
}
JSON
run_sh 1 "以纯 X25519 组启动交付包服务端（预期应支持回退）" "cd '$GW_PKG_DIR' && '$GW_BIN' check -config '$CFG'"
if [ "$FAIL" -gt 0 ]; then
    {
        echo "发现时间: $(date '+%F %T')"
        echo "现象: 交付包 pqc-gateway 配置校验报 unsupported PQ group \"X25519\"，不支持纯 X25519 组。"
        echo "影响: TLS-3-3（X25519 传统密钥交换回退验证）在交付包上无法通过；若交付范围包含传统回退能力，属于功能缺口。"
        echo "证据: 本目录 step-1.out、commands.log。"
    } > "$CASE_DIR/analysis/finding-不支持纯X25519回退.txt"
fi
finish_case
