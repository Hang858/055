#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-2-7" "握手延迟与鲁棒性测试"
gw_serve netem '["SM2MLKEM512"]'
n=1
for d in 0 2 25 100; do
    run_sh "$n" "注入单程时延 ${d}ms（RTT≈$((d*2))ms），probe ${GW_NETEM_N:-20} 次" \
        "tc qdisc del dev lo root 2>/dev/null || true; [ $d -gt 0 ] && tc qdisc add dev lo root netem delay ${d}ms; s=\$(date +%s%N); ok=0; for i in \$(seq 1 ${GW_NETEM_N:-20}); do '$GW_BIN' probe -url https://127.0.0.1:$GW_PORT/ -server-name '$GW_SERVER_NAME' -ca '$GW_PKG_DIR/certs/44/root.crt' -auth sm2-mldsa-44 -kex SM2MLKEM512 -cert '$GW_PKG_DIR/demo/44/client.crt' -key '$GW_PKG_DIR/demo/44/client.key' -pq-key '$GW_PKG_DIR/demo/44/client.pq.key' -client-ca '$GW_PKG_DIR/certs/44/root.crt' >/dev/null 2>&1 && ok=\$((ok+1)); done; e=\$(date +%s%N); echo \"成功 \$ok/${GW_NETEM_N:-20}，总耗时 \$(( (e-s)/1000000 ))ms\""
    expect_text "$n" "全部 probe 成功" "成功 ${GW_NETEM_N:-20}/${GW_NETEM_N:-20}"
    n=$((n+1))
done
run_sh "$n" "清除 netem" "tc qdisc del dev lo root 2>/dev/null || true"
server_stop
skip_step "$n" "中间盒鲁棒性（尺寸限制丢弃/仅首段解析/丢包）" "缺少 tools/tls_middlebox.py"
finish_case
