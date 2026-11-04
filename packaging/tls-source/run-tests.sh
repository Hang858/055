#!/usr/bin/env bash
# 客户端侧入口：检查服务端端点可达后，执行全部 TLS 用例（客户端 22 条 + 服务端侧 2 条）
# 用法：sudo bash run-tests.sh            （本机客户端；sudo 用于抓包）
#       bash run-tests.sh                 （无抓包权限时抓包与解析步骤记 SKIP）
set -uo pipefail
PREFIX=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$PREFIX"
command -v python3 >/dev/null || { echo "需要 python3" >&2; exit 1; }
[ -x .build/client ] || { echo "未找到 .build/client，请先运行 deploy.sh 或构建客户端" >&2; exit 1; }

# shellcheck source=/dev/null
source tls-test-scripts/config.env
missing=0
for p in "$SERVER_PORT" "$SERVER_PORT_HQC" "$SERVER_PORT_POLICY" "$SERVER_PORT_BENCH" "$SERVER_PORT_EXPIRED"; do
    if timeout 2 bash -c "echo > /dev/tcp/$SERVER_HOST/$p" 2>/dev/null; then
        echo "端点可达：$SERVER_HOST:$p"
    else
        echo "端点不可达：$SERVER_HOST:$p（在服务端执行 tls-test-scripts/server-endpoints.sh start）" >&2
        missing=1
    fi
done
[ "$missing" = 0 ] || { echo "先启动服务端端点再执行测试" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "提示：非 root 运行，抓包与解析步骤将记 SKIP；建议 sudo bash run-tests.sh" >&2

exec bash tls-test-scripts/run_all.sh
