#!/usr/bin/env bash
# 服务端侧：在服务端本机执行 TLS-2-5（服务端资源）与 TLS-1-13（异构认证）两条用例
set -uo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR/.."
for s in "$SCRIPT_DIR/TLS-2-5 服务器资源消耗.sh" "$SCRIPT_DIR/TLS-1-13 混合密钥拼接.sh"; do
    echo "=== 执行 $(basename "$s") ==="
    bash "$s" || true
done
echo "结果目录：${RUN_DIR:-${RESULTS_ROOT:-$SCRIPT_DIR/results}}"
