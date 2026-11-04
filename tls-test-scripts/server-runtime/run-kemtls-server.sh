#!/usr/bin/env bash
# 启动 TLS-1-13 使用的异构 Sig/KEM 认证服务端（已修复验签缺陷）。
# 前置：go_kemtls 已解压并编译为 .build/extracted/cloudflare_server/server-linux
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
SRV=${KEMTLS_SERVER:-$ROOT/.build/extracted/cloudflare_server/server-linux}
[ -x "$SRV" ] || { echo "未找到 $SRV（先解压 go_1.25.1_PQTLS.zip 并用 patched 工具链编译）" >&2; exit 1; }
cd "$(dirname "$SRV")"
exec ./server-linux
