#!/usr/bin/env bash
# 部署 TLS 源码测试环境：源码 + 补丁版 Go + 预编译二进制 + 测试脚本
# 用法：sudo ./deploy.sh [安装目录] [--rebuild|--no-build] [--no-endpoints]
#   默认安装到 /opt/pqc-tls-test；--rebuild 用包内 Go 从源码重编非 HQC 二进制；
#   部署完成后默认启动 8080/8181/8082/8099/8111 固定端点，供客户端侧用例访问
set -euo pipefail
umask 077
BUNDLE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PREFIX=${1:-/opt/pqc-tls-test}
USE_PREBUILT=0
START_ENDPOINTS=1
for a in "$@"; do
    case "$a" in
        --no-build)     USE_PREBUILT=1 ;;
        --rebuild)      USE_PREBUILT=0 ;;
        --no-endpoints) START_ENDPOINTS=0 ;;
    esac
done
[[ $(uname -s) = Linux && $(uname -m) = x86_64 ]] || { echo "仅支持 Linux x86_64（Ubuntu 20.04）" >&2; exit 1; }
case "$PREFIX" in /*) ;; *) echo "安装路径必须是绝对路径" >&2; exit 1 ;; esac
[ -e "$PREFIX" ] && { echo "安装目录已存在，拒绝覆盖：$PREFIX" >&2; exit 1; }

echo "[1/6] 校验包完整性"
(cd "$BUNDLE" && sha256sum -c SHA256SUMS >/dev/null)

echo "[2/6] 复制源码与测试脚本到 $PREFIX"
mkdir -p "$PREFIX/.build"
cp -a "$BUNDLE/src/tls-hybrid" "$BUNDLE/src/tools" "$BUNDLE/src/tls-test-scripts" "$PREFIX/"
cp -a "$BUNDLE/run-tests.sh" "$PREFIX/"
[ -f "$BUNDLE/README.md" ] && cp -a "$BUNDLE/README.md" "$PREFIX/"

echo "[3/6] 安装可执行程序与测试证书"
cp -a "$BUNDLE"/bin/server "$BUNDLE"/bin/client "$BUNDLE"/bin/e2e "$BUNDLE"/bin/tlsbench "$PREFIX/.build/" 2>/dev/null || true
cp -a "$BUNDLE"/bin/server_hqc "$BUNDLE"/bin/client_hqc "$BUNDLE"/bin/e2e_hqc "$BUNDLE"/bin/tlsbench_hqc "$PREFIX/.build/" 2>/dev/null || true
cp -a "$BUNDLE/bin/certs" "$PREFIX/.build/certs"
[ -d "$BUNDLE/bin/liboqs" ] && cp -a "$BUNDLE/bin/liboqs" "$PREFIX/.build/liboqs"
find "$PREFIX/.build/certs" -name '*.key' -exec chmod 600 {} +

echo "[4/6] 安装补丁版 Go 工具链"
mkdir -p "$PREFIX/.build/go"
tar -xzf "$BUNDLE/bin/go-min.tgz" -C "$PREFIX/.build/go"

echo "[5/6] 安装 go_kemtls 工具链并构建异构认证 server/client"
mkdir -p "$PREFIX/.build/go-kemtls" "$PREFIX/.build/extracted"
tar -xzf "$BUNDLE/bin/go-kemtls-min.tgz" -C "$PREFIX/.build/go-kemtls"
cp -a "$BUNDLE/src/kemtls/cloudflare_server" "$BUNDLE/src/kemtls/cloudflare_client" "$PREFIX/.build/extracted/"
KGOROOT="$PREFIX/.build/go-kemtls"
KGOCACHE="$PREFIX/.build/gocache-kemtls"
( cd "$PREFIX/.build/extracted/cloudflare_server" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o server-linux . )
( cd "$PREFIX/.build/extracted/cloudflare_client" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o client-linux . )

# KEM 认证变体：ProtocolType 由 AKEX(11) 改为 KemCert_KEX(21)，供 TLS-1-13 四模式矩阵
echo "构建 KEM 认证变体（Sig-Sig / Sig-KEM / KEM-Sig / KEM-KEM）"
cp -a "$PREFIX/.build/extracted/cloudflare_server" "$PREFIX/.build/extracted/cloudflare_server_kem"
cp -a "$PREFIX/.build/extracted/cloudflare_client" "$PREFIX/.build/extracted/cloudflare_client_kem"
sed -i 's/tls\.QuantumSupportAKEX/tls.QuantumSupportKemCert_KEX/' \
    "$PREFIX/.build/extracted/cloudflare_server_kem/server.go" \
    "$PREFIX/.build/extracted/cloudflare_client_kem/client.go"
( cd "$PREFIX/.build/extracted/cloudflare_server_kem" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o server-kem-linux . )
( cd "$PREFIX/.build/extracted/cloudflare_client_kem" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o client-kem-linux . )

# 1.5-RTT 流程优化变体：ProtocolType 由 AKEX(11) 改为 SignCert_ServerKeyGen(13)
echo "构建 ServerKeyGen 1.5-RTT 变体"
cp -a "$PREFIX/.build/extracted/cloudflare_server" "$PREFIX/.build/extracted/cloudflare_server_keygen"
cp -a "$PREFIX/.build/extracted/cloudflare_client" "$PREFIX/.build/extracted/cloudflare_client_keygen"
sed -i 's/tls\.QuantumSupportAKEX/tls.QuantumSupportSignCert_ServerKeyGen/' \
    "$PREFIX/.build/extracted/cloudflare_server_keygen/server.go" \
    "$PREFIX/.build/extracted/cloudflare_client_keygen/client.go"
( cd "$PREFIX/.build/extracted/cloudflare_server_keygen" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o server-keygen-linux . )
( cd "$PREFIX/.build/extracted/cloudflare_client_keygen" && GOROOT="$KGOROOT" GOCACHE="$KGOCACHE" GOFLAGS="-buildvcs=false" "$KGOROOT/bin/go" build -o client-keygen-linux . )

if [ "$USE_PREBUILT" = 0 ] && command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    echo "[6/6] 在目标机重编二进制（非 HQC 静态；HQC 用私有 liboqs）"
    export GOROOT="$PREFIX/.build/go"
    export PATH="$GOROOT/bin:$PATH"
    export GOCACHE="$PREFIX/.build/gocache"
    export GOFLAGS="-buildvcs=false"
    GO="$GOROOT/bin/go"
    ( cd "$PREFIX/tls-hybrid/server"      && CGO_ENABLED=0 "$GO" build -o ../../.build/server . )
    ( cd "$PREFIX/tls-hybrid/client"      && CGO_ENABLED=0 "$GO" build -o ../../.build/client . )
    ( cd "$PREFIX/tls-hybrid/e2e"         && CGO_ENABLED=0 "$GO" build -o ../../.build/e2e . )
    ( cd "$PREFIX/tools/tlsbench"         && CGO_ENABLED=0 "$GO" build -o ../../.build/tlsbench . )
    if [ -f "$PREFIX/.build/liboqs/lib/liboqs.a" ]; then
        export CGO_ENABLED=1
        export CGO_CFLAGS="-I$PREFIX/.build/liboqs/include"
        export CGO_LDFLAGS="-L$PREFIX/.build/liboqs/lib -loqs"
        ( cd "$PREFIX/tls-hybrid/server"  && "$GO" build -tags pq_hqc -o ../../.build/server_hqc . )
        ( cd "$PREFIX/tls-hybrid/client"  && "$GO" build -tags pq_hqc -o ../../.build/client_hqc . )
        ( cd "$PREFIX/tls-hybrid/e2e"     && "$GO" build -tags pq_hqc -o ../../.build/e2e_hqc . )
        ( cd "$PREFIX/tools/tlsbench"     && "$GO" build -tags pq_hqc -o ../../.build/tlsbench_hqc . )
    else
        echo "未找到私有 liboqs，HQC 版本保留预编译二进制"
    fi
else
    echo "[6/6] 使用预编译二进制（未在目标机重编）"
fi

chmod +x "$PREFIX"/tls-test-scripts/*.sh "$PREFIX"/tls-test-scripts/server-runtime/*.sh 2>/dev/null || true

if [ "$START_ENDPOINTS" = 1 ]; then
    echo "启动固定端点（8080/8181/8082/8099/8111）"
    bash "$PREFIX/tls-test-scripts/server-endpoints.sh" start || true
fi

echo "部署完成：$PREFIX"
echo "服务端端点：bash $PREFIX/tls-test-scripts/server-endpoints.sh status"
echo "客户端（本机）执行：sudo bash tls-test-scripts/run_all.sh"
echo "服务端侧用例：bash $PREFIX/tls-test-scripts/run-server-side.sh"
