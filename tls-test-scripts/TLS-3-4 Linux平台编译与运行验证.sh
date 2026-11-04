#!/usr/bin/env bash
# 本机编译 Linux 产物并回环运行（编译/运行验证，不依赖远端端点）
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-3-4" "Linux平台编译与运行验证"

GO="$PROJECT_ROOT/$GO_BIN"
run_sh 1 "编译 Linux 服务端与客户端" "mkdir -p dist/tls/server dist/tls/client; cd tls-hybrid/server && GOCACHE='$PROJECT_ROOT/.build/gocache-tls' GOFLAGS=-buildvcs=false '$GO' build -o ../../dist/tls/server/linux_server . && cd ../client && GOCACHE='$PROJECT_ROOT/.build/gocache-tls' GOFLAGS=-buildvcs=false '$GO' build -o ../../dist/tls/client/linux_client . && cd '$PROJECT_ROOT' && file dist/tls/server/linux_server dist/tls/client/linux_client"
expect_text 1 "产物为 Linux ELF" "ELF 64-bit"

CAPTURE_REMOTE=0 capture_start tls-3-4-linux 8080 lo
local_server_start linux_server "dist/tls/server/linux_server -addr 127.0.0.1:8080 -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem -kex X25519Kyber1024Draft00"
wait_local_port 8080 || true
run_sh 2 "用 dist 产物完成握手" "dist/tls/client/linux_client -addr 127.0.0.1:8080 -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 2 "客户端完成 256 比特档握手" "Used X25519Kyber1024Draft00"
capture_stop
server_stop
run_sh 3 "解析抓包（0xfe36）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-3-4-linux.pcap' 8080 --expect X25519Kyber1024Draft00"
finish_case
