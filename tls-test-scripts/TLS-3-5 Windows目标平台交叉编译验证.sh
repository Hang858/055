#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-3-5" "Windows目标平台交叉编译验证"

GO="$PROJECT_ROOT/$GO_BIN"
run_sh 1 "交叉编译 Windows 服务端" "mkdir -p dist/tls/server; cd tls-hybrid/server && GOCACHE='$PROJECT_ROOT/.build/gocache-tls' GOFLAGS=-buildvcs=false GOOS=windows GOARCH=amd64 '$GO' build -o ../../dist/tls/server/windows_server.exe ."
run_sh 2 "交叉编译 Windows 客户端" "mkdir -p dist/tls/client; cd tls-hybrid/client && GOCACHE='$PROJECT_ROOT/.build/gocache-tls' GOFLAGS=-buildvcs=false GOOS=windows GOARCH=amd64 '$GO' build -o ../../dist/tls/client/windows_client.exe ."
run_sh 3 "检查产物类型（应为 PE32+）" "file dist/tls/server/windows_server.exe dist/tls/client/windows_client.exe"
expect_text 3 "Windows 可执行文件" "PE32\\+ executable"
skip_step 4 "Windows 实机运行" "本条仅验证交叉编译，运行需 Windows 机器"
finish_case
