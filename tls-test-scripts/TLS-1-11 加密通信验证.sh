#!/usr/bin/env bash
# 客户端视角：客户端发送加密应用数据，解密并打印服务端回显
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-11" "加密通信验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-11-appdata "$SERVER_PORT"
run_sh 1 "发送文本数据" ".build/client -addr $SERVER_HOST:$SERVER_PORT -ca .build/certs/server_root_cert1.pem -msg '测试文本数据 test text 123'"
expect_text 1 "服务端回显与发送一致的原文" "测试文本数据 test text 123"
run_sh 2 "发送二进制数据" ".build/client -addr $SERVER_HOST:$SERVER_PORT -ca .build/certs/server_root_cert1.pem -msg-hex 00ff1020304050607080"
expect_text 2 "服务端回显二进制内容（十六进制）" "00ff1020304050607080|00FF1020304050607080"
capture_stop
if command -v tshark >/dev/null 2>&1; then
    run_sh 3 "检查 Application Data 记录" "tshark -r '$CASE_DIR/captures/tls-1-11-appdata.pcap' -d tcp.port==$SERVER_PORT,tls -Y 'tls.app_data' -T fields -e frame.number"
    expect_text 3 "抓包中存在 Application Data 记录" "[0-9]"
else
    skip_step 3 "检查 Application Data 记录" "未安装 tshark；以客户端解密回显作为证据"
fi
finish_case
