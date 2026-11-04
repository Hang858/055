#!/usr/bin/env bash
# 客户端视角：本机向服务端端点发送异常/低版本 ClientHello
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-8" "异常协议版本处理"
require_server "$SERVER_PORT" || exit 1

capture_start tls-1-8-abnormal "$SERVER_PORT"
run_sh_fail 1 "用 TLS 1.2 发起连接（应被拒绝）" "openssl s_client -connect $SERVER_HOST:$SERVER_PORT -tls1_2 -brief </dev/null"
expect_text 1 "拒绝原因是 protocol_version 告警" "alert protocol version|alert number 70"
run_sh 2 "构造畸形版本号的 ClientHello（应返回 protocol_version 告警）" "python3 tools/tls_abnormal_hello.py --addr $SERVER_HOST:$SERVER_PORT --mode bad-version"
expect_text 2 "服务端返回 protocol_version 告警" "desc=70|protocol_version"
run_sh 3 "构造无共同组的 ClientHello（应返回 handshake_failure 告警）" "python3 tools/tls_abnormal_hello.py --addr $SERVER_HOST:$SERVER_PORT --mode no-common-group"
expect_text 3 "服务端返回 handshake_failure 告警" "desc=40|handshake_failure"
capture_stop
if command -v tshark >/dev/null 2>&1; then
    run_sh 4 "用 tshark 检查 Alert 记录" "tshark -r '$CASE_DIR/captures/tls-1-8-abnormal.pcap' -d tcp.port==$SERVER_PORT,tls -Y 'tls.alert_message' -T fields -e tls.alert_message.level -e tls.alert_message.desc"
    expect_text 4 "抓包中存在 protocol_version 告警（desc=70）" "^2[[:space:]]+70$"
    expect_text 4 "抓包中存在 handshake_failure 告警（desc=40）" "^2[[:space:]]+40$"
else
    skip_step 4 "用 tshark 检查 Alert 记录" "未安装 tshark（TLS 抓包解析依赖 tshark）"
    expect_text 4 "抓包中存在 ClientHello" "ClientHello"
fi
finish_case
