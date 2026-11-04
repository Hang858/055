#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-8" "异常协议版本处理"
gw_serve x '["SM2MLKEM512"]'
capture_start tls-1-8-abnormal "$GW_PORT"
run_sh_fail 1 "用 TLS 1.2 发起连接（应被拒绝）" "openssl s_client -connect 127.0.0.1:$GW_PORT -tls1_2 -brief </dev/null"
run_sh 2 "构造畸形版本号的 ClientHello（应返回 protocol_version 告警）" "python3 tools/tls_abnormal_hello.py --addr 127.0.0.1:$GW_PORT --mode bad-version"
expect_text 2 "返回 protocol_version 告警" "desc=70|protocol_version"
run_sh 3 "构造无共同组的 ClientHello（应返回 handshake_failure 告警）" "python3 tools/tls_abnormal_hello.py --addr 127.0.0.1:$GW_PORT --mode no-common-group"
expect_text 3 "返回 handshake_failure 告警" "desc=40|handshake_failure"
capture_stop; server_stop
skip_step 4 "tshark 检查 Alert 记录" "未安装 tshark；告警类型已由步骤 2/3 直接断言"
finish_case
