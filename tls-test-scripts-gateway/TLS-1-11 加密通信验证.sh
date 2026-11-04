#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
gw_init "TLS-1-11" "加密通信验证"
gw_serve enc '["SM2MLKEM512"]'
capture_start tls-1-11-appdata "$GW_PORT"
run_sh 1 "probe 发起 HTTPS GET（抓包）" "$(gw_probe_cmd SM2MLKEM512)"
expect_text 1 "HTTP 200 且证书校验通过" "http_status= 200"
expect_text 1 "应用数据为密文传输，响应体正常" "Directory listing|<!DOCTYPE|<html"
capture_stop
run_sh 2 "解析抓包中的握手与记录" "python3 tools/tls_hello_check.py '$CASE_DIR/captures/tls-1-11-appdata.pcap' --expect SM2MLKEM512"
server_stop
skip_step 3 "tshark 查看 Application Data 明文/密文" "未安装 tshark；以 pcap 与 probe 响应体作为证据"
finish_case
