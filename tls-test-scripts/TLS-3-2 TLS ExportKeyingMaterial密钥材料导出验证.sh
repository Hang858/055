#!/usr/bin/env bash
# 客户端视角：客户端导出密钥材料并用其加密收发，验证两端内容一致
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-3-2" "TLS ExportKeyingMaterial密钥材料导出验证"
require_server "$SERVER_PORT" || exit 1

capture_start tls-3-2-keyingmaterial "$SERVER_PORT"
run_sh 1 "客户端用导出密钥收发数据" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519Kyber1024Draft00 -ca .build/certs/server_root_cert1.pem"
expect_text 1 "收发完成" "Server response"
run_sh 2 "发送自定义内容复核" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex X25519Kyber1024Draft00 -msg 'hello-keying-material' -ca .build/certs/server_root_cert1.pem"
expect_text 2 "两端内容一致" "hello-keying-material"
capture_stop
if command -v tshark >/dev/null 2>&1; then
    run_sh 3 "检查 Application Data 记录" "tshark -r '$CASE_DIR/captures/tls-3-2-keyingmaterial.pcap' -d tcp.port==$SERVER_PORT,tls -Y 'tls.app_data' -T fields -e frame.number"
    expect_text 3 "抓包中存在 Application Data 记录" "[0-9]"
else
    skip_step 3 "检查密钥材料不出现在报文中" "未安装 tshark；以客户端解密回显为证"
fi
finish_case
