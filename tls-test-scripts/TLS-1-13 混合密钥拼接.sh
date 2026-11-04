#!/usr/bin/env bash
# TLS-1-13 异构 Sig/KEM 认证模式验证
# 构建与准备（go_kemtls 工具链、cloudflare server/client）由 deploy.sh 完成；
# 本用例只跑运行部分：启动服务端、客户端建连、日志核对、缺私钥负向抽检。
# 服务端侧用例：在服务端本机执行（启动 cloudflare 服务端并读取其日志、移走抗量子私钥）
export MODE=server CAPTURE_IFACE=lo
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-1-13" "混合密钥拼接（异构 Sig/KEM 认证）"

KEMTLS="$PROJECT_ROOT/.build/extracted"

if [ ! -x "$KEMTLS/cloudflare_server/server-linux" ] || [ ! -x "$KEMTLS/cloudflare_client/client-linux" ]; then
    skip_step 1 "运行异构 Sig/KEM 认证" "部署阶段未准备 .build/extracted（请重新执行 deploy.sh）"
    finish_case
    exit 0
fi

# 1) 正向：Sig 模式 100 次建连
capture_start tls-1-13-kemtls 8443
server_start kemtls "cd '$KEMTLS/cloudflare_server' && exec ./server-linux"
wait_port 8443 10 || true
run_sh 1 "客户端 100 次建连（Sig 模式）" "cd '$KEMTLS/cloudflare_client' && ./client-linux"
expect_text 1 "客户端完成 100 次握手" "总次数: 100"
expect_text 1 "握手成功" "handshake OK"
capture_stop
run_sh 2 "核对服务端抗量子签名与双向认证日志" "grep -E '抗量子私钥已加载|签名成功|Client cert subject' '$CASE_DIR/server-kemtls.log'"
expect_text 2 "服务端加载抗量子私钥并校验客户端证书" "抗量子私钥已加载"
server_stop

# 2) 负向：移走服务端抗量子私钥，握手必须失败
if [ "${RUN_KEY_TEST:-1}" = 1 ]; then
    key="$KEMTLS/cloudflare_server/pqcerts/end-entity-pq-key.bin"
    if [ -f "$key" ]; then
        mv "$key" "$key.bak"
        server_start kemtls_nokey "cd '$KEMTLS/cloudflare_server' && exec ./server-linux"
        wait_port 8443 10 || true
        record_cmd "移走抗量子私钥后重跑客户端" "mv pqcerts/end-entity-pq-key.bin{,.bak}; ./client-linux"
        ( cd "$KEMTLS/cloudflare_client" && ./client-linux ) > "$CASE_DIR/step-3.out" 2>&1
        rc=$?
        TOTAL=$((TOTAL+1))
        if [ "$rc" -ne 0 ] && grep -Eq 'handshake|tls: |EOF|remote error|certificate|签名' "$CASE_DIR/step-3.out"; then
            printf 'PASS 步骤 3：移走抗量子私钥后握手失败（退出码 %s）\n' "$rc" >> "$CASE_DIR/summary.txt"
            PASS=$((PASS+1)); log "步骤 3 通过：缺少抗量子私钥时握手失败"
        else
            printf 'FAIL 步骤 3：移走抗量子私钥后仍握手成功——抗量子签名未参与认证\n' >> "$CASE_DIR/summary.txt"
            FAIL=$((FAIL+1)); warn "步骤 3 失败：缺少抗量子私钥仍握手成功（见 analysis/finding）"
            {
                echo "发现时间: $(date '+%F %T')"
                echo "现象: 移走 cloudflare_server/pqcerts/end-entity-pq-key.bin 后，客户端握手仍成功。"
                echo "影响: 抗量子签名未真正参与服务端身份认证，缺少私钥不会导致握手失败。"
                echo "证据: step-3.out、server-kemtls_nokey.log。"
            } > "$CASE_DIR/analysis/finding-缺少抗量子私钥仍握手成功.txt"
        fi
        server_stop
        mv "$key.bak" "$key"
    else
        skip_step 3 "移走抗量子私钥后握手应失败" "未找到 $key"
    fi
else
    skip_step 3 "移走抗量子私钥后握手应失败" "RUN_KEY_TEST=0，已关闭该抽检"
fi

# 3) 四模式矩阵：Sig-Sig / Sig-KEM / KEM-Sig / KEM-KEM
#    四种组合由服务端/客户端两侧的 ProtocolType 决定，deploy.sh 预编译了 KEM 变体：
#      cloudflare_server/server-linux        (SignCert, AKEX=11)
#      cloudflare_server_kem/server-kem-linux (KemCert, 21)
#      cloudflare_client/client-linux        (SignCert, 11)
#      cloudflare_client_kem/client-kem-linux (KemCert, 21)
if [ "${RUN_MODE_MATRIX:-1}" = 1 ] \
   && [ -x "$KEMTLS/cloudflare_server_kem/server-kem-linux" ] \
   && [ -x "$KEMTLS/cloudflare_client_kem/client-kem-linux" ]; then
    matrix_step() {
        local n=$1 name=$2 sdir=$3 sbin=$4 cdir=$5 cbin=$6 marker=$7
        capture_start "tls-1-13-$name" 8443
        server_start "kemtls-$name" "cd '$KEMTLS/$sdir' && exec ./$sbin"
        wait_port 8443 10 || true
        run_sh "$n" "客户端 100 次建连（$name）" "cd '$KEMTLS/$cdir' && ./$cbin"
        expect_text "$n" "完成 100 次握手（$name）" "总次数: 100"
        expect_text "$n" "握手成功（$name）" "handshake OK"
        capture_stop
        run_sh "$((n+1))" "核对服务端认证方式日志（$name）" \
            "grep -E '抗量子私钥已加载|抗量子私钥签名成功' '$CASE_DIR/server-kemtls-$name.log' | head -5"
        expect_text "$((n+1))" "服务端认证方式符合预期（$name）" "$marker"
        server_stop
    }

    matrix_step 4  sig-sig  cloudflare_server      server-linux      cloudflare_client      client-linux      "抗量子私钥签名成功"
    matrix_step 6  sig-kem  cloudflare_server      server-linux      cloudflare_client_kem  client-kem-linux  "抗量子私钥签名成功"
    matrix_step 8  kem-sig  cloudflare_server_kem  server-kem-linux  cloudflare_client      client-linux      "pq-key-KEM.bin"
    matrix_step 10 kem-kem  cloudflare_server_kem  server-kem-linux  cloudflare_client_kem  client-kem-linux  "pq-key-KEM.bin"
else
    skip_step 4 "四模式矩阵（Sig-Sig/Sig-KEM/KEM-Sig/KEM-KEM）" \
        "需 deploy.sh 预编译 KEM 变体（cloudflare_server_kem / cloudflare_client_kem），或 RUN_MODE_MATRIX=0"
fi
finish_case
