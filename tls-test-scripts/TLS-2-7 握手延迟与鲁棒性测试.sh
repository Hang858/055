#!/usr/bin/env bash
# 客户端视角：本机注入 netem 时延压测远端 tlsbench 端点；再经中间盒代理跑三种策略，
# 最后按 ClientHello 记录长度判定是否超过 1455 字节（分包）。
source "$(dirname "$0")/lib.sh"
ensure_capture_env
init_case "TLS-2-7" "握手延迟与鲁棒性测试"
require_server "$SERVER_PORT_BENCH" "tlsbench 端点" || exit 1

IFACE=${CAPTURE_IFACE:-eno2}
NETEM_ADDED=0
clear_netem() { [ "$NETEM_ADDED" = 1 ] && tc qdisc del dev "$IFACE" root 2>/dev/null; NETEM_ADDED=0; }
trap 'clear_netem; cleanup' EXIT

run_delay() {
    local n=$1 d=$2 kex=$3
    [ "$d" -gt 0 ] && NETEM_ADDED=1
    run_sh "$n" "注入单程时延 ${d}ms（RTT≈$((d*2))ms）并建立 ${NETEM_N} 次连接" \
        "tc qdisc del dev $IFACE root 2>/dev/null || true; [ $d -gt 0 ] && tc qdisc add dev $IFACE root netem delay ${d}ms; .build/tlsbench -mode client -addr $SERVER_HOST:$SERVER_PORT_BENCH -kex $kex -n ${NETEM_N} -c ${NETEM_C}"
    expect_text "$n" "全部成功" "成功 ${NETEM_N} / 失败 0"
    expect_text "$n" "输出平均耗时" "平均="
}

# ---------------- 1. 四档网络时延 ----------------
n=1
if [ "$(id -u)" -eq 0 ] && command -v tc >/dev/null 2>&1; then
    capture_start tls-2-7-classic "$SERVER_PORT_BENCH"
    for d in 0 2 25 100; do run_delay "$n" "$d" X25519; n=$((n+1)); done
    clear_netem
    capture_stop
    run_sh "$n" "清除 netem 并解析抓包" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-2-7-classic.pcap' $SERVER_PORT_BENCH --expect X25519"
    n=$((n+1))
else
    skip_step "$n" "netem 时延注入（四档）" "需要 root 且安装 iproute2；当前用户无法注入时延"
    n=$((n+1))
    capture_start tls-2-7-classic "$SERVER_PORT_BENCH"
    run_sh "$n" "无时延基线（${NETEM_N} 次连接）" ".build/tlsbench -mode client -addr $SERVER_HOST:$SERVER_PORT_BENCH -kex X25519 -n ${NETEM_N} -c ${NETEM_C}"
    expect_text "$n" "全部成功" "成功 ${NETEM_N} / 失败 0"
    expect_text "$n" "输出平均耗时" "平均="
    n=$((n+1))
    capture_stop
    run_sh "$n" "解析抓包" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-2-7-classic.pcap' $SERVER_PORT_BENCH --expect X25519"
    n=$((n+1))
fi

# ---------------- 2. 四方案 × 四档时延 ----------------
if [ "${NETEM_FULL:-0}" = 1 ] && [ "$(id -u)" -eq 0 ] && command -v tc >/dev/null 2>&1; then
    for cfg in "HybridKEX:X25519Kyber768Draft00" "HRR:DummyKex,X25519" "Our:SM2Kyber512Draft00"; do
        name=${cfg%%:*}; kex=${cfg##*:}
        for d in 0 2 25 100; do run_delay "$n" "$d" "$kex"; n=$((n+1)); done
        clear_netem
    done
elif [ "${NETEM_FULL:-0}" = 1 ]; then
    skip_step "$n" "四方案×四档时延对比" "需要 root 且安装 iproute2 才能注入四档时延"
    n=$((n+1))
else
    skip_step "$n" "四方案×四档时延对比" "NETEM_FULL=0，只跑 ClassicKEX 四档"
    n=$((n+1))
fi

# ---------------- 3. 中间盒三策略 ----------------
MB_PORT=8100
MB_N=200
MB_C=10
MB_SCRIPT="$PROJECT_ROOT/tools/tls_middlebox.py"
if [ ! -f "$MB_SCRIPT" ]; then
    skip_step "$n" "中间盒鲁棒性（三策略）" "缺少 tools/tls_middlebox.py"
    n=$((n+1))
elif (exec 3<>"/dev/tcp/127.0.0.1/$MB_PORT") 2>/dev/null; then
    skip_step "$n" "中间盒鲁棒性（三策略）" "本机 $MB_PORT 已被占用"
    n=$((n+1))
else
    mb_step() {
        local num=$1 policy=$2 kex=$3 desc=$4 pattern=$5
        shift 5
        local tag="$policy-$kex"
        local stats="$CASE_DIR/middlebox-$tag.json" log="$CASE_DIR/middlebox-$tag.log"
        python3 "$MB_SCRIPT" --listen "127.0.0.1:$MB_PORT" \
            --upstream "$SERVER_HOST:$SERVER_PORT_BENCH" --policy "$policy" \
            --stats "$stats" "$@" >"$log" 2>&1 &
        local pid=$!
        sleep 1
        if [ "$policy" = size-drop ] && [ "$kex" = X25519 ]; then
            run_sh "$num" "$desc" ".build/tlsbench -mode client -addr 127.0.0.1:$MB_PORT -kex $kex -n $MB_N -c $MB_C -timeout 3s"
        elif [ "$policy" = size-drop+loss ]; then
            run_sh "$num" "$desc" ".build/tlsbench -mode client -addr 127.0.0.1:$MB_PORT -kex $kex -n $MB_N -c $MB_C -timeout 3s"
        else
            run_sh_fail "$num" "$desc" ".build/tlsbench -mode client -addr 127.0.0.1:$MB_PORT -kex $kex -n $MB_N -c $MB_C -timeout 3s"
        fi
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        expect_text "$num" "$desc（客户端统计）" "$pattern"
        run_sh "$((num+1))" "读取中间盒统计（$policy）" "cat '$stats'"
        expect_text "$((num+1))" "代理转发 ${MB_N} 条连接" "\"accepted\": $MB_N"
        run_sh "$((num+2))" "校验 $MB_N 条连接均有结果" "grep -o '成功 [0-9]* / 失败 [0-9]*' '$CASE_DIR/step-$num.out' | awk '{print \$2+\$5}'"
        expect_text "$((num+2))" "成功+失败 = $MB_N" "^$MB_N$"
    }

    mb_step "$n" size-drop X25519 \
        "size-drop 1455：小报文（X25519）应全部成功" "成功 $MB_N / 失败 0"
    n=$((n+3))
    mb_step "$n" size-drop X25519Kyber1024Draft00 \
        "size-drop 1455：ClientHello 超限（Kyber-1024）应出现失败" "失败 [1-9][0-9]*"
    n=$((n+3))
    mb_step "$n" first-segment-only X25519 \
        "first-segment-only：只转首段，握手应失败" "失败 [1-9][0-9]*"
    n=$((n+3))
    mb_step "$n" size-drop+loss X25519Kyber512Draft00 \
        "size-drop+loss 1%（Kyber-512）记录成功率/失败数" "成功 [0-9]+ / 失败 [0-9]+"
    n=$((n+3))
fi

# ---------------- 4. ClientHello 是否分包（1455 字节判据） ----------------
for row in "X25519Kyber512Draft00:≤1455:，不分包）" "X25519Kyber1024Draft00:>1455:，分包）"; do
    kex=${row%%:*}; rest=${row#*:}; mark=${rest%%:*}; label=${rest##*:}
    tag=$(echo "$kex" | tr 'A-Z' 'a-z')
    capture_start "tls-2-7-frag-$tag" "$SERVER_PORT"
    run_sh "$n" "客户端握手（$kex），抓取 ClientHello" ".build/client -addr $SERVER_HOST:$SERVER_PORT -kex $kex -ca .build/certs/server_root_cert1.pem"
    expect_text "$n" "客户端完成握手" "Used|Server response"
    capture_stop
    n=$((n+1))
    run_sh "$n" "解析 ClientHello 记录长度（$kex）" "bash tools/tshark_check.sh '$CASE_DIR/captures/tls-2-7-frag-$tag.pcap' $SERVER_PORT"
    expect_text "$n" "记录长度 $mark（$label）" "$mark"
    expect_text "$n" "判定为$label" "$label"
    n=$((n+1))
done

finish_case
