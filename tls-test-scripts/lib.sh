# TLS 测试脚本公共函数
# 用法：脚本内 `source "$(dirname "$0")/lib.sh"`，随后 `init_case <用例标识> <用例名称>`。
# 结果目录：tls-test-scripts/results/run-<时间戳>/<用例标识>/
#   commands.log   每条指令与退出码
#   output.log     全部终端输出（含服务端/客户端日志）
#   captures/      抓包文件（.pcap）
#   analysis/      解析结果（tshark / tshark_check.sh 等）
#   summary.txt    步骤级通过/失败/跳过与最终结论

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
# shellcheck source=config.env
source "$SCRIPT_DIR/config.env"

MODE=${MODE:-client}
SERVER_HOST=${SERVER_HOST:-192.168.2.165}
SERVER_PORT=${SERVER_PORT:-8080}
SERVER_PORT_HQC=${SERVER_PORT_HQC:-8181}
SERVER_PORT_POLICY=${SERVER_PORT_POLICY:-8082}
SERVER_PORT_BENCH=${SERVER_PORT_BENCH:-8099}
SERVER_PORT_EXPIRED=${SERVER_PORT_EXPIRED:-8111}
RESULTS_ROOT=${RESULTS_ROOT:-$SCRIPT_DIR/results}
RUN_DIR=${RUN_DIR:-$RESULTS_ROOT/run-$(date +%Y%m%d-%H%M%S)-$$}
mkdir -p -- "$RUN_DIR"
export PROJECT_ROOT SCRIPT_DIR RESULTS_ROOT RUN_DIR MODE SERVER_HOST
export SERVER_PORT SERVER_PORT_HQC SERVER_PORT_POLICY SERVER_PORT_BENCH SERVER_PORT_EXPIRED

TOTAL=0; PASS=0; FAIL=0; SKIP=0
TRACE=${TRACE:-0}
[ "${TRACE_ALL:-0}" = 1 ] && set -x

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s][WARN] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# TRACE=1 时把实际执行的命令展开打印到终端，便于截图留证
trace_cmd() {
    [ "$TRACE" = 1 ] || return 0
    printf '\n$ %s\n' "$*"
}

# 是否已具备抓包权限（root 或免密 sudo）
_can_capture() {
    [ "$(id -u)" -eq 0 ] && return 0
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

# 抓包准备
# client 模式：客户端在真实网卡上抓包，必须有 root/CAP_NET_RAW；user+net namespace
#                会隔离网络，无法访问远端服务端，因此不做 namespace 回退，只降级跳过抓包。
# server 模式：服务端与客户端同机，沿用原逻辑（无权限时进 namespace）。
ensure_capture_env() {
    [ "${NO_CAPTURE:-0}" = 1 ] && return 0
    if _can_capture; then return 0; fi
    if [ "$MODE" = client ]; then
        warn "当前用户无抓包权限（需 root 或 CAP_NET_RAW）；抓包与解析步骤记为 SKIP，其余步骤照常执行"
        NO_CAPTURE=1; export NO_CAPTURE
        return 0
    fi
    [ "${IN_NETNS:-0}" = 1 ] && return 0
    if command -v unshare >/dev/null 2>&1 && command -v ip >/dev/null 2>&1 \
       && unshare -Urn --map-root-user true 2>/dev/null; then
        export IN_NETNS=1
        local self; self=$(readlink -f -- "$0")
        warn "当前用户无抓包权限，转入 user+net namespace 执行：$self"
        exec unshare -Urn --map-root-user bash -c \
            'ip link set lo up 2>/dev/null || true; export IN_NETNS=1; exec bash "$1" "${@:2}"' \
            -- "$self" "$@"
    fi
    warn "当前用户无抓包权限，且无法建立网络命名空间；抓包步骤将跳过"
    NO_CAPTURE=1; export NO_CAPTURE
}

init_case() {
    CASE_ID=$1
    CASE_NAME=$2
    CASE_DIR=$RUN_DIR/$CASE_ID
    mkdir -p -- "$CASE_DIR/captures" "$CASE_DIR/analysis"
    : > "$CASE_DIR/commands.log"
    : > "$CASE_DIR/output.log"
    printf '用例标识: %s\n用例名称: %s\n执行方式: %s\n服务端: %s\n开始时间: %s\n主机: %s\n\n' \
        "$CASE_ID" "$CASE_NAME" "$MODE" \
        "$([ "$MODE" = client ] && echo "$SERVER_HOST" || echo "本机")" \
        "$(date '+%F %T')" "$(hostname)" > "$CASE_DIR/summary.txt"
    log "开始 $CASE_ID $CASE_NAME"
    if [ "$TRACE" = 1 ]; then
        printf '\n================================================================\n'
        printf '用例 %s  %s\n' "$CASE_ID" "$CASE_NAME"
        printf '执行方式: %s    服务端: %s\n' "$MODE" \
            "$([ "$MODE" = client ] && echo "$SERVER_HOST" || echo "本机")"
        printf '================================================================\n'
    fi
    trap cleanup EXIT
}

# 记录一条指令的执行（输出同时写入 step 文件与 output.log）
# 用法：run_sh <序号> <说明> <shell 命令字符串>
run_sh() {
    local n=$1 desc=$2 cmd=$3 out="$CASE_DIR/step-$1.out"
    TOTAL=$((TOTAL+1))
    printf '\n===== 步骤 %s：%s =====\n' "$n" "$desc" >> "$CASE_DIR/commands.log"
    printf '$ %s\n' "$cmd" >> "$CASE_DIR/commands.log"
    printf '\n----- 步骤 %s：%s -----\n$ %s\n' "$n" "$desc" "$cmd" >> "$CASE_DIR/output.log"
    if [ "${NO_CAPTURE:-0}" = 1 ] && grep -Eq 'tcpdump|pcap_capture\.py|tls_hello_check\.py|tshark' <<<"$cmd"; then
        log "步骤 $n 跳过（无抓包权限）"
        printf 'SKIP 步骤 %s：%s（无抓包权限）\n' "$n" "$desc" >> "$CASE_DIR/summary.txt"
        SKIP=$((SKIP+1))
        echo "(skipped)" > "$out"
        return 0
    fi
    trace_cmd "$cmd"
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) 2>&1 | tee "$out" | tee -a "$CASE_DIR/output.log"
    local rc=${PIPESTATUS[0]}
    printf '退出码: %s\n' "$rc" >> "$CASE_DIR/commands.log"
    if [ "$rc" -eq 77 ]; then
        # 工具缺失（如未安装 tshark）：该步骤记 SKIP，不判失败
        log "步骤 $n 跳过：$desc（缺少工具）"
        printf 'SKIP 步骤 %s：%s（缺少工具：%s）\n' "$n" "$desc" "$(head -1 "$out" 2>/dev/null)" >> "$CASE_DIR/summary.txt"
        echo "(skipped)" > "$out"
        SKIP=$((SKIP+1))
        return 0
    fi
    if [ "$rc" -eq 0 ]; then
        log "步骤 $n 通过：$desc"
        printf 'PASS 步骤 %s：%s\n' "$n" "$desc" >> "$CASE_DIR/summary.txt"
        PASS=$((PASS+1))
    else
        warn "步骤 $n 失败（退出码 $rc）：$desc"
        printf 'FAIL 步骤 %s：%s（退出码 %s）\n' "$n" "$desc" "$rc" >> "$CASE_DIR/summary.txt"
        FAIL=$((FAIL+1))
    fi
    return "$rc"
}

# 断言上一步输出包含指定文本，如不包含则记失败（不中断）
# 用法：expect_text <序号> <说明> <正则> [输出文件]
expect_text() {
    local n=$1 desc=$2 pattern=$3 file=${4:-$CASE_DIR/step-$1.out}
    if [ "$(head -c 9 "$file" 2>/dev/null)" = "(skipped)" ]; then
        skip_step "$n" "$desc" "上一步无抓包权限被跳过"
        return 0
    fi
    if grep -Eq -- "$pattern" "$file"; then
        log "断言通过：$desc"
        printf 'PASS 断言 %s：%s（匹配 /%s/）\n' "$n" "$desc" "$pattern" >> "$CASE_DIR/summary.txt"
        PASS=$((PASS+1)); TOTAL=$((TOTAL+1))
    else
        warn "断言失败：$desc（未匹配 /$pattern/，见 $file）"
        printf 'FAIL 断言 %s：%s（未匹配 /%s/）\n' "$n" "$desc" "$pattern" >> "$CASE_DIR/summary.txt"
        FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
    fi
}

skip_step() {
    local n=$1 desc=$2 reason=$3
    printf 'SKIP 步骤 %s：%s（%s）\n' "$n" "$desc" "$reason" >> "$CASE_DIR/summary.txt"
    SKIP=$((SKIP+1))
    log "步骤 $n 跳过：$desc（$reason）"
}

# ---------------- 抓包 ----------------
capture_start() {
    local name=$1 port=$2 iface=${3:-${CAPTURE_IFACE:-lo}}
    local pcap="$CASE_DIR/captures/$name.pcap"
    if [ "${NO_CAPTURE:-0}" = 1 ]; then CAPTURE_PID=""; return 0; fi
    local filter
    case "$port" in
        *[!0-9]*) filter=$port ;;      # 传入的是完整过滤表达式（如多端口）
        *)        filter="port $port" ;;
    esac
    if [ "$MODE" = client ] && [ "${CAPTURE_REMOTE:-1}" = 1 ]; then
        # 客户端视角：只抓本机与远端服务端之间的流量
        case "$port" in
            *[!0-9]*) filter="host $SERVER_HOST and ($filter)" ;;
            *)        filter="host $SERVER_HOST and port $port" ;;
        esac
    fi
    : > "$pcap"
    if [ "${IN_NETNS:-0}" = 1 ]; then
        # user namespace 内 tcpdump 无法降权，改用 Python 抓包（等价输出 pcap）
        if [ "$filter" = "port $port" ]; then
            python3 "$PROJECT_ROOT/tools/pcap_capture.py" -i "$iface" -w "$pcap" -p "$port" \
                > "$CASE_DIR/captures/$name.capture.log" 2>&1 &
        else
            python3 "$PROJECT_ROOT/tools/pcap_capture.py" -i "$iface" -w "$pcap" --all \
                > "$CASE_DIR/captures/$name.capture.log" 2>&1 &
        fi
    else
        # 新版 tcpdump 支持 --immediate-mode：报文立即交付，配合 capture_stop 的等待更稳
        local opts=""
        if tcpdump --immediate-mode --version >/dev/null 2>&1; then opts="--immediate-mode"; fi
        # shellcheck disable=SC2086
        trace_cmd "tcpdump -i $iface -nn $opts -s0 -w $pcap $filter"
        printf '\n===== 抓包 =====\n$ tcpdump -i %s -nn %s -s0 -w %s %s\n' \
            "$iface" "$opts" "$pcap" "$filter" >> "$CASE_DIR/commands.log"
        tcpdump -i "$iface" -nn $opts -s0 -w "$pcap" $filter \
            > "$CASE_DIR/captures/$name.tcpdump.log" 2>&1 &
    fi
    CAPTURE_PID=$!
    sleep 1
    if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
        warn "抓包启动失败，见 captures/$name.tcpdump.log"; CAPTURE_PID=""
    else
        log "抓包已启动：$pcap（端口 $port，PID $CAPTURE_PID）"
    fi
}

capture_stop() {
    if [ -n "${CAPTURE_PID:-}" ] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        # 新版 libpcap（TPACKET_V3）按 1 秒块超时交付报文，立即 SIGTERM 会丢掉
        # 尚未写入文件的握手报文；这里等待超过 1 秒再停止。
        sleep 2
        trace_cmd "kill $CAPTURE_PID   # 停止抓包"
        kill "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
        log "抓包已停止"
    fi
    CAPTURE_PID=""
    local last; last=$(ls -t "$CASE_DIR"/captures/*.pcap 2>/dev/null | head -1)
    if [ -n "$last" ]; then
        local sz; sz=$(stat -c %s "$last" 2>/dev/null || echo 0)
        if [ "$sz" -le 24 ]; then
            warn "抓包文件为空：$last（检查抓包权限）"
        else
            log "抓包文件：$last（$sz 字节）"
        fi
    fi
}

# ---------------- 服务端 ----------------
# 客户端模式：服务端端点由服务端 server-endpoints.sh 预先启动，脚本不启停服务端。
server_start() {
    if [ "$MODE" = client ]; then
        log "客户端模式：服务端端点已在 $SERVER_HOST 运行，不启动本地服务端"
        return 0
    fi
    local name=$1 cmd=$2
    local logf="$CASE_DIR/server-$name.log"
    trace_cmd "$cmd   # 启动服务端 $name"
    # 用独立进程组启动，确保 stop 时能把真正的服务端进程一起回收
    setsid bash -c "cd \"$PROJECT_ROOT\" && $cmd" > "$logf" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$CASE_DIR/server-$name.pid"
    log "服务端已启动：$name（PID $SERVER_PID，日志 server-$name.log）"
}

# 本机回环服务端（TLS-3-4 编译产物运行验证用，与远端端点无关）
local_server_start() {
    local name=$1 cmd=$2
    local logf="$CASE_DIR/server-$name.log"
    setsid bash -c "cd \"$PROJECT_ROOT\" && $cmd" > "$logf" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$CASE_DIR/server-$name.pid"
    log "本机服务端已启动：$name（PID $SERVER_PID，日志 server-$name.log）"
}

# 检查远端端点可达；不可达记 FAIL 并返回 1，用例应随即退出
require_server() {
    local port=${1:-$SERVER_PORT} desc=${2:-服务端端点}
    trace_cmd "(exec 3<>/dev/tcp/$SERVER_HOST/$port)   # 探测服务端端点"
    if wait_port "$port" 5; then
        log "$desc 可达：$SERVER_HOST:$port"
        return 0
    fi
    warn "$desc 不可达：$SERVER_HOST:$port（请在服务端执行 tls-test-scripts/server-endpoints.sh start）"
    printf 'FAIL 前置：%s 不可达（%s:%s）\n' "$desc" "$SERVER_HOST" "$port" >> "$CASE_DIR/summary.txt"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
    return 1
}

wait_port() {
    local port=$1 timeout=${2:-10} i host=127.0.0.1
    [ "$MODE" = client ] && host=$SERVER_HOST
    for i in $(seq 1 $((timeout*10))); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    warn "端口 $host:$port 在 ${timeout}s 内未就绪"
    return 1
}

# 本机回环端口探测（TLS-3-4 运行本机编译产物时使用）
wait_local_port() {
    local port=$1 timeout=${2:-10} i
    for i in $(seq 1 $((timeout*10))); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    warn "本机端口 $port 在 ${timeout}s 内未就绪"
    return 1
}

server_stop() {
    local pid=${SERVER_PID:-}
    if [ -n "$pid" ]; then
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        local i
        for i in $(seq 1 30); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        log "服务端已停止（PID $pid）"
    fi
    SERVER_PID=""
}

cleanup() {
    capture_stop
    server_stop
    {
        printf '\n结束时间: %s\n' "$(date '+%F %T')"
        printf '合计: %s  通过: %s  失败: %s  跳过: %s\n' "$TOTAL" "$PASS" "$FAIL" "$SKIP"
        if [ "$FAIL" -gt 0 ]; then printf '结论: FAIL\n'
        elif [ "$TOTAL" -eq 0 ] && [ "$SKIP" -eq 0 ]; then printf '结论: FAIL（未执行任何步骤）\n'
        elif [ "$PASS" -eq 0 ] && [ "$SKIP" -gt 0 ]; then printf '结论: SKIP（需源码或材料，已暂停）\n'
        else printf '结论: PASS\n'; fi
    } >> "$CASE_DIR/summary.txt"
    log "结果目录：$CASE_DIR"
    log "汇总：通过 $PASS / 失败 $FAIL / 跳过 $SKIP"
}

finish_case() {
    [ "$FAIL" -eq 0 ] && return 0 || return 1
}

# 仅记录一条后台/辅助指令（不执行）
record_cmd() { printf '\n===== %s =====\n$ %s\n' "$1" "$2" >> "$CASE_DIR/commands.log"; }

# 期望命令失败（用于异常/负向用例）：退出码非 0 记为通过
run_sh_fail() {
    local n=$1 desc=$2 cmd=$3 out="$CASE_DIR/step-$1.out"
    TOTAL=$((TOTAL+1))
    printf '\n===== 步骤 %s（期望失败）：%s =====\n$ %s\n' "$n" "$desc" "$cmd" >> "$CASE_DIR/commands.log"
    printf '\n----- 步骤 %s（期望失败）：%s -----\n$ %s\n' "$n" "$desc" "$cmd" >> "$CASE_DIR/output.log"
    trace_cmd "$cmd"
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) 2>&1 | tee "$out" | tee -a "$CASE_DIR/output.log"
    local rc=${PIPESTATUS[0]}
    printf '退出码: %s（期望非 0）\n' "$rc" >> "$CASE_DIR/commands.log"
    if [ "$rc" -ne 0 ]; then
        log "步骤 $n 通过（按预期失败）：$desc"
        printf 'PASS 步骤 %s：%s（按预期失败，退出码 %s）\n' "$n" "$desc" "$rc" >> "$CASE_DIR/summary.txt"
        PASS=$((PASS+1))
    else
        warn "步骤 $n 失败（本应失败却成功）：$desc"
        printf 'FAIL 步骤 %s：%s（本应失败却成功）\n' "$n" "$desc" >> "$CASE_DIR/summary.txt"
        FAIL=$((FAIL+1))
    fi
    return 0
}
