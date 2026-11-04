# TLS 测试脚本公共函数
# 用法：脚本内 `source "$(dirname "$0")/lib.sh"`，随后 `init_case <用例标识> <用例名称>`。
# 结果目录：tls-test-scripts/results/run-<时间戳>/<用例标识>/
#   commands.log   每条指令与退出码
#   output.log     全部终端输出（含服务端/客户端日志）
#   captures/      抓包文件（.pcap）
#   analysis/      解析结果（tls_hello_check.py 等）
#   summary.txt    步骤级通过/失败/跳过与最终结论

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
# shellcheck source=config.env
source "$SCRIPT_DIR/config.env"

MODE=${MODE:-local}
RESULTS_ROOT=${RESULTS_ROOT:-$SCRIPT_DIR/results}
RUN_DIR=${RUN_DIR:-$RESULTS_ROOT/run-$(date +%Y%m%d-%H%M%S)-$$}
mkdir -p -- "$RUN_DIR"
export PROJECT_ROOT SCRIPT_DIR RESULTS_ROOT RUN_DIR MODE

TOTAL=0; PASS=0; FAIL=0; SKIP=0

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s][WARN] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# 是否已具备抓包权限（root 或免密 sudo）
_can_capture() {
    [ "$(id -u)" -eq 0 ] && return 0
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

# 本地抓包：无权限时自动进入 user+net namespace（lo 仍可用），保证 tcpdump 可执行
ensure_capture_env() {
    [ "$MODE" = local ] || return 0
    [ "${IN_NETNS:-0}" = 1 ] && return 0
    if _can_capture; then return 0; fi
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
    NO_CAPTURE=1
}

init_case() {
    CASE_ID=$1
    CASE_NAME=$2
    CASE_DIR=$RUN_DIR/$CASE_ID
    mkdir -p -- "$CASE_DIR/captures" "$CASE_DIR/analysis"
    : > "$CASE_DIR/commands.log"
    : > "$CASE_DIR/output.log"
    printf '用例标识: %s\n用例名称: %s\n执行方式: %s\n开始时间: %s\n主机: %s\n\n' \
        "$CASE_ID" "$CASE_NAME" "$MODE" "$(date '+%F %T')" "$(hostname)" > "$CASE_DIR/summary.txt"
    log "开始 $CASE_ID $CASE_NAME"
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
    if [ "${NO_CAPTURE:-0}" = 1 ] && grep -q 'tcpdump' <<<"$cmd"; then
        log "步骤 $n 跳过（无抓包权限）"
        printf 'SKIP 步骤 %s：%s（无抓包权限）\n' "$n" "$desc" >> "$CASE_DIR/summary.txt"
        SKIP=$((SKIP+1))
        echo "(skipped)" > "$out"
        return 0
    fi
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) 2>&1 | tee "$out" >> "$CASE_DIR/output.log"
    local rc=${PIPESTATUS[0]}
    printf '退出码: %s\n' "$rc" >> "$CASE_DIR/commands.log"
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
    local name=$1 port=$2
    local pcap="$CASE_DIR/captures/$name.pcap"
    if [ "${NO_CAPTURE:-0}" = 1 ]; then CAPTURE_PID=""; return 0; fi
    local filter
    case "$port" in
        *[!0-9]*) filter=$port ;;      # 传入的是完整过滤表达式（如多端口）
        *)        filter="port $port" ;;
    esac
    : > "$pcap"
    if [ "${IN_NETNS:-0}" = 1 ]; then
        # user namespace 内 tcpdump 无法降权，改用 Python 抓包（等价输出 pcap）
        if [ "$filter" = "port $port" ]; then
            python3 "$PROJECT_ROOT/tools/pcap_capture.py" -i "${CAPTURE_IFACE:-lo}" -w "$pcap" -p "$port" \
                > "$CASE_DIR/captures/$name.capture.log" 2>&1 &
        else
            python3 "$PROJECT_ROOT/tools/pcap_capture.py" -i "${CAPTURE_IFACE:-lo}" -w "$pcap" --all \
                > "$CASE_DIR/captures/$name.capture.log" 2>&1 &
        fi
    else
        # shellcheck disable=SC2086
        tcpdump -i "${CAPTURE_IFACE:-lo}" -nn -s0 -w "$pcap" $filter \
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
server_start() {
    local name=$1 cmd=$2
    local logf="$CASE_DIR/server-$name.log"
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) > "$logf" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$CASE_DIR/server-$name.pid"
    log "服务端已启动：$name（PID $SERVER_PID，日志 server-$name.log）"
}

wait_port() {
    local port=$1 timeout=${2:-10} i
    for i in $(seq 1 $((timeout*10))); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    warn "端口 $port 在 ${timeout}s 内未就绪"
    return 1
}

server_stop() {
    local pid=${SERVER_PID:-}
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        log "服务端已停止（PID $pid）"
    fi
    SERVER_PID=""
}

# ---------------- 抓包解析 ----------------
checker() {
    local pcap=$1; shift
    local out="$CASE_DIR/analysis/$(basename "${pcap%.pcap}").check.txt"
    ( cd "$PROJECT_ROOT" && python3 tools/tls_hello_check.py "$CASE_DIR/captures/$pcap" "$@" ) \
        2>&1 | tee "$out"
    printf '解析结果: %s\n' "$out" >> "$CASE_DIR/summary.txt"
}

cleanup() {
    capture_stop
    server_stop
    {
        printf '\n结束时间: %s\n' "$(date '+%F %T')"
        printf '合计: %s  通过: %s  失败: %s  跳过: %s\n' "$TOTAL" "$PASS" "$FAIL" "$SKIP"
        if [ "$FAIL" -gt 0 ]; then printf '结论: FAIL\n'
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

# 远端执行（MODE=remote 时预留；本地不启用）
remote_run() { ssh -p "${REMOTE_PORT:-22}" "$REMOTE_HOST" "cd '$REMOTE_DIR' && $*"; }
remote_capture_start() {
    ssh -p "${REMOTE_PORT:-22}" "$REMOTE_HOST" \
        "cd '$REMOTE_DIR' && nohup tcpdump -i ${CAPTURE_IFACE:-lo} -nn -s0 -w '$1.pcap' port '$2' >/dev/null 2>&1 & echo \$!"
}

# 期望命令失败（用于异常/负向用例）：退出码非 0 记为通过
run_sh_fail() {
    local n=$1 desc=$2 cmd=$3 out="$CASE_DIR/step-$1.out"
    TOTAL=$((TOTAL+1))
    printf '\n===== 步骤 %s（期望失败）：%s =====\n$ %s\n' "$n" "$desc" "$cmd" >> "$CASE_DIR/commands.log"
    printf '\n----- 步骤 %s（期望失败）：%s -----\n$ %s\n' "$n" "$desc" "$cmd" >> "$CASE_DIR/output.log"
    ( cd "$PROJECT_ROOT" && bash -c "$cmd" ) 2>&1 | tee "$out" >> "$CASE_DIR/output.log"
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
