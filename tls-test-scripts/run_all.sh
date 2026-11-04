#!/usr/bin/env bash
# 客户端视角：依次执行可在本机完成的用例，并在服务端执行 TLS-2-5、TLS-1-13，
# 两部分结果合并到 $RUN_DIR/summary.tsv。
#   RUN_SERVER_SIDE=1（默认）通过 SSH 在服务端执行；=0 跳过；=local 在本机执行
#   SERVER_SSH 为已配置免密登录的主机别名，SERVER_DIR 为服务端部署目录
source "$(dirname "$0")/lib.sh"
export RUN_DIR
ensure_capture_env
if [ "${NO_CAPTURE:-0}" = 1 ]; then
    echo "提示：当前用户无抓包权限（未用 sudo），抓包 / pcap 解析 / tshark 步骤将记 SKIP，属于降级执行；完整验收请用 sudo 运行本脚本。"
fi
printf '用例\t结论\t通过\t失败\t跳过\n' > "$RUN_DIR/summary.tsv"

echo "服务端：$SERVER_HOST（8080 非 HQC / 8181 HQC / 8082 协商策略 / 8099 压测 / 8111 过期证书）"

# 以调用者身份执行 ssh/scp（sudo 下 root 没有用户的密钥与主机别名）
ssh_do() {
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" -H ssh -o BatchMode=yes "$@"
    else
        ssh -o BatchMode=yes "$@"
    fi
}
scp_do() {
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" -H scp -q -r "$@"
    else
        scp -q -r "$@"
    fi
}

append_row() {
    local cid=$1 dir=$2 f="$2/$1/summary.txt" concl line p fa sk
    if [ -f "$f" ]; then
        concl=$(grep -o '结论: [A-Z]*' "$f" | tail -1 | awk '{print $2}')
        line=$(grep -o '通过: [0-9]*  失败: [0-9]*  跳过: [0-9]*' "$f" | tail -1)
        p=$(awk '{print $2}' <<<"$line"); fa=$(awk '{print $4}' <<<"$line"); sk=$(awk '{print $6}' <<<"$line")
        printf '%s\t%s\t%s\t%s\t%s\n' "$cid" "${concl:-UNKNOWN}" "${p:-0}" "${fa:-0}" "${sk:-0}" >> "$RUN_DIR/summary.tsv"
    else
        printf '%s\tNO-RESULT\t0\t0\t0\n' "$cid" >> "$RUN_DIR/summary.tsv"
    fi
}

SERVER_SIDE_CASES="TLS-2-5 TLS-1-13"

for s in "$SCRIPT_DIR"/TLS-*.sh; do
    cid=$(basename "$s" | cut -d' ' -f1)
    case " $SERVER_SIDE_CASES " in
        *" $cid "*) continue ;;
    esac
    bash "$s" || true
    append_row "$cid" "$RUN_DIR"
done

# ---------------- 服务端侧用例 ----------------
run_server_side() {
    local cid list=""
    for cid in $SERVER_SIDE_CASES; do list="$list $cid"; done
    if [ "${RUN_SERVER_SIDE:-1}" = 0 ]; then
        echo "跳过服务端侧用例（RUN_SERVER_SIDE=0）：$list"
        for cid in $SERVER_SIDE_CASES; do printf '%s\tSERVER-SIDE\t0\t0\t0\n' "$cid" >> "$RUN_DIR/summary.tsv"; done
        return 0
    fi
    local local_run=0
    if [ "${RUN_SERVER_SIDE:-1}" = local ] || hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$SERVER_HOST"; then
        local_run=1
    fi
    local remote_dir="$SERVER_DIR/server-side-results/run-$(date +%Y%m%d-%H%M%S)-$$"
    local remote_failed=0

    if [ "$local_run" = 1 ]; then
        echo "服务端侧用例在本机执行：$list"
        mkdir -p "$RUN_DIR/server-side"
        ( cd "$SERVER_DIR" && RUN_DIR="$RUN_DIR/server-side" bash tls-test-scripts/run-server-side.sh ) || true
    else
        echo "服务端侧用例通过 SSH 在 $SERVER_SSH:$SERVER_DIR 执行：$list"
        if ssh_do "$SERVER_SSH" "cd '$SERVER_DIR' && RUN_DIR='$remote_dir' bash tls-test-scripts/run-server-side.sh"; then
            mkdir -p "$RUN_DIR/server-side"
            # sudo 下 RUN_DIR 属于 root，取回前交给调用者，scp 才能写入
            if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
                chown -R "$SUDO_USER" "$RUN_DIR/server-side"
            fi
            if scp_do "$SERVER_SSH:$remote_dir/." "$RUN_DIR/server-side/"; then
                echo "服务端侧结果已取回：$RUN_DIR/server-side"
            else
                echo "服务端侧结果取回失败，仅保留远端 $remote_dir" >&2
                remote_failed=1
            fi
        else
            echo "服务端侧用例执行失败（SSH 或服务端环境不可用）" >&2
            remote_failed=1
        fi
    fi

    for cid in $SERVER_SIDE_CASES; do
        if [ -f "$RUN_DIR/server-side/$cid/summary.txt" ]; then
            append_row "$cid" "$RUN_DIR/server-side"
        elif [ "$remote_failed" = 1 ]; then
            printf '%s\tSERVER-SIDE-ERROR\t0\t0\t0\n' "$cid" >> "$RUN_DIR/summary.tsv"
        else
            printf '%s\tSERVER-SIDE\t0\t0\t0\n' "$cid" >> "$RUN_DIR/summary.tsv"
        fi
    done
}

run_server_side

# 汇总按用例标识排序，服务端两条与客户端用例混排
{
    head -1 "$RUN_DIR/summary.tsv"
    tail -n +2 "$RUN_DIR/summary.tsv" | sort -V
} > "$RUN_DIR/summary.tsv.tmp" && mv "$RUN_DIR/summary.tsv.tmp" "$RUN_DIR/summary.tsv"

echo "汇总：$RUN_DIR/summary.tsv"
column -t -s $'\t' "$RUN_DIR/summary.tsv" 2>/dev/null || cat "$RUN_DIR/summary.tsv"
if grep -qE $'\t(FAIL|SERVER-SIDE-ERROR|NO-RESULT|UNKNOWN)\t' "$RUN_DIR/summary.tsv"; then
    echo "存在失败用例，退出码 1" >&2
    exit 1
fi
