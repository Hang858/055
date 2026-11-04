#!/usr/bin/env bash
# 逐条执行测试用例：清屏 -> 展开命令执行 -> 结束后截图，图片以用例名命名。
# 用法:
#   bash tools/capture-case.sh                       # 全部客户端用例
#   bash tools/capture-case.sh "tls-test-scripts/TLS-1-1 ....sh"
#   OUT=evidence NO_SUDO=1 bash tools/capture-case.sh "..."   # 不抓包（无 root）
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${OUT:-evidence}
NO_SUDO=${NO_SUDO:-0}
mkdir -p "$OUT"

# 截图：按可用工具依次尝试；成功返回 0
capture_screen() {
    local png=$1 tool
    for tool in gnome-screenshot spectacle scrot import grim flameshot maim; do
        command -v "$tool" >/dev/null 2>&1 || continue
        case "$tool" in
            gnome-screenshot) gnome-screenshot -w -f "$png" >/dev/null 2>&1 ;;
            spectacle)        spectacle -a -b -n -o "$png" >/dev/null 2>&1 ;;
            scrot)            scrot -u "$png" >/dev/null 2>&1 ;;
            import)           import -window root "$png" >/dev/null 2>&1 ;;
            grim)             grim "$png" >/dev/null 2>&1 ;;
            flameshot)        flameshot full -p "$OUT" >/dev/null 2>&1 && [ -s "$png" ] || flameshot full -p "$png" >/dev/null 2>&1 ;;
            maim)             maim -u "$png" >/dev/null 2>&1 ;;
        esac
        [ -s "$png" ] && return 0
    done
    return 1
}

run_one() {
    local script=$1 name log png rc
    name=$(basename "$script" .sh)
    log="$OUT/$name.log"
    png="$OUT/$name.png"

    if [ "$CLEAR_SCREEN" = 1 ]; then clear; fi
    printf '用例: %s\n' "$name"
    printf '时间: %s\n\n' "$(date '+%F %T')"

    if [ "$NO_SUDO" = 1 ] || [ "$(id -u)" -eq 0 ]; then
        TRACE=1 bash "$script" 2>&1 | tee "$log"
    elif sudo -n true 2>/dev/null || sudo -v 2>/dev/null; then
        sudo --preserve-env=TRACE,SERVER_HOST,CAPTURE_IFACE,RESULTS_ROOT,RUN_SERVER_SIDE \
            env TRACE=1 bash "$script" 2>&1 | tee "$log"
    else
        echo "无 sudo：抓包相关步骤会跳过" >&2
        TRACE=1 bash "$script" 2>&1 | tee "$log"
    fi
    rc=${PIPESTATUS[0]}

    sleep 1
    if [ "$SCREENSHOT" = 1 ] && capture_screen "$png"; then
        echo "截图已保存: $png"
    else
        echo "未检测到可用截图工具，改为按日志渲染同尺寸图片: $png"
        python3 "$ROOT/tools/render_log.py" "$log" "$png" --size 18 --cols 118
    fi
    echo "日志: $log    退出码: $rc"
    return "$rc"
}

CLEAR_SCREEN=${CLEAR_SCREEN:-1}
SCREENSHOT=${SCREENSHOT:-1}

CASES=("$@")
if [ ${#CASES[@]} -eq 0 ]; then
    while IFS= read -r -d '' s; do
        case "$(basename "$s")" in
            TLS-2-5*|TLS-1-13*) continue ;;
        esac
        CASES+=("$s")
    done < <(find "$ROOT/tls-test-scripts" -maxdepth 1 -name 'TLS-*.sh' -print0 | sort -zV)
fi

FAILED=0
for s in "${CASES[@]}"; do
    run_one "$s" || FAILED=$((FAILED+1))
done

echo
echo "完成 ${#CASES[@]} 条，失败 $FAILED 条，图片与日志在: $OUT"
exit $((FAILED > 0 ? 1 : 0))
