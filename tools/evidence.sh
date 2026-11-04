#!/usr/bin/env bash
# 单条用例留证：展开命令执行，并把终端输出完整保存为日志；可选自动截当前窗口。
# 用法: sudo bash tools/evidence.sh "tls-test-scripts/TLS-1-1 格类...sh" [输出目录]
set -uo pipefail

CASE_SCRIPT=${1:?用法: sudo bash tools/evidence.sh "tls-test-scripts/TLS-1-1 ....sh" [输出目录]}
OUT=${2:-evidence}
mkdir -p "$OUT"
NAME=$(basename "$CASE_SCRIPT" .sh)
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$OUT/$NAME-$STAMP.log"

echo "用例脚本: $CASE_SCRIPT"
echo "留证日志: $LOG"
echo "提示: 终端会逐条打印实际执行的命令；结束后可截图，或按 Ctrl+Shift+S 等自行截屏。"
echo

TRACE=1 bash "$CASE_SCRIPT" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}

echo
echo "执行结束，退出码: $RC"
echo "日志已保存: $LOG"
echo "汇总文件: $(ls -dt tls-test-scripts/results/run-*/"$(basename "$CASE_SCRIPT" | cut -d' ' -f1)"/summary.txt 2>/dev/null | head -1)"

# 若系统有截图工具，尝试自动截当前窗口（以调用者身份，保留其桌面会话）
if [ -n "${SUDO_USER:-}" ] && [ -n "${DISPLAY:-}" ]; then
    SHOT="$OUT/$NAME-$STAMP.png"
    if command -v gnome-screenshot >/dev/null 2>&1; then
        echo
        echo "5 秒后截取当前窗口到 $SHOT（请保持本终端在前台）..."
        sleep 5
        sudo -u "$SUDO_USER" DISPLAY="$DISPLAY" gnome-screenshot -w -f "$SHOT" 2>/dev/null && echo "已截图: $SHOT"
    elif command -v scrot >/dev/null 2>&1; then
        echo
        echo "5 秒后截屏到 $SHOT（请保持本终端在前台）..."
        sleep 5
        sudo -u "$SUDO_USER" DISPLAY="$DISPLAY" scrot -u "$SHOT" 2>/dev/null && echo "已截图: $SHOT"
    fi
fi
exit "$RC"
