#!/usr/bin/env bash
# TLS 网关现场诊断脚本
# 用法：
#   sudo bash diag-tls-gateway.sh
#   sudo bash diag-tls-gateway.sh /tmp/my-diag.txt
#   PREFIX=/opt/pqc-gateway-hybrid sudo bash diag-tls-gateway.sh
#
# 输出同时打印到终端并保存到文件，默认 /tmp/tls-gateway-diag-<时间>.txt。

set -u
umask 077
export SYSTEMD_PAGER=cat
export PAGER=cat

PREFIX=${PREFIX:-/opt/pqc-gateway-hybrid}
OUT=${1:-/tmp/tls-gateway-diag-$(date +%Y%m%d-%H%M%S).txt}

: > "$OUT" 2>/dev/null || {
    echo "无法写入 $OUT" >&2
    exit 1
}
exec > >(tee -a "$OUT") 2>&1

section() { printf '\n===== %s =====\n' "$*"; }

run() {
    printf '\n$'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[退出码 %s]\n' "$rc"
    fi
}

run_sh() {
    printf '\n$ %s\n' "$*"
    bash -c "$*" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[退出码 %s]\n' "$rc"
    fi
}

# xgs 用户级 systemd 的调用前缀
uid=$(id -u xgs 2>/dev/null || true)
xdg=${XDG_RUNTIME_DIR:-/run/user/${uid:-1000}}
USER_PREFIX=()
if [ "$(id -u)" -eq 0 ] && [ -n "$uid" ]; then
    if command -v sudo >/dev/null 2>&1; then
        USER_PREFIX=(sudo -u xgs env "XDG_RUNTIME_DIR=$xdg" "DBUS_SESSION_BUS_ADDRESS=unix:path=$xdg/bus")
    elif command -v runuser >/dev/null 2>&1; then
        USER_PREFIX=(runuser -u xgs -- env "XDG_RUNTIME_DIR=$xdg" "DBUS_SESSION_BUS_ADDRESS=unix:path=$xdg/bus")
    fi
elif [ "$(id -un)" = "xgs" ]; then
    USER_PREFIX=(env "XDG_RUNTIME_DIR=$xdg" "DBUS_SESSION_BUS_ADDRESS=unix:path=$xdg/bus")
fi

user_run() {
    if [ "${#USER_PREFIX[@]}" -gt 0 ]; then
        run "${USER_PREFIX[@]}" "$@"
    else
        printf '\n[跳过] 当前用户无法访问 xgs 的用户级 systemd：%s\n' "$*"
    fi
}

section "基本信息"
run date -Is
run hostname
run id
run uname -a
run_sh "cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION|ID|VERSION_ID|PRETTY_NAME)=' || true"
run_sh "ip -br addr 2>/dev/null || true"
run_sh "ip route 2>/dev/null || true"

section "快速结论"
echo "安装目录：$PREFIX"
echo "配置里的 listen："
run_sh "grep -n '\"listen\"' '$PREFIX'/config/gateway-managed*.json 2>/dev/null || echo '未找到配置文件'"
echo "443/8443/8444/8445/9000 监听："
run_sh "ss -ltnp 2>/dev/null | grep -E ':(443|8443|8444|8445|9000)\\b' || echo '以上端口均未监听'"
echo "pqc-gateway 进程："
run_sh "ps -eo pid,user,lstart,args 2>/dev/null | grep '[p]qc-gateway' || echo '未发现 pqc-gateway 进程'"
echo "系统级 unit："
run_sh "systemctl list-unit-files --no-pager 2>/dev/null | grep -i pqc || echo '系统级无 pqc unit'"
echo "用户级 unit："
if [ "${#USER_PREFIX[@]}" -gt 0 ]; then
    run_sh "${USER_PREFIX[*]} systemctl --user list-unit-files --no-pager 2>/dev/null | grep -i pqc || echo '用户级无 pqc unit'"
else
    echo '当前用户无法查询 xgs 用户级 systemd'
fi

section "配置目录"
run ls -la "$PREFIX/config" 2>&1
for f in gateway-managed.json gateway-managed-87.json gateway-managed-ecdsa.json; do
    if [ -f "$PREFIX/config/$f" ]; then
        printf '\n--- %s ---\n' "$PREFIX/config/$f"
        run cat "$PREFIX/config/$f"
    fi
done

section "证书目录"
run_sh "ls -ld '$PREFIX'/certs '$PREFIX'/certs/44 '$PREFIX'/certs/87 '$PREFIX'/certs/ecdsa 2>/dev/null || true"
run_sh "ls -l '$PREFIX'/certs/44 '$PREFIX'/certs/87 '$PREFIX'/certs/ecdsa 2>/dev/null || true"
for lvl in 44 87 ecdsa; do
    if [ -f "$PREFIX/certs/$lvl/server.crt" ]; then
        printf '\n--- %s server.crt ---\n' "$lvl"
        run openssl x509 -in "$PREFIX/certs/$lvl/server.crt" -noout -subject -issuer -dates -ext subjectAltName 2>&1
    fi
done

section "程序版本"
if [ -x "$PREFIX/bin/pqc-gateway" ]; then
    run "$PREFIX/bin/pqc-gateway" version
else
    echo "找不到可执行文件：$PREFIX/bin/pqc-gateway"
fi

section "系统级 systemd 状态"
for u in pqc-gateway-hybrid pqc-gateway-hybrid-87 pqc-gateway-hybrid-ecdsa pqc-gateway-demo-backend; do
    printf '\n--- %s.service ---\n' "$u"
    run systemctl status "$u.service" -l --no-pager
    run systemctl show "$u.service" -p FragmentPath -p ActiveState -p SubState -p ExecMainStatus -p ExecMainPID --no-pager
    run systemctl cat "$u.service"
done

section "用户级 systemd 状态"
if [ "${#USER_PREFIX[@]}" -gt 0 ]; then
    for u in pqc-gateway-hybrid pqc-gateway-hybrid-87 pqc-gateway-hybrid-ecdsa pqc-gateway-demo-backend; do
        printf '\n--- %s.service (xgs) ---\n' "$u"
        user_run systemctl --user status "$u.service" -l --no-pager
        user_run systemctl --user show "$u.service" -p FragmentPath -p ActiveState -p SubState -p ExecMainStatus -p ExecMainPID --no-pager
        user_run systemctl --user cat "$u.service"
    done
else
    echo '当前用户无法查询 xgs 用户级 systemd'
fi

section "系统级 journal"
for u in pqc-gateway-hybrid pqc-gateway-hybrid-87 pqc-gateway-hybrid-ecdsa pqc-gateway-demo-backend; do
    printf '\n--- %s.service ---\n' "$u"
    run journalctl -u "$u.service" -n 120 --no-pager
done

section "用户级 journal"
if [ "${#USER_PREFIX[@]}" -gt 0 ]; then
    for u in pqc-gateway-hybrid pqc-gateway-hybrid-87 pqc-gateway-hybrid-ecdsa pqc-gateway-demo-backend; do
        printf '\n--- %s.service (xgs) ---\n' "$u"
        user_run journalctl --user -u "$u.service" -n 120 --no-pager
    done
else
    echo '当前用户无法查询 xgs 用户级 journal'
fi

section "端口与连接"
run ss -ltnp
run_sh "ss -tnp state established 2>/dev/null | head -40 || true"
run_sh "ss -s 2>/dev/null || true"

section "手工启动日志"
run_sh "ls -l '$PREFIX'/run/*.log '$PREFIX'/nohup.out 2>/dev/null || echo '没有 run/*.log 或 nohup.out'"
for f in "$PREFIX"/run/*.log; do
    [ -f "$f" ] || continue
    printf '\n--- %s (最后 50 行) ---\n' "$f"
    run tail -n 50 "$f"
done

section "最近系统错误"
run_sh "journalctl -n 80 -p warning --no-pager 2>/dev/null | tail -80 || true"

section "输出文件"
echo "$OUT"
echo "把这份文件发给开发即可。"
