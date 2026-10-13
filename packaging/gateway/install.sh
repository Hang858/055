#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_prefix=${1:-/opt/pqc-gateway}
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo '本安装包仅支持 Linux x86_64（目标 Ubuntu 20.04）。' >&2; exit 1
fi
case "$install_prefix" in /*) ;; *) echo '安装路径必须是绝对路径。' >&2; exit 1;; esac
if [[ -e "$install_prefix" ]]; then echo "安装目录已存在，拒绝覆盖：$install_prefix" >&2; exit 1; fi
(cd "$bundle_dir" && sha256sum -c SHA256SUMS > /dev/null)
mkdir -p "$install_prefix/bin" "$install_prefix/config" "$install_prefix/docs" "$install_prefix/systemd"
install -m 0755 "$bundle_dir/bin/pqc-gateway" "$install_prefix/bin/"
install -m 0644 "$bundle_dir/config/gateway.json" "$install_prefix/config/"
cp -R "$bundle_dir/docs/." "$install_prefix/docs/"
install -m 0644 "$bundle_dir/systemd/pqc-gateway.service" "$install_prefix/systemd/"
chmod 0755 "$install_prefix" "$install_prefix/bin" "$install_prefix/config" "$install_prefix/docs" "$install_prefix/systemd"
printf '已安装到 %s\n下一步：按 docs/安装和配置说明.md 生成现场证书并编辑 config/gateway.json。\n' "$install_prefix"
echo '服务尚未启动；演示证书不会自动用于正式配置。'
