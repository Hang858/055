#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_prefix=${1:-/opt/pqc-gateway-hybrid}
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo '仅支持 Linux x86_64；目标系统为 Ubuntu 20.04。' >&2
  exit 1
fi
case "$install_prefix" in
  /*) ;;
  *) echo '安装路径必须为绝对路径。' >&2; exit 1 ;;
esac
if [[ -e "$install_prefix" ]]; then
  echo "安装目录已存在，拒绝覆盖：$install_prefix" >&2
  exit 1
fi
(cd "$bundle_dir" && sha256sum -c SHA256SUMS >/dev/null)
mkdir -p "$install_prefix"
cp -a "$bundle_dir/." "$install_prefix/"
find "$install_prefix/demo" -type f -name '*.key' -exec chmod 600 {} +
echo "已安装到 $install_prefix"
echo "按 $install_prefix/docs/安装配置说明.md 生成厂内专用证书并修改配置。"
