#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# -ne 2 ]]; then echo "用法：$0 pure-pq|sm2|x509-multi|gen-pq-chain|gen-sm2-chain 新输出目录" >&2; exit 1; fi
tool_name=$1
case "$tool_name" in pure-pq|sm2|x509-multi|gen-pq-chain|gen-sm2-chain) ;; *) echo '未知证书工具' >&2; exit 1;; esac
output_dir=$2
if [[ -e "$output_dir" ]]; then echo '输出目录已存在，拒绝覆盖。' >&2; exit 1; fi
mkdir -p "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
if [[ "$tool_name" == gen-* ]]; then
  mkdir "$output_dir/work" "$output_dir/data"
  cp "$bundle_dir/certificate-tools/data/public_keys.txt" "$output_dir/data/"
  (cd "$output_dir/work" && "$bundle_dir/certificate-tools/bin/$tool_name") > "$output_dir/generation.log" 2>&1
else
  (cd "$output_dir" && "$bundle_dir/certificate-tools/bin/$tool_name") > "$output_dir/generation.log" 2>&1
fi
find "$output_dir" -type f \( -name '*.key' -o -name '*key*.pem' -o -name '*key*.bin' \) -exec chmod 600 {} +
cat "$output_dir/generation.log"
echo "已生成到 $output_dir；研究证书不能直接替换网关运行证书，请阅读 docs/能力与证书对应说明.md。"
