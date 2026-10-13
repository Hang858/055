#!/usr/bin/env bash
set -euo pipefail
PACKAGE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export CERTTOOL_RESULTS_DIR=${CERTTOOL_RESULTS_DIR:-$PACKAGE_ROOT/results/pipeline-$(date +%Y%m%d-%H%M%S)-$$}
mkdir -p -- "$CERTTOOL_RESULTS_DIR/logs"
mapfile -d '' cases < <(find "$PACKAGE_ROOT/certtool-test-scripts" -maxdepth 1 -name 'ZS-*.sh' -print0 | sort -zV)
test "${#cases[@]}" -gt 0 || { echo '未找到用例脚本' >&2; exit 1; }
failed=0
for script in "${cases[@]}"; do
    name=$(basename "$script" .sh)
    id=${name%% *}
    printf '%s' "执行 $name ... "
    if bash "$script" > "$CERTTOOL_RESULTS_DIR/logs/$id.log" 2>&1; then
        echo '通过'
        printf '%s\t%s\n' "$id" '通过' >> "$CERTTOOL_RESULTS_DIR/summary.tsv"
    else
        echo '失败'
        printf '%s\t%s\n' "$id" '失败' >> "$CERTTOOL_RESULTS_DIR/summary.tsv"
        failed=$((failed+1))
    fi
done
echo "结果目录：$CERTTOOL_RESULTS_DIR"
echo "完成 ${#cases[@]} 条，失败 $failed 条"
test "$failed" -eq 0
