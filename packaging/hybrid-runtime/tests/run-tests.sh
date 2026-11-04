#!/usr/bin/env bash
source "$(dirname "$0")/lib-gw.sh"
export RUN_DIR
printf '用例\t结论\t通过\t失败\t跳过\n' > "$RUN_DIR/summary.tsv"
for s in "$GW_SCRIPT_DIR"/TLS-*.sh; do
    bash "$s" || true
    cid=$(basename "$s" | cut -d' ' -f1)
    f="$RUN_DIR/$cid/summary.txt"
    if [ -f "$f" ]; then
        concl=$(grep -o '结论: [A-Z]*' "$f" | tail -1 | awk '{print $2}')
        line=$(grep -o '通过: [0-9]*  失败: [0-9]*  跳过: [0-9]*' "$f" | tail -1)
        printf '%s\t%s\t%s\t%s\t%s\n' "$cid" "${concl:-UNKNOWN}" "$(awk '{print $2}' <<<"$line")" "$(awk '{print $4}' <<<"$line")" "$(awk '{print $6}' <<<"$line")" >> "$RUN_DIR/summary.tsv"
    else
        printf '%s\tNO-RESULT\t0\t0\t0\n' "$cid" >> "$RUN_DIR/summary.tsv"
    fi
done
echo "汇总：$RUN_DIR/summary.tsv"; column -t -s $'\t' "$RUN_DIR/summary.tsv" 2>/dev/null || cat "$RUN_DIR/summary.tsv"
