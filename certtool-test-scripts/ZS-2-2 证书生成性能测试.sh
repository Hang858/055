#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
init_case ZS-2-2
# 步骤：五类证书链各重复三次；每次使用新 output_dir，记录端到端生成耗时。
CSV=$CASE_DIR/timings.csv
echo 'type,iteration,elapsed_ms' > "$CSV"
for kind in rsa-hybrid sm2-hybrid kem dsa slh; do
    for n in 1 2 3; do
        case "$kind" in
            rsa-hybrid|sm2-hybrid) case_config "$kind-$n" "$kind" ML-DSA-44 ML-DSA-44 ML-KEM-512 1;;
            kem) case_config "$kind-$n" pure-pq ML-DSA-44 ML-DSA-44 ML-KEM-512 1;;
            dsa) case_config "$kind-$n" pure-pq ML-DSA-44 ML-DSA-44 ML-DSA-44 1;;
            slh) case_config "$kind-$n" slh-dsa SLH-DSA-SHA2-128s SLH-DSA-SHA2-128s SLH-DSA-SHA2-128s 1;;
        esac
        "$CERTTOOL_BIN" check -config "$CONFIG_FILE" > /dev/null
        start=$(date +%s%N)
        "$CERTTOOL_BIN" generate -config "$CONFIG_FILE" > "$CASE_DIR/$kind-$n.generate.json"
        end=$(date +%s%N)
        "$CERTTOOL_BIN" verify -config "$CONFIG_FILE" > /dev/null
        assert_pem user.crt CERTIFICATE
        echo "$kind,$n,$(( (end-start)/1000000 ))" >> "$CSV"
    done
done
# 验收：每类三次全部成功，并输出平均、最大、最小耗时。
python3 - "$CSV" "$CASE_DIR/summary.txt" <<'PY'
import csv,statistics,sys
rows=list(csv.DictReader(open(sys.argv[1])))
assert len(rows)==15
groups={}
for row in rows: groups.setdefault(row['type'],[]).append(int(row['elapsed_ms']))
assert len(groups)==5 and all(len(v)==3 for v in groups.values())
with open(sys.argv[2],'w') as out:
 for kind,ms in groups.items():
  out.write(f'{kind}: 次数=3 成功=3 失败=0 平均={statistics.mean(ms):.1f}ms 最小={min(ms)}ms 最大={max(ms)}ms\n')
PY
cat "$CASE_DIR/summary.txt"
case_pass '五类证书生成均成功，耗时统计完整；大纲未给固定性能阈值'
