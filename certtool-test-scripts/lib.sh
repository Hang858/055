#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PACKAGE_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CERTTOOL_BIN=${CERTTOOL_BIN:-$PACKAGE_ROOT/bin/pqc-certtool}
CERTTOOL_CONFIG_DIR=${CERTTOOL_CONFIG_DIR:-$PACKAGE_ROOT/config}
CERTTOOL_DATA_DIR=${CERTTOOL_DATA_DIR:-$PACKAGE_ROOT/data}
CERTTOOL_RESULTS_DIR=${CERTTOOL_RESULTS_DIR:-$PACKAGE_ROOT/results/manual-$(date +%Y%m%d-%H%M%S)-$$}

init_case() {
    CASE_ID=$1
    CASE_DIR=$CERTTOOL_RESULTS_DIR/$CASE_ID
    mkdir -p -- "$CASE_DIR"
    test -x "$CERTTOOL_BIN" || { echo "证书工具不可执行：$CERTTOOL_BIN" >&2; exit 1; }
    command -v python3 >/dev/null
    command -v openssl >/dev/null
    echo "[$CASE_ID] 开始"
}

# 按现有 JSON 样例生成本用例的独立配置。参数：标签、样例名、根算法、中间算法、用户算法、中间级数。
case_config() {
    local label=$1 template=$2 root_alg=$3 inter_alg=$4 leaf_alg=$5 inter_count=$6
    CONFIG_FILE=$CASE_DIR/$label.json
    OUT_DIR=$CASE_DIR/$label-out
    python3 - "$CERTTOOL_CONFIG_DIR/$template.json" "$CONFIG_FILE" "$OUT_DIR" "$root_alg" "$inter_alg" "$leaf_alg" "$inter_count" <<'PY'
import json,sys
source,dest,out,root_alg,inter_alg,leaf_alg,count=sys.argv[1:]
c=json.load(open(source,encoding='utf-8'))
c['output_dir']=out
c['root'].update(name='root',common_name='Test Root',algorithm=root_alg,valid_days=3650)
c['intermediates']=[{'name':f'inter{i+1}','common_name':f'Test Intermediate {i+1}',
                     'algorithm':inter_alg,'valid_days':1825 if i==0 else 1000}
                    for i in range(int(count))]
c['leaves']=[{'name':'user','common_name':'Test User','algorithm':leaf_alg,'valid_days':365}]
with open(dest,'w',encoding='utf-8') as f: json.dump(c,f,ensure_ascii=False,indent=2)
PY
}

case_add_leaf() {
    python3 - "$CONFIG_FILE" "$1" "$2" <<'PY'
import json,sys
p,name,algorithm=sys.argv[1:]
c=json.load(open(p,encoding='utf-8'))
c['leaves'].append({'name':name,'common_name':'Test '+name,'algorithm':algorithm,'valid_days':365})
with open(p,'w',encoding='utf-8') as f: json.dump(c,f,ensure_ascii=False,indent=2)
PY
}

case_set_import() {
    python3 - "$CONFIG_FILE" "$1" <<'PY'
import json,sys
p,key=sys.argv[1:]
c=json.load(open(p,encoding='utf-8'))
c['leaves'][0]['public_key_file']=key
with open(p,'w',encoding='utf-8') as f: json.dump(c,f,ensure_ascii=False,indent=2)
PY
}

case_run() {
    "$CERTTOOL_BIN" check -config "$CONFIG_FILE" > "$CASE_DIR/$(basename "$CONFIG_FILE" .json).check.json"
    "$CERTTOOL_BIN" generate -config "$CONFIG_FILE" > "$CASE_DIR/$(basename "$CONFIG_FILE" .json).generate.json"
    "$CERTTOOL_BIN" verify -config "$CONFIG_FILE" > "$CASE_DIR/$(basename "$CONFIG_FILE" .json).verify.json"
    python3 - "$CASE_DIR/$(basename "$CONFIG_FILE" .json).verify.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['verified'] is True
PY
}

assert_file() { test -s "$OUT_DIR/$1" || { echo "文件缺失或为空：$OUT_DIR/$1" >&2; exit 1; }; }
assert_absent() { test ! -e "$OUT_DIR/$1" || { echo "不应输出：$OUT_DIR/$1" >&2; exit 1; }; }
assert_pem() {
    assert_file "$1"
    local first
    IFS= read -r first < "$OUT_DIR/$1"
    test "$first" = "-----BEGIN $2-----" || { echo "$1 PEM 类型错误：$first" >&2; exit 1; }
}
assert_report_algorithm() {
    python3 - "$OUT_DIR/report.json" "$1" "$2" <<'PY'
import json,sys
report,name,want=sys.argv[1:]
items=json.load(open(report))['certificates']
got=next((x['algorithm'] for x in items if x['name']==name),None)
assert got==want, f'{name}: expected {want}, got {got}'
PY
}
assert_oid() {
    python3 - "$OUT_DIR/$1" "$2" <<'PY'
import base64,re,sys
path,oid=sys.argv[1:]
text=open(path,'rb').read()
m=re.search(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----',text,re.S)
assert m, f'{path}: invalid PEM'
der=base64.b64decode(re.sub(rb'\s',b'',m.group(1)),validate=True)
parts=list(map(int,oid.split('.')))
def enc(n):
 out=[n&127];n>>=7
 while n: out.insert(0,128|(n&127));n>>=7
 return bytes(out)
body=enc(parts[0]*40+parts[1])+b''.join(enc(x) for x in parts[2:])
assert len(body)<128
assert bytes([6,len(body)])+body in der, f'{path}: OID {oid} not found'
PY
}
assert_rsa_chain() {
    local chain=$CASE_DIR/rsa-chain.pem
    : > "$chain"
    for cert in "$OUT_DIR"/inter*.crt; do
        if test -e "$cert"; then cat "$cert" >> "$chain"; fi
    done
    if test -s "$chain"; then
        openssl verify -CAfile "$OUT_DIR/root.crt" -untrusted "$chain" "$OUT_DIR/user.crt" > "$CASE_DIR/openssl-verify.txt"
    else
        openssl verify -CAfile "$OUT_DIR/root.crt" "$OUT_DIR/user.crt" > "$CASE_DIR/openssl-verify.txt"
    fi
    grep -q 'OK$' "$CASE_DIR/openssl-verify.txt"
}

case_pass() { echo "[$CASE_ID] 通过：$1"; }
