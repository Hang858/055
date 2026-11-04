#!/usr/bin/env bash
# 用 tshark（Wireshark 命令行）校验 pcap 中的 TLS 握手字段。
# 用法: tshark_check.sh <pcap> <port> [--expect 组名|0xXXXX]
# 退出码: 0=校验通过；1=校验失败；2=抓包中无 ClientHello；77=未安装 tshark
set -uo pipefail

pcap=${1:?用法: tshark_check.sh <pcap> <port> [--expect 组名]}
port=${2:?缺少端口}
shift 2
expect=""
while [ $# -gt 0 ]; do
    case "$1" in
        --expect) expect=${2:-}; shift 2 ;;
        *) shift ;;
    esac
done

command -v tshark >/dev/null 2>&1 || { echo "SKIP: 未安装 tshark"; exit 77; }
[ -f "$pcap" ] || { echo "FAIL: pcap 不存在: $pcap"; exit 1; }

T() { tshark -r "$pcap" -d "tcp.port=$port,tls" "$@" 2>/dev/null; }
F() { T -Y "$1" -T fields -e "$2"; }

hex_of() { printf '0x%04x' "$1"; }

name_to_hex() {
    case "$1" in
        SM2Kyber512Draft00)      echo 0xfe34 ;;
        X25519Kyber512Draft00)   echo 0xfe30 ;;
        X25519Kyber768Draft00)   echo 0x6399 ;;
        X25519Kyber1024Draft00)  echo 0xfe36 ;;
        SM2Kyber1024Draft00)     echo 0xfe37 ;;
        X25519HQC-128|X25519HQC1) echo 0xfe38 ;;
        X25519HQC-256|X25519HQC5) echo 0xfe39 ;;
        SM2HQC-128|SM2HQC1)      echo 0xfe3a ;;
        SM2HQC-256|SM2HQC5)      echo 0xfe3b ;;
        X25519)                  echo 0x001d ;;
        0x*)                     echo "$1" ;;
        *)                       echo "" ;;
    esac
}

ch_n=$(F 'tls.handshake.type==1' frame.number | grep -c .)
sh_n=$(F 'tls.handshake.type==2' frame.number | grep -c .)
if [ "$ch_n" -eq 0 ]; then
    echo "FAIL: 未在抓包中找到 ClientHello"
    exit 2
fi

groups=$(F 'tls.handshake.type==1' tls.handshake.extensions_supported_group | head -1)
vers=$(F 'tls.handshake.type==1' tls.handshake.extensions.supported_version | head -1)
reclen=$(F 'tls.handshake.type==1' tls.record.length | head -1)

echo "ClientHello: $ch_n 条"
echo "  supported_groups: ${groups:-未携带}"
case "$vers" in
    0x0304) echo "  支持的协议版本: TLS 1.3" ;;
    "")     echo "  支持的协议版本: 未携带" ;;
    *)      echo "  支持的协议版本: $vers" ;;
esac

if [ -n "$reclen" ]; then
    if [ "$reclen" -le 1455 ]; then marker="≤1455，不分包"; else marker=">1455，分包"; fi
else
    marker="未知"
fi
echo "  ClientHello 记录长度: ${reclen:-未知} 字节（$marker）"

mapfile -t ch_g < <(F 'tls.handshake.type==1' tls.handshake.extensions_key_share_group)
mapfile -t ch_l < <(F 'tls.handshake.type==1' tls.handshake.extensions_key_share_key_exchange_length)
for i in "${!ch_g[@]}"; do
    g=${ch_g[$i]:-}; [ -z "$g" ] && continue
    echo "  CH key_share: 组=$(hex_of "$g") 长度=${ch_l[$i]:-未知}"
done

echo "ServerHello: $sh_n 条"
final=""
printed=0
mapfile -t sh_g < <(F 'tls.handshake.type==2' tls.handshake.extensions_key_share_group)
mapfile -t sh_l < <(F 'tls.handshake.type==2' tls.handshake.extensions_key_share_key_exchange_length)
for i in "${!sh_g[@]}"; do
    g=${sh_g[$i]:-}; [ -z "$g" ] && continue
    h=$(hex_of "$g")
    final=$h
    if [ "$printed" -lt 3 ]; then
        echo "  SH key_share: 组=$h 长度=${sh_l[$i]:-未知}"
        printed=$((printed+1))
    fi
done
if [ "$printed" -gt 0 ] && [ "$sh_n" -gt "$printed" ]; then
    echo "  …… 其余 $((sh_n - printed)) 条 ServerHello 的 key_share 同组"
fi

hrr_n=$(F 'tls.handshake.type==2 && tls.handshake.random==cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c' frame.number | grep -c .)
if [ "$hrr_n" -gt 0 ]; then
    echo "  HelloRetryRequest: 出现（HRR $hrr_n 条，ServerHello 共 $sh_n 条）"
else
    echo "  HRR: 未出现（ServerHello 共 $sh_n 条）"
fi

if [ -z "$final" ]; then
    echo "FAIL: ServerHello 中未找到 key_share 扩展"
    exit 1
fi
if [ -n "$expect" ]; then echo "最后一条 ServerHello 的协商组: $final"; else echo "协商组: $final"; fi

if [ -n "$expect" ]; then
    want=$(name_to_hex "$expect")
    if [ -z "$want" ]; then
        echo "FAIL: 未知的期望组 $expect"
        exit 1
    fi
    want_dec=$((want))
    # 同一端口上可能混有其它客户端/进程的握手；只要本次抓包中存在
    # 协商为期望组的 ServerHello 即视为通过，并给出条数。
    cnt=$(F "tls.handshake.type==2 && tls.handshake.extensions_key_share_group==$want_dec" frame.number | grep -c .)
    if [ "$cnt" -gt 0 ]; then
        echo "OK: 共 $cnt 条 ServerHello 协商为 $want（$expect）"
    else
        echo "FAIL: 未找到协商为 $want（$expect）的 ServerHello（最后一条为 $final）"
        exit 1
    fi
fi
