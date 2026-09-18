#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 TLS 1.3 握手报文：ClientHello / ServerHello 的 supported_groups 与 key_share。

用途
----
对应 TLS 协议源码库测试用例：
  * TLS-1-4 ClientHello 消息格式验证
  * TLS-1-5 ServerHello 消息格式验证
  * 新增用例「混合密钥拼接结构验证」

为什么用长度就能验证拼接
------------------------
RFC 9954《Hybrid Key Exchange in TLS 1.3》：
  §3.2 “the key_exchange field of a KeyShareEntry is the concatenation of the
        key_exchange field for each of the constituent algorithms. The order of
        shares in the concatenation MUST be the same as the order of algorithms
        indicated in the definition of the NamedGroup.”
  §3.3 “concatenated_shared_secret = MyECDH.shared_secret || MyPQKEM.shared_secret”
即：混合组的 key_exchange = 各分量**直接拼接、不带长度字段**，各分量长度固定。
因此 “ClientHello 的 key_share 长度 == 经典分量长度 + 抗量子分量长度” 即可判定拼接正确。

依赖
----
纯标准库，无需 tshark / dpkt。支持 classic pcap（tcpdump / tshark -w 的默认输出格式），
链路层支持 Ethernet / Linux SLL / Linux SLL2 / RAW IP，网络层支持 IPv4，传输层 TCP。

用法
----
    python3 tools/tls_hello_check.py capture.pcap
    python3 tools/tls_hello_check.py capture.pcap --expect X25519Kyber1024Draft00
    python3 tools/tls_hello_check.py capture.pcap --port 8099 --json result.json

抓包（需要 root 或 CAP_NET_RAW，二者其一）：
    sudo tshark -i lo -f "tcp port 8099" -w capture.pcap
    sudo tcpdump -i lo -w capture.pcap "tcp port 8099"
"""

import argparse
import json
import struct
import sys
from collections import OrderedDict

# ---------------------------------------------------------------- 组名与期望长度
# key_share 期望长度 = 各分量拼接后的总字节数
#   client(CH) = Σ 各分量公钥长度；server(SH) = Σ 各分量密文长度
# 其中 (EC)DH 分量的“密文”是服务端自己的临时公钥（RFC 9954 §3.2）。
# HQC 长度取自 liboqs kem_hqc.h；Kyber/SM2 取自 CIRCL 参数表。
GROUPS = {
    0x001d: ("X25519",                    32,        32),
    0x0017: ("P-256",                     65,        65),
    0x11ec: ("X25519MLKEM768",            1184 + 32, 1088 + 32),   # CIRCL 中 ML-KEM 在前
    0x6399: ("X25519Kyber768Draft00",     32 + 1184, 32 + 1088),
    0xfe30: ("X25519Kyber512Draft00",     32 + 800,  32 + 768),
    0xfe31: ("X25519Kyber768Draft00Old",  32 + 1184, 32 + 1088),
    0xfe32: ("P256Kyber768Draft00",       65 + 1184, 65 + 1088),
    0xfe33: ("DummyKex",                  32,        32),           # 仅用于触发 HRR
    0xfe34: ("SM2Kyber512Draft00",        65 + 800,  129 + 768),
    0xfe35: ("SM2Kyber768Draft00",        65 + 1184, 129 + 1088),
    0xfe36: ("X25519Kyber1024Draft00",    32 + 1568, 32 + 1568),
    0xfe37: ("SM2Kyber1024Draft00",       65 + 1568, 129 + 1568),
    0xfe38: ("X25519HQC-128",             32 + 2249, 32 + 4433),
    0xfe39: ("X25519HQC-256",             32 + 7245, 32 + 14421),
}

HANDSHAKE_TYPE = {1: "ClientHello", 2: "ServerHello"}
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
# 注意：TLS 1.3 的扩展号 —— supported_groups 是 10，supported_versions 是 43，
# key_share 是 51（RFC 8446 §4.2）。
EXT_SUPPORTED_GROUPS = 10
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def version_name(v):
    return TLS_VERSIONS.get(v, "0x%04x" % v)


def group_name(gid):
    return GROUPS.get(gid, ("未知组(0x%04x)" % gid, None, None))[0]


# ---------------------------------------------------------------- pcap 读取
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),   # 小端, 微秒
    b"\xa1\xb2\xc3\xd4": (">", 1000000),   # 大端, 微秒
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),  # 小端, 纳秒
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),  # 大端, 纳秒
}


def read_pcapng(path):
    """极简 pcapng 读取：只取 SHB/IDB/EPB 块（tshark -w 的默认格式）。"""
    with open(path, "rb") as f:
        data = f.read()
    endian = "<"
    linktype = 1
    out = []
    pos = 0
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:                       # SHB
            bom = struct.unpack("<I", data[pos + 8:pos + 12])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + blen - 4] if blen >= 12 else b""
        if btype == 0x00000001 and len(body) >= 8:    # IDB
            linktype = struct.unpack(endian + "H", body[:2])[0]
        elif btype == 0x00000006 and len(body) >= 20:  # EPB
            # body: interface_id(4) ts_high(4) ts_low(4) caplen(4) origlen(4) data...
            _, ts_hi, ts_lo, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            ts = ((ts_hi << 32) | ts_lo) / 1e6
            out.append((ts, body[20:20 + caplen]))
        if blen < 12:
            break
        pos += blen
    return linktype, out


def read_pcap(path):
    """返回 (linktype, [(ts, payload), ...])；自动识别 classic pcap / pcapng。"""
    with open(path, "rb") as f:
        head = f.read(4)
    if head == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(path)
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise SystemExit("文件太小，不是有效 pcap：%s" % path)
    magic = data[:4]
    if magic not in PCAP_MAGICS:
        raise SystemExit("无法识别的文件格式（magic=%s）" % magic.hex())
    endian, _ = PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off, out = 24, []
    while off + 16 <= len(data):
        ts_s, ts_u, caplen, wirelen = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        out.append((ts_s + ts_u / 1e6, data[off:off + caplen]))
        off += caplen
    return linktype, out


def strip_link_layer(linktype, buf):
    """剥掉链路层，返回 IP 报文（IPv4/IPv6）。"""
    if linktype == 1:      # Ethernet
        if len(buf) < 14:
            return None
        ethertype = struct.unpack("!H", buf[12:14])[0]
        off = 14
        while ethertype in (0x8100, 0x88A8):   # VLAN
            ethertype = struct.unpack("!H", buf[off + 2:off + 4])[0]
            off += 4
        if ethertype == 0x0800:
            return buf[off:]
        if ethertype == 0x86DD:
            return buf[off:]
        return None
    if linktype == 113:    # Linux SLL
        if len(buf) < 16:
            return None
        return buf[16:]
    if linktype == 276:    # Linux SLL2
        if len(buf) < 20:
            return None
        return buf[20:]
    if linktype == 101:    # RAW IP
        return buf
    return None


def parse_tcp(pkt):
    """从 IPv4 报文里取 (src, sport, dst, dport, seq, payload)。"""
    if not pkt or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl + 20 or pkt[9] != 6:      # 必须是 TCP
        return None
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    sport, dport, seq = struct.unpack("!HHI", pkt[ihl:ihl + 8])
    data_off = (pkt[ihl + 12] >> 4) * 4
    payload = pkt[ihl + data_off:]
    return src, sport, dst, dport, seq, payload


def reassemble(segments):
    """按 seq 排序拼接同一方向的 TCP 流（环回抓包，无重传/乱序）。"""
    if not segments:
        return b""
    segments = sorted(set(segments))
    base = segments[0][0]
    out = bytearray()
    for seq, payload in segments:
        off = seq - base
        if off < 0:
            continue
        if off > len(out):      # 中间有空洞，保守放弃空洞后的数据
            break
        out[off:off + len(payload)] = payload
    return bytes(out)


# ---------------------------------------------------------------- TLS 解析
def parse_handshake_messages(stream, init_type=None):
    """从 TCP 流里抽出 (handshake_type, body) 列表，跨 record 组装。"""
    msgs, buf, pos = [], b"", 0
    while pos + 5 <= len(stream):
        ctype = stream[pos]
        rec_len = struct.unpack("!H", stream[pos + 3:pos + 5])[0]
        body = stream[pos + 5:pos + 5 + rec_len]
        if len(body) < rec_len:
            break
        pos += 5 + rec_len
        if ctype != 22:          # 只看 handshake record
            continue
        buf += body
        while len(buf) >= 4:
            htype = buf[0]
            hlen = int.from_bytes(buf[1:4], "big")
            if len(buf) < 4 + hlen:
                break
            msgs.append((htype, buf[4:4 + hlen]))
            buf = buf[4 + hlen:]
    return msgs


def parse_extensions(data):
    ext = OrderedDict()
    if len(data) < 2:
        return ext
    total = struct.unpack("!H", data[:2])[0]
    pos = 2
    end = min(2 + total, len(data))
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", data[pos:pos + 4])
        ext[etype] = data[pos + 4:pos + 4 + elen]
        pos += 4 + elen
    return ext


def parse_supported_groups(body):
    """supported_groups(43) → [group id]"""
    if len(body) < 2:
        return []
    n = struct.unpack("!H", body[:2])[0]
    return [struct.unpack("!H", body[2 + 2 * i:4 + 2 * i])[0] for i in range(n)
            if 4 + 2 * i <= len(body)]


def parse_supported_versions_client(body):
    """supported_versions(43) 客户端 → [version]（1 字节列表长度 + 若干 u16）"""
    if len(body) < 1:
        return []
    n = body[0]
    return [struct.unpack("!H", body[1 + 2 * i:3 + 2 * i])[0] for i in range(n // 2)
            if 3 + 2 * i <= len(body)]


def parse_supported_versions_server(body):
    """supported_versions(43) 服务端 → 选中的 version（单个 u16，无长度前缀）"""
    if len(body) < 2:
        return None
    return struct.unpack("!H", body[:2])[0]


def parse_key_share_client(body):
    """key_share(51) 客户端 → [(group, share_len)]"""
    out = []
    if len(body) < 2:
        return out
    total = struct.unpack("!H", body[:2])[0]
    pos, end = 2, min(2 + total, len(body))
    while pos + 4 <= end:
        gid, klen = struct.unpack("!HH", body[pos:pos + 4])
        out.append((gid, klen))
        pos += 4 + klen
    return out


def parse_key_share_server(body):
    """key_share(51) 服务端 → (group, share_len)"""
    if len(body) < 4:
        return None
    gid, klen = struct.unpack("!HH", body[:4])
    return gid, klen


def parse_client_hello(body):
    if len(body) < 34:
        return None
    legacy_version = struct.unpack("!H", body[:2])[0]
    random = body[2:34]
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    cs_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    cipher_suites = [struct.unpack("!H", body[pos + 2 * i:pos + 2 * i + 2])[0]
                     for i in range(cs_len // 2)]
    pos += cs_len
    comp_len = body[pos]
    pos += 1 + comp_len
    ext = parse_extensions(body[pos:])
    return {
        "legacy_version": "0x%04x" % legacy_version,
        "random": random.hex(),
        "cipher_suites": cipher_suites,
        "supported_versions": parse_supported_versions_client(ext.get(EXT_SUPPORTED_VERSIONS, b"")),
        "supported_groups": parse_supported_groups(ext.get(EXT_SUPPORTED_GROUPS, b"")),
        "key_shares": parse_key_share_client(ext.get(EXT_KEY_SHARE, b"")),
        "has_key_share_ext": EXT_KEY_SHARE in ext,
    }


def parse_server_hello(body):
    if len(body) < 38:
        return None
    legacy_version = struct.unpack("!H", body[:2])[0]
    random = body[2:34]
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    cipher_suite = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    pos += 1                                   # compression
    ext = parse_extensions(body[pos:])
    ks = parse_key_share_server(ext.get(EXT_KEY_SHARE, b"")) if EXT_KEY_SHARE in ext else None
    return {
        "legacy_version": "0x%04x" % legacy_version,
        "random": random.hex(),
        "is_hello_retry_request": random == HRR_RANDOM,
        "selected_version": parse_supported_versions_server(ext.get(EXT_SUPPORTED_VERSIONS, b"")),
        "cipher_suite": "0x%04x" % cipher_suite,
        "key_share": ks,
    }


def analyze(path, port=None):
    linktype, packets = read_pcap(path)
    streams = OrderedDict()      # (src,sport,dst,dport) -> [(seq, payload)]
    for _, buf in packets:
        ip = strip_link_layer(linktype, buf)
        info = parse_tcp(ip) if ip else None
        if not info:
            continue
        src, sport, dst, dport, seq, payload = info
        if port and port not in (sport, dport):
            continue
        if not payload:
            continue
        streams.setdefault((src, sport, dst, dport), []).append((seq, payload))

    result = {"file": path, "linktype": linktype, "client_hello": None,
              "server_hello": None, "server_hellos": []}
    for key, segs in streams.items():
        stream = reassemble(segs)
        for htype, body in parse_handshake_messages(stream):
            if htype == 1 and result["client_hello"] is None:
                ch = parse_client_hello(body)
                if ch:
                    ch["from"] = "%s:%d -> %s:%d" % key
                    result["client_hello"] = ch
            elif htype == 2:
                sh = parse_server_hello(body)
                if sh:
                    sh["from"] = "%s:%d -> %s:%d" % key
                    result["server_hellos"].append(sh)
                    if not sh["is_hello_retry_request"] and result["server_hello"] is None:
                        result["server_hello"] = sh
    return result


# ---------------------------------------------------------------- 输出
def check_key_share(role, gid, klen):
    name, ch_len, sh_len = GROUPS.get(gid, (None, None, None))
    if name is None:
        return "  ⚠️  组 0x%04x 不在已知表中，无法核对长度" % gid, False
    expect = ch_len if role == "CH" else sh_len
    ok = (expect == klen)
    mark = "✅" if ok else "❌"
    return ("  %s %s key_share: 组=0x%04x(%s) 长度=%d，期望 %d"
            % (mark, role, gid, name, klen, expect)), ok


def main():
    ap = argparse.ArgumentParser(description="解析 TLS 握手报文（ClientHello/ServerHello）")
    ap.add_argument("pcap", help="pcap 文件（tcpdump/tshark -w 输出）")
    ap.add_argument("--port", type=int, default=None, help="只分析该 TCP 端口")
    ap.add_argument("--expect", default=None,
                    help="断言最终协商的组名（如 X25519Kyber1024Draft00）")
    ap.add_argument("--json", default=None, help="把结构化结果写入 JSON 文件")
    args = ap.parse_args()

    r = analyze(args.pcap, args.port)
    ch, sh = r["client_hello"], r["server_hello"]
    all_ok = True

    print("=" * 72)
    print("TLS 握手报文分析: %s  (linktype=%d)" % (r["file"], r["linktype"]))
    print("=" * 72)

    if not ch:
        print("❌ 未在抓包中找到 ClientHello")
        return 2
    print("\n【ClientHello】来自 %s" % ch["from"])
    print("  legacy_version(记录层显示值): %s" % ch["legacy_version"])
    print("  支持的协议版本(supported_versions): %s"
          % (", ".join(version_name(v) for v in ch["supported_versions"]) or "未携带"))
    print("  密码套件数: %d（首个: %s）" % (len(ch["cipher_suites"]),
                                      "0x%04x" % ch["cipher_suites"][0] if ch["cipher_suites"] else "-"))
    print("  supported_groups(%d 个):" % len(ch["supported_groups"]))
    for gid in ch["supported_groups"]:
        print("    - 0x%04x  %s" % (gid, group_name(gid)))
    print("  key_share(%d 个，按客户端偏好降序):" % len(ch["key_shares"]))
    for gid, klen in ch["key_shares"]:
        line, ok = check_key_share("CH", gid, klen)
        print(line)
        all_ok = all_ok and ok
        name = group_name(gid)
        if klen and "+" in name or klen > 32:
            pass
    if not ch["has_key_share_ext"]:
        print("  ⚠️  ClientHello 未携带 key_share 扩展")

    print("\n【ServerHello】共 %d 条（含 HRR）" % len(r["server_hellos"]))
    for i, s in enumerate(r["server_hellos"], 1):
        tag = "HelloRetryRequest" if s["is_hello_retry_request"] else "ServerHello"
        print("  #%d %s  来自 %s" % (i, tag, s["from"]))
        print("      legacy_version=%s  选中版本=%s  cipher_suite=%s"
              % (s["legacy_version"],
                 version_name(s["selected_version"]) if s["selected_version"] else "-",
                 s["cipher_suite"]))
        if s["key_share"]:
            gid, klen = s["key_share"]
            line, ok = check_key_share("SH", gid, klen)
            print("     " + line)
            if not s["is_hello_retry_request"]:
                all_ok = all_ok and ok
                if args.expect and group_name(gid) != args.expect:
                    print("     ❌ 期望协商组为 %s，实际为 %s" % (args.expect, group_name(gid)))
                    all_ok = False
                elif args.expect:
                    print("     ✅ 协商组符合预期: %s" % args.expect)

    if sh:
        gid = sh["key_share"][0] if sh["key_share"] else None
        print("\n【结论】客户端共 offer %d 组，最终协商: %s"
              % (len(ch["supported_groups"]),
                 ("0x%04x %s" % (gid, group_name(gid))) if gid else "无 key_share"))

    print("\n总判定: %s" % ("✅ 全部通过" if all_ok else "❌ 存在不符项"))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(r, f, ensure_ascii=False, indent=2)
        print("结构化结果已写入: %s" % args.json)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
