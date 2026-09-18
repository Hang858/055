#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""手工构造异常 ClientHello，验证服务端的异常处理（TLS-1-7 / TLS-1-8）。

模式
----
  bad-version       legacy_version=0x0300 且不带 supported_versions
                    → 期望服务端回 protocol_version 告警（desc=70）
  tls12-only        只支持 TLS 1.2（supported_versions=[0x0303]）
                    → 期望 protocol_version 告警（70）
  unknown-group     supported_groups=[0x1234, 0x001d]，key_share 只含 0x1234
                    → 期望服务端回 HelloRetryRequest，要求 0x001d (X25519)
  no-common-group   supported_groups=[0x1234]（与服务端无交集）
                    → 期望 handshake_failure 告警（desc=40）

用法
----
    # 先起服务端（只支持 X25519，便于观察 HRR）
    cd tls-hybrid/e2e && ../../.build/e2e -cert server_root_cert1.pem \
        -key server_root_key1.pem -ca server_root_cert1.pem -kex X25519 -addr localhost:8099

    python3 tools/tls_abnormal_hello.py --addr localhost:8099 --mode bad-version
    python3 tools/tls_abnormal_hello.py --addr localhost:8099 --mode unknown-group

纯标准库，不需要 tshark/root。
"""

import argparse
import os
import socket
import struct
import sys

ALERT_DESC = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807]


def ext(etype, body):
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello(mode):
    legacy_version = 0x0303
    groups = [0x001d]
    shares = [(0x001d, os.urandom(32))]
    versions = [0x0304]

    if mode == "bad-version":
        legacy_version = 0x0300          # 非法：TLS 1.3 要求 0x0303
        versions = []                    # 并且不带 supported_versions
    elif mode == "tls12-only":
        versions = [0x0303]
    elif mode == "unknown-group":
        groups = [0x1234, 0x001d]        # 未知组在前，X25519 在后
        shares = [(0x1234, os.urandom(32))]
    elif mode == "no-common-group":
        groups = [0x1234]
        shares = [(0x1234, os.urandom(32))]

    body = struct.pack("!H", legacy_version)
    body += os.urandom(32)               # random
    body += b"\x00"                      # session_id
    body += struct.pack("!H", 2) + struct.pack("!H", 0x1301)   # TLS_AES_128_GCM_SHA256
    body += b"\x01\x00"                  # compression: null

    exts = b""
    if versions:
        exts += ext(EXT_SUPPORTED_VERSIONS, bytes([len(versions) * 2]) + b"".join(
            struct.pack("!H", v) for v in versions))
    exts += ext(EXT_SUPPORTED_GROUPS,
                struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups))
    exts += ext(EXT_SIGNATURE_ALGORITHMS,
                struct.pack("!H", len(SIG_ALGS) * 2) + b"".join(struct.pack("!H", s) for s in SIG_ALGS))
    ks = b"".join(struct.pack("!HH", g, len(d)) + d for g, d in shares)
    exts += ext(EXT_KEY_SHARE, struct.pack("!H", len(ks)) + ks)
    body += struct.pack("!H", len(exts)) + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def read_records(sock, limit=8):
    """读若干条 TLS 记录，返回 [(content_type, body)]。"""
    out, buf = [], b""
    sock.settimeout(5)
    while len(out) < limit:
        try:
            chunk = sock.recv(65535)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 5:
            ctype = buf[0]
            rlen = struct.unpack("!H", buf[3:5])[0]
            if len(buf) < 5 + rlen:
                break
            out.append((ctype, buf[5:5 + rlen]))
            buf = buf[5 + rlen:]
    return out


def describe(records):
    """把服务端响应翻译成人类可读结论。"""
    lines, verdict = [], None
    for ctype, body in records:
        if ctype == 21 and len(body) >= 2:                 # alert
            lvl, desc = body[0], body[1]
            lines.append("ALERT level=%d desc=%d(%s)" % (lvl, desc, ALERT_DESC.get(desc, "?")))
            verdict = "alert:%s" % ALERT_DESC.get(desc, desc)
        elif ctype == 22 and len(body) >= 4:               # handshake
            htype = body[0]
            hlen = int.from_bytes(body[1:4], "big")
            hbody = body[4:4 + hlen]
            if htype == 2 and len(hbody) >= 38:            # ServerHello
                random = hbody[2:34]
                is_hrr = random == HRR_RANDOM
                pos = 34
                sid = hbody[pos]
                pos += 1 + sid
                pos += 2 + 1                               # cipher_suite + compression
                selected, version = None, None
                if pos + 2 <= len(hbody):
                    total = struct.unpack("!H", hbody[pos:pos + 2])[0]
                    p, end = pos + 2, min(pos + 2 + total, len(hbody))
                    while p + 4 <= end:
                        et, el = struct.unpack("!HH", hbody[p:p + 4])
                        eb = hbody[p + 4:p + 4 + el]
                        if et == EXT_KEY_SHARE and len(eb) >= 2:
                            selected = struct.unpack("!H", eb[:2])[0]
                        elif et == EXT_SUPPORTED_VERSIONS and len(eb) >= 2:
                            version = struct.unpack("!H", eb[:2])[0]
                        p += 4 + el
                tag = "HelloRetryRequest" if is_hrr else "ServerHello"
                lines.append("%s selected_version=%s key_share_group=%s"
                             % (tag,
                                "0x%04x" % version if version else "-",
                                ("0x%04x" % selected) if selected else "-"))
                verdict = "hrr:0x%04x" % selected if is_hrr and selected else \
                          ("serverhello" if not is_hrr else "hrr")
        else:
            lines.append("record type=%d len=%d" % (ctype, len(body)))
    return lines, verdict


def main():
    ap = argparse.ArgumentParser(description="构造异常 ClientHello 验证服务端异常处理")
    ap.add_argument("--addr", default="localhost:8099")
    ap.add_argument("--mode", required=True,
                    choices=["bad-version", "tls12-only", "unknown-group", "no-common-group"])
    args = ap.parse_args()

    host, _, port = args.addr.rpartition(":")
    hello = build_client_hello(args.mode)
    print("模式: %s   目标: %s   ClientHello %d 字节" % (args.mode, args.addr, len(hello)))

    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(hello)
    records = read_records(s)
    s.close()

    lines, verdict = describe(records)
    for line in lines:
        print("  服务端响应: " + line)

    expect = {
        "bad-version": "alert:protocol_version",
        "tls12-only": "alert:protocol_version",
        "unknown-group": "hrr:0x001d",
        "no-common-group": "alert:handshake_failure",
    }[args.mode]
    ok = verdict == expect
    print("\n判定: %s（期望 %s，实际 %s）" % ("✅ 通过" if ok else "❌ 不符", expect, verdict))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
