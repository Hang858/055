#!/usr/bin/env python3
"""最小 pcap 抓包工具（无需 tcpdump/root 系统权限）。

用途：在没有 root、只能进入 user+network namespace 的环境里抓取测试报文，
输出标准 libpcap 文件，供 tools/tls_hello_check.py 解析。

用法：
    python3 tools/pcap_capture.py -i lo -w out.pcap -p 8080 [--all]

    -i  网卡（默认 lo）
    -w  输出 pcap 文件
    -p  只保存 TCP 源/目的端口等于该值的报文（可省略，表示全部）
    --all 等价于省略 -p
说明：运行需要 CAP_NET_RAW（在 user namespace 内以 root 运行即可）。
"""
import argparse
import os
import signal
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

_running = True
_out = None
_pkts = 0


def _stop(signum, frame):
    global _running
    _running = False


def _tcp_port_ok(frame, port):
    if len(frame) < 14:
        return False
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100:  # VLAN
        if len(frame) < 18:
            return False
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if ethertype != 0x0800:
        return False
    if len(frame) < off + 20:
        return False
    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    if proto != 6 or len(frame) < off + ihl + 4:
        return False
    sport, dport = struct.unpack("!HH", frame[off + ihl:off + ihl + 4])
    return sport == port or dport == port


def main():
    global _out, _pkts
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default="lo")
    ap.add_argument("-w", "--write", required=True)
    ap.add_argument("-p", "--port", type=int, default=0)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))
    sock.settimeout(0.2)

    with open(args.write, "wb") as f:
        _out = f
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))
        f.flush()
        while _running:
            try:
                frame = sock.recv(SNAPLEN)
            except socket.timeout:
                continue
            if not args.all and args.port and not _tcp_port_ok(frame, args.port):
                continue
            ts = time.time()
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
            _pkts += 1
            if _pkts % 32 == 0:
                f.flush()
        f.flush()
    sock.close()
    print("captured %d packets -> %s" % (_pkts, args.write), file=sys.stderr)


if __name__ == "__main__":
    main()
