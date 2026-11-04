#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中间盒模拟代理（TLS-2-7 第 4 步）

在客户端与 tlsbench 服务端之间转发 TCP，并按策略模拟现网中间盒的行为：
  size-drop        转发时丢弃超过 --limit 字节的 TCP 段（模拟只认标准 MSS 的防火墙/NAT）
  first-segment-only  每条连接只转发客户端第一个 TCP 段，随后断开（模拟只解析首段的浅解析设备）
  size-drop+loss   在 size-drop 基础上按 --loss 百分比随机丢弃数据（模拟有损链路）

用法：
  python3 tools/tls_middlebox.py --listen 127.0.0.1:8100 --upstream 192.168.2.165:8099 \
      --policy size-drop --limit 1455 --stats /tmp/mb.json

代理本身不做 TLS 解析，只按字节流长度/首段/概率决定转发或断开；收到 SIGTERM/SIGINT 时
把统计（accepted/ok/aborted/bytes_dropped）以 JSON 输出到 stdout 和 --stats 文件。
"""
import argparse
import asyncio
import json
import random
import signal
import sys


class Stats:
    def __init__(self):
        self.accepted = 0
        self.ok = 0
        self.aborted = 0
        self.bytes_dropped = 0
        self.reasons = {}

    def bump(self, reason, nbytes=0):
        self.aborted += 1
        self.bytes_dropped += nbytes
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


async def handle(client_reader, client_writer, args, stats):
    stats.accepted += 1
    aborted = False
    try:
        up_reader, up_writer = await asyncio.open_connection(args.upstream_host, args.upstream_port)
    except Exception as exc:  # 上游不可达
        print("上游连接失败: %s" % exc, file=sys.stderr)
        stats.bump("upstream-error")
        client_writer.close()
        return

    first_chunk = True

    async def client_to_upstream():
        nonlocal aborted, first_chunk
        while True:
            data = await client_reader.read(65536)
            if not data:
                break
            if args.policy == "first-segment-only":
                if not first_chunk:
                    aborted = True
                    stats.bump("first-segment-only", len(data))
                    return
                first_chunk = False
                up_writer.write(data)
                await up_writer.drain()
                # 只转首段：立刻断开，后续报文不再转发
                aborted = True
                stats.bump("first-segment-only")
                return
            if args.policy in ("size-drop", "size-drop+loss"):
                if len(data) > args.limit:
                    aborted = True
                    stats.bump("size-drop", len(data))
                    return
                if args.policy == "size-drop+loss" and random.random() < args.loss / 100.0:
                    aborted = True
                    stats.bump("loss", len(data))
                    return
            up_writer.write(data)
            await up_writer.drain()

    async def upstream_to_client():
        while True:
            data = await up_reader.read(65536)
            if not data:
                break
            client_writer.write(data)
            await client_writer.drain()

    tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in (up_writer, client_writer):
            try:
                writer.close()
            except Exception:
                pass
    if aborted:
        return
    stats.ok += 1


def write_stats(args, stats):
    result = {
        "policy": args.policy,
        "limit": args.limit,
        "loss": args.loss,
        "accepted": stats.accepted,
        "ok": stats.ok,
        "aborted": stats.aborted,
        "bytes_dropped": stats.bytes_dropped,
        "reasons": stats.reasons,
    }
    text = json.dumps(result, ensure_ascii=False)
    if args.stats:
        try:
            with open(args.stats, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as exc:
            print("写统计文件失败: %s" % exc, file=sys.stderr)
    return text


async def handle_and_count(reader, writer, args, stats):
    try:
        await handle(reader, writer, args, stats)
    finally:
        write_stats(args, stats)


async def main_async(args, stats):
    server = await asyncio.start_server(
        lambda r, w: handle_and_count(r, w, args, stats), args.listen_host, args.listen_port
    )
    print("middlebox: listen=%s:%d upstream=%s:%d policy=%s limit=%d loss=%.1f%%"
          % (args.listen_host, args.listen_port, args.upstream_host,
             args.upstream_port, args.policy, args.limit, args.loss), file=sys.stderr)
    stop = asyncio.Event()

    def shutdown():
        stop.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            signal.signal(sig, lambda *_: shutdown())

    async with server:
        serve = asyncio.create_task(server.serve_forever())
        await stop.wait()
        serve.cancel()
        await asyncio.gather(serve, return_exceptions=True)


def main():
    ap = argparse.ArgumentParser(description="中间盒模拟代理（TLS-2-7 中间盒鲁棒性）")
    ap.add_argument("--listen", default="127.0.0.1:8100", help="监听地址 host:port")
    ap.add_argument("--upstream", required=True, help="上游服务端 host:port")
    ap.add_argument("--policy", required=True,
                    choices=["size-drop", "first-segment-only", "size-drop+loss"])
    ap.add_argument("--limit", type=int, default=1455, help="size-drop 的最大转发长度（字节）")
    ap.add_argument("--loss", type=float, default=1.0, help="size-drop+loss 的丢包百分比（0-100）")
    ap.add_argument("--stats", default="", help="把统计 JSON 写入该文件")
    args = ap.parse_args()

    args.listen_host, _, port = args.listen.partition(":")
    args.listen_port = int(port or 8100)
    args.upstream_host, _, uport = args.upstream.partition(":")
    args.upstream_port = int(uport or 8099)

    stats = Stats()
    try:
        asyncio.run(main_async(args, stats))
    except KeyboardInterrupt:
        pass
    result = {
        "policy": args.policy,
        "limit": args.limit,
        "loss": args.loss,
        "accepted": stats.accepted,
        "ok": stats.ok,
        "aborted": stats.aborted,
        "bytes_dropped": stats.bytes_dropped,
        "reasons": stats.reasons,
    }
    text = json.dumps(result, ensure_ascii=False)
    print(text)
    if args.stats:
        try:
            with open(args.stats, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as exc:
            print("写统计文件失败: %s" % exc, file=sys.stderr)


if __name__ == "__main__":
    main()
