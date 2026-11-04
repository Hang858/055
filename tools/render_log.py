#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把终端日志渲染成图片（等宽字体、暗色背景），用于报告附图/截图排版预览。"""
import argparse
import re
import sys
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"

def pick_font(size):
    for idx in range(12):
        try:
            f = ImageFont.truetype(FONT_PATH, size, index=idx)
        except Exception:
            continue
        name = f.getname()[0] if f.getname() else ""
        if "Mono" in name and "CJK" in name:
            return f
    return ImageFont.truetype(FONT_PATH, size, index=0)

def disp_width(s):
    return sum(2 if ord(ch) > 0x2E7F else 1 for ch in s)

def wrap(line, cols):
    out, cur, w = [], "", 0
    for ch in line:
        cw = 2 if ord(ch) > 0x2E7F else 1
        if w + cw > cols:
            out.append(cur)
            cur, w = "    " + ch, 4 + cw
        else:
            cur += ch
            w += cw
    out.append(cur)
    return out or [""]

def color_of(line):
    s = line.strip()
    if s.startswith("$ "):
        return "#4ec9b0"
    if "FAIL" in s or "失败（" in s:
        return "#f48771"
    if "SKIP" in s or "跳过" in s:
        return "#d7ba7d"
    if "断言通过" in s or s.startswith("OK:") or ("步骤" in s and "通过" in s):
        return "#89d185"
    if s.startswith("[") or s.startswith("=====") or (s and set(s) <= {"="}):
        return "#808080"
    return "#d4d4d4"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("out")
    ap.add_argument("--cols", type=int, default=118)
    ap.add_argument("--size", type=int, default=18)
    ap.add_argument("--title", default="")
    args = ap.parse_args()

    lines = []
    with open(args.log, encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.rstrip("\n").replace("\t", "    ")
            raw = re.sub(r"^\[sudo\] password for [^:]+: ", "", raw)
            lines.extend(wrap(raw, args.cols))

    font = pick_font(args.size)
    lh = int(args.size * 1.55)
    pad = 18
    char_w = font.getlength("M")
    width = pad * 2 + int(char_w * args.cols)
    height = pad * 2 + lh * len(lines)
    img = Image.new("RGB", (width, height), "#1e1e1e")
    d = ImageDraw.Draw(img)
    y = pad
    for line in lines:
        d.text((pad, y), line, font=font, fill=color_of(line))
        y += lh
    img.save(args.out)
    print("%s  %dx%d  %d 行" % (args.out, width, height, len(lines)))

if __name__ == "__main__":
    main()
