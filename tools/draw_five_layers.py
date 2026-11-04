#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""绘制“工具五层架构”图（黑白灰，适配中文设计报告）。"""
from PIL import Image, ImageDraw, ImageFont

REG = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"

def fnt(path, size):
    for i in range(20):
        f = ImageFont.truetype(path, size, index=i)
        name = f.getname()[0]
        if name == "Noto Sans CJK SC":
            return f
    return ImageFont.truetype(path, size, index=0)

LAYERS = [
    ("验证与持久层", ["PEM 保存、证书链校验、证书信息输出"]),
    ("证书签发层", ["根 CA、中间 CA、终端证书分层签发；", "先完成经典签发，再写入抗量子扩展与签名"]),
    ("证书模板层", ["按 X.509 v3 构造证书模板；", "注册抗量子公钥、抗量子签名两个私有扩展"]),
    ("密钥管理层", ["PQKeyPair 统一保存签名密钥、KEM 密钥", "与序列化公钥"]),
    ("算法抽象层", ["PQAlgorithm 枚举；封装 Dilithium/ML-DSA、", "SLH-DSA、Kyber/ML-KEM 的密钥生成、", "序列化与签名接口"]),
]

W, H = 2200, 1560
M = 100
BOX_H = 230
GAP = 70
X0, X1 = 120, W - 120
TITLE_W = 440
FILL = "#F5F5F5"
BORDER = "#333333"
TEXT = "#1A1A1A"
DIV = "#999999"

img = Image.new("RGB", (W, H), "white")
d = ImageDraw.Draw(img)
ft = fnt(BOLD, 56)
fb = fnt(REG, 42)

total_h = BOX_H * len(LAYERS) + GAP * (len(LAYERS) - 1)
y = (H - total_h) // 2

for i, (title, lines) in enumerate(LAYERS):
    d.rectangle([X0, y, X1, y + BOX_H], fill=FILL, outline=BORDER, width=3)
    d.line([X0 + TITLE_W, y + 12, X0 + TITLE_W, y + BOX_H - 12], fill=DIV, width=1)
    # 标题（垂直居中）
    tb = d.textbbox((0, 0), title, font=ft)
    d.text((X0 + 40, y + (BOX_H - (tb[3] - tb[1])) / 2 - tb[1]), title, font=ft, fill=TEXT)
    # 内容（垂直居中，多行）
    line_h = 56
    block_h = line_h * len(lines)
    cy = y + (BOX_H - block_h) / 2
    for ln in lines:
        d.text((X0 + TITLE_W + 40, cy), ln, font=fb, fill=TEXT)
        cy += line_h
    # 向下箭头：上层调用下层
    if i < len(LAYERS) - 1:
        cx = (X0 + X1) // 2
        y1 = y + BOX_H
        y2 = y + BOX_H + GAP
        d.line([cx, y1 + 6, cx, y2 - 14], fill=BORDER, width=5)
        d.polygon([(cx, y2 - 2), (cx - 13, y2 - 20), (cx + 13, y2 - 20)], fill=BORDER)
    y += BOX_H + GAP

img.save("docs/assets/图5-2-工具五层架构.png")
print("saved docs/assets/图5-2-工具五层架构.png", img.size)
