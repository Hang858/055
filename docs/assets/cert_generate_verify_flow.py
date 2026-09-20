#!/usr/bin/env python3
"""绘制「证书生成与验证流程」示意图（中文，通信双方时序风格）。

与 docs/assets 下 TLS 相关配图风格保持一致：白底、浅绿参与方框、蓝色生命线、黑色箭头。

用法（仓库根目录下执行）：
    python3 docs/assets/cert_generate_verify_flow.py

输出：docs/assets/cert_generate_verify_flow.png
"""
import os
import tempfile
from pathlib import Path

# matplotlib 需要可写的配置目录，不可写时退回到临时目录，避免告警噪音
try:
    os.makedirs(Path.home() / ".config" / "matplotlib", exist_ok=True)
except OSError:
    os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="mplconfig-"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

plt.rcParams["font.sans-serif"] = [
    "Noto Sans CJK SC",
    "Noto Sans CJK JP",
    "Source Han Sans SC",
    "WenQuanYi Zen Hei",
    "Droid Sans Fallback",
    "DejaVu Sans",
]
plt.rcParams["axes.unicode_minus"] = False

GREEN = "#d9ead3"   # 参与方标题框底色
BLUE = "#2e75b6"    # 生命线
BLACK = "#000000"
FS = 11.5

XA, XB = 0.24, 0.76          # 两条生命线的横向位置
Y_TOP, Y_BOTTOM = 0.855, 0.05  # 生命线上下端
Y_ARROW_1, Y_ARROW_2 = 0.70, 0.38


def party_box(ax, x, label):
    """参与方标题框：浅绿圆角矩形。"""
    ax.add_patch(
        FancyBboxPatch(
            (x - 0.085, 0.855),
            0.17,
            0.11,
            boxstyle="round,pad=0.010,rounding_size=0.030",
            linewidth=1.0,
            edgecolor=BLACK,
            facecolor=GREEN,
            zorder=3,
        )
    )
    ax.text(x, 0.910, label, ha="center", va="center", fontsize=FS + 1.0, color=BLACK, zorder=4)


def arrow(ax, x0, x1, y, label):
    """带实心箭头的消息箭头，文字标注在箭头上方。"""
    ax.add_patch(
        FancyArrowPatch(
            (x0, y),
            (x1, y),
            arrowstyle="-|>",
            mutation_scale=16,
            linewidth=1.6,
            color=BLACK,
            shrinkA=0,
            shrinkB=0,
            zorder=3,
        )
    )
    ax.text((x0 + x1) / 2, y + 0.035, label, ha="center", va="bottom", fontsize=FS, color=BLACK)


def side_note(ax, x, y, text, ha):
    """生命线外侧的本地操作说明。"""
    ax.text(x, y, text, ha=ha, va="top", fontsize=FS, color=BLACK, linespacing=1.5)


def main():
    fig, ax = plt.subplots(figsize=(8.0, 3.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)

    # 参与方与生命线
    for x, name in ((XA, "通信方A"), (XB, "通信方B")):
        ax.plot([x, x], [Y_TOP, Y_BOTTOM], color=BLUE, linewidth=1.5, zorder=1)
        party_box(ax, x, name)

    # 消息交互
    arrow(ax, XA, XB, Y_ARROW_1, "提交公钥PK（证书请求）")
    arrow(ax, XB, XA, Y_ARROW_2, "发送证书Cert")

    # 本地操作
    side_note(ax, 0.015, 0.78, "生成密钥对\n（SK，PK）", "left")
    side_note(ax, XB + 0.025, 0.60, "用抗量子签名私钥\n对证书TBS签名，\n生成证书Cert", "left")
    side_note(ax, 0.015, 0.26, "用签发者公钥验签，\n得到证书公钥PK", "left")

    out = Path(__file__).resolve().parent / "cert_generate_verify_flow.png"
    fig.savefig(out, dpi=200, facecolor="white")
    plt.close(fig)
    print("已生成:", out)


if __name__ == "__main__":
    main()
