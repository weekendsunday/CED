"""产物落盘：报告 / 结果 JSON / PoC 脚本 / 固化语料 —— 一律写 LF。

为什么值得单独一个函数：这些文件都对外声称"可由一条命令**逐字节**重建"。若行尾跟着
平台走（Windows 上 ``Path.write_text`` 默认把 ``\\n`` 翻成 ``\\r\\n``），同一份语料在
两台机器上生成的东西就不一样，"逐字节一致"当场失效；而且每次重建都会把整份文件在
git 里翻一遍，review 时看不出真正改了什么。

只覆盖**产物**。``ced-settings.json``、捕获记录这类本机私有文件不走这里 ——
它们被 .gitignore 挡着，行尾不构成跨机器差异。
"""
from __future__ import annotations

from pathlib import Path

#: 文本产物统一用这个编码与行尾（写入时不翻译换行）
ENCODING = "utf-8"
NEWLINE = "\n"


def write_text(path: str | Path, text: str) -> Path:
    """写一个文本产物，固定 LF 行尾。返回写到的路径。"""
    path = Path(path)
    path.write_text(text, encoding=ENCODING, newline=NEWLINE)
    return path


__all__ = ["ENCODING", "NEWLINE", "write_text"]
