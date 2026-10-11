"""模型原始输出 → 能用的 JSON。

这里只解决"文本形状"问题：模型爱把 JSON 裹在 Markdown 围栏里、爱在前后加两句
客套话。解读层拿到裸文本后需要的是**可解析的对象**，不是又一层校验 —— 字段该不该
认、超长要不要截断，都由 ``interpret.py`` 按它自己的白名单处理。

所以本模块刻意只留一个纯函数，不做任何与业务字段有关的事。
"""
from __future__ import annotations

import json
import re


def extract_json(text: str) -> object:
    """从模型输出里抠出 JSON。

    容忍三种形态：纯 JSON、`````json`` 围栏、夹在解说文字里的 JSON。
    抠不出来抛 ``ValueError``，由调用方决定怎么降级。
    """
    if not isinstance(text, str):
        raise ValueError("模型输出不是文本")
    for candidate in _candidates(text):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    raise ValueError("模型输出中找不到合法 JSON")


def _candidates(text: str) -> list[str]:
    text = text.strip()
    out = [text]
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        out.append(m.group(1).strip())
    for opener, closer in (("[", "]"), ("{", "}")):
        i, j = text.find(opener), text.rfind(closer)
        if i != -1 and j > i:
            out.append(text[i:j + 1])
    return out


__all__ = ["extract_json"]
