"""LLM 解读层：把大模型限制在"把已定的证据翻译成人话"这一件事上。

包内职责：
  ``client``    OpenAI 兼容 HTTP 客户端（纯 urllib；全包唯一的网络出口）
  ``schema``    模型原始输出 → 可解析的 JSON（只解决文本形状）
  ``interpret`` 解读层：判定出完之后把证据翻成人话，并标注"非判定"

不变式：本包**不产出任何判定**，也不影响搜索方向。``Interpretation`` 里根本没有
level / verdict 这类键，模型多写的键在解析时被直接丢掉；没配模型、调用失败、
输出不合形一律 ``ok=False``，调用方保留内核原文案。

模型在引擎里的位置只有一个：**结论出来之后的解读者**。
"""
from __future__ import annotations

from .client import LlmClient, LlmConfig, LlmUnavailable, config_from_env
from .interpret import (INTERPRET_KEYS, Interpretation, SYSTEM_PROMPT,
                        build_prompt, interpret, parse_interpretation)
from .schema import extract_json

__all__ = [
    "INTERPRET_KEYS", "Interpretation", "LlmClient", "LlmConfig",
    "LlmUnavailable", "SYSTEM_PROMPT", "build_prompt", "config_from_env",
    "extract_json", "interpret", "parse_interpretation",
]
