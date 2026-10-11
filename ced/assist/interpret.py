"""解读层 —— 判定**已经给出之后**，让模型把证据翻译成人话。

它是模型在引擎里的**唯一位置**：跑在内核**后面**（把已经定好的结论讲清楚）。

为什么这一层不可能污染判定 —— 三条硬约束，任何一条被绕过都不成立：

  1. **时机**：它只在 ``judge`` 出完级之后被调用，看不到也改不了级别；
  2. **形状**：``Interpretation`` 里**没有任何判定字段**（没有 level、没有 verdict），
     模型多写出来的键（例如它自作主张塞的 ``"level": "security"``）在
     ``parse_interpretation`` 里被**直接丢掉**，不进任何结构；
  3. **降级**：没配模型 / 调用失败 / 输出不成 JSON —— 一律返回 ``ok=False``，
     调用方保留内核原来的模板文案，绝不让"模型没答上来"影响报告。

所以本模块对报告只做**加法**：原有那几行确定性文案一行不动，模型说的话另起一栏、
明确标注"非判定"。
"""
from __future__ import annotations

from dataclasses import dataclass

from .client import LlmClient, LlmUnavailable
from .schema import extract_json

#: 只认这三个键 —— 其余（包括模型幻觉出来的 level / cwe / verdict）一律丢弃
INTERPRET_KEYS = ("impact", "cwe_hint", "fix")

#: 每段文字的长度上限，防止一段话把报告刷爆
MAX_LEN = {"impact": 400, "cwe_hint": 160, "fix": 400}

SYSTEM_PROMPT = """你是 CED（语义差分漏洞挖掘引擎）报告的解读者，不是判定者。

判定已经由确定性内核用「差分 + 消融实验」给出并写死在输入里了。你的任务只有一件：
把这份已经定好的证据**翻译成人能读懂的中文**，让读者不用看字段名也能明白发生了什么。

硬性约束：
1. **不得改变级别**。输入里是什么级别就是什么级别，不许升级、不许降级、不许说"其实这是误报"。
2. **不得声称发现了新的漏洞**，也不得引入输入里没有的事实（不要编 CVE 编号、不要编具体的攻击载荷）。
3. CWE 归属只作为**建议**：可以指出输入给的 CWE 是否贴切、有没有更贴切的类别；不确定就留空字符串。
4. 只输出一个 JSON 对象，不要解释文字、不要 Markdown 围栏，形如：
{"impact": "一到三句话讲清楚：这个分歧在真实拓扑下意味着什么后果", "cwe_hint": "CWE-xxx 类别名（不确定就留空）", "fix": "一到三句话的可执行修复建议"}
5. 用中文，术语可以保留英文。不要复述字段名，不要写成"根据输入"这类套话。"""


@dataclass(frozen=True)
class Interpretation:
    """一段模型解读。``ok=False`` 表示这段解读不可用，调用方应保留内核原文案。"""

    impact: str = ""
    cwe_hint: str = ""
    fix: str = ""
    model: str = ""
    ok: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {"impact": self.impact, "cwe_hint": self.cwe_hint,
                "fix": self.fix, "model": self.model, "ok": self.ok,
                "error": self.error}


def _clean(value: object, limit: int) -> str:
    """任何形态的取值都压成一行纯文本：非字符串先转字符串，空白折叠，超长截断。"""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    text = " ".join(value.split())
    return text[:limit]


def parse_interpretation(text: str) -> Interpretation:
    """模型输出 → ``Interpretation``。

    只读 ``INTERPRET_KEYS`` 里的三个键，其余键**全部丢弃** —— 这是"模型改不了判定"
    在类型层面的落点。拿不到 JSON 对象时抛 ``ValueError``。
    """
    obj = extract_json(text or "")
    if isinstance(obj, list):
        if len(obj) != 1:
            raise ValueError("解读输出必须是单个 JSON 对象")
        obj = obj[0]
    if not isinstance(obj, dict):
        raise ValueError("解读输出不是 JSON 对象")

    fields = {key: _clean(obj.get(key, ""), MAX_LEN[key]) for key in INTERPRET_KEYS}
    if not any(fields.values()):
        raise ValueError("解读输出三个字段都是空的")
    return Interpretation(**fields, ok=True)


def build_prompt(finding: dict) -> str:
    """把内核已经算出的证据摊平给模型看 —— 只给事实，不给它做判定所需的自由。

    刻意只喂判定**结果**与**证据文本**，不喂原始字节：解读不需要重新解析报文，
    拿到字节只会引诱模型自己去做差分（那是内核算的，它做了也算数）。
    """
    rows = [
        ("领域", finding.get("domain", "")),
        ("结论级别（已由内核定死，不得更改）", finding.get("level", "")),
        ("分歧类型", finding.get("kind", "")),
        ("对照的两个实现", f"{finding.get('left', '')} ↔ {finding.get('right', '')}"),
        ("内核给的判定理由", finding.get("reason", "")),
        ("消融证据", finding.get("ablation", "")),
        ("内核给出的安全后果", finding.get("effect", "")),
        ("内核归属的 CWE", finding.get("cwe", "")),
        ("内核归属的攻击场景", finding.get("scenario", "")),
        ("内核给的修复建议", finding.get("fix", "")),
    ]
    body = "\n".join(f"- {label}：{value or '（无）'}" for label, value in rows)
    return ("下面是一条已经定级的发现，请按系统提示把它翻译成人话。\n\n"
            f"{body}\n\n只输出那一个 JSON 对象。")


def interpret(client: LlmClient | None, *, finding: dict,
              temperature: float = 0.2) -> Interpretation:
    """给一条已定级的发现生成解读。

    **永不抛异常**：没配模型、连不上、输出不合形，都返回 ``ok=False`` 的解读，
    由调用方决定保留内核原文案。降级路径与正常路径共用一个入口。
    """
    if client is None or not getattr(client, "available", False):
        return Interpretation(error="未配置模型")

    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(finding)}]
    try:
        text = client.chat(messages, temperature=temperature)
    except LlmUnavailable as exc:
        return Interpretation(error=str(exc))

    try:
        parsed = parse_interpretation(text)
    except ValueError as exc:
        return Interpretation(error=f"解读输出不合形：{exc}")

    return Interpretation(impact=parsed.impact, cwe_hint=parsed.cwe_hint,
                          fix=parsed.fix, model=_model_name(client), ok=True)


def _model_name(client: LlmClient | None) -> str:
    config = getattr(client, "config", None)
    return getattr(config, "model", "") or ""


__all__ = ["INTERPRET_KEYS", "Interpretation", "SYSTEM_PROMPT", "build_prompt",
           "interpret", "parse_interpretation"]
