"""验证层的数据契约 —— 「待验证的假设」与「验证结论」。

外部扫描器（nuclei / Burp / HAR / curl / 普通清单）产出的是**线索**，
不是结论。这里把它们统一成 :class:`Hypothesis`，再经同一条差分 oracle 链
得到三态的 :class:`Verification`（已证实 / 未证实 / 证不了）。

「未证实」是保守口径：只表示**试过的这些领域里看不出分歧**，不等于这条发现是假的。

和模型解读层同一个哲学：模型/外部扫描器自述的内容只是输入，
是否成立必须由**确定性差分**重新判定，而不是采信它们的 severity。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    """一条「待验证的假设」—— 外部扫描器说这里可能有问题。"""

    source: str          # nuclei | burp | har | curl | list | manual
    target: str          # 一条 URL 或一个裸目标
    raw: str = ""        # 原始素材（可能含完整请求字节）
    note: str = ""


@dataclass(frozen=True)
class Verification:
    """一条假设喂进 oracle 链之后的结论。"""

    hypothesis: Hypothesis
    verdict: str         # confirmed | refuted | unverifiable
    domain: str = ""     # 在哪个领域验证的
    left: str = ""       # 该领域的左实现
    right: str = ""
    level: str = ""      # security | unknown | compatibility
    severity: str = ""   # 五档危险等级（档位由类型上限 + 证据强度定，与 level 正交）
    kind: str = ""
    reason: str = ""
    evidence: str = ""   # 消融证据
    quantified: str = "" # 链路量化的描述（量化不出来时为空）
    payload: bytes | None = None   # 实际喂进去的待测对象（用来算"修复形态"）
    minimized_b64: str | None = None
    detail: str = ""     # 人话说明（尤其是 unverifiable/refuted 的原因）


__all__ = ["Hypothesis", "Verification"]
