"""可升级性判定器 —— 平台的知识资产。

核心公式：

    漏洞 ⇔ 语义分歧 ∧ 分歧点攻击者可控 ∧ 存在安全后果

其中「分歧由攻击者可直接发送的字节承载」这一前提，用**消融实验**机械地定位承载者，
而不是靠规则猜测：

    逐条移除请求头 → 重新对两侧求观测 → 若分歧消失，
    则该头就是这个分歧的承载者 —— 而请求头是攻击者可以直接发送的。

注意：消融实验定位的是承载者，不等于证明分歧可被实际利用；
`security` 的含义是「结构性前提成立」，最终结论以实机复现为准。

这一步是抑制"兼容性噪声"的唯一有效过滤器，也是本平台与
"SAST 拿规则命中当结论"的根本区别。
"""
from __future__ import annotations

import re
from typing import Callable

from ..contracts import (LEVEL_COMPAT, LEVEL_SECURITY, LEVEL_UNKNOWN,
                         Divergence, Observation, ProbeRejected, Verdict)
from ..differ.comparator import diff_keys
from .. import httpmsg

#: 评估器签名：(impl_id, payload) -> Observation
Evaluator = Callable[[str, bytes], Observation]


def still_diverges(candidate: bytes, div: Divergence,
                   evaluate: Evaluator, compare_keys: tuple[str, ...]) -> bool:
    """消融实验的判据：把 candidate 重放两侧，看分歧是否仍然存在。

    返回 ``False`` 的分量很重 —— "这个候选让分歧消失了"，于是它会被认定为
    承载者、进而把 boundary 类分歧升级成 ``security``。所以**观测不到的时候
    绝不能返回 False**：真实前置会拒掉一部分消融候选（实测：nginx 1.25.5 在
    抹掉 Content-Length 之后直接 400，根本不转发），这时"分歧是否消失"无从观测，
    凭空返回 False 就是拿兼容性噪声造安全结论。宁可不升级（留给复核），不可滥报。
    """
    try:
        left = evaluate(div.left.impl_id, candidate)
        right = evaluate(div.right.impl_id, candidate)
    except ProbeRejected:
        return True
    return bool(diff_keys(left, right, compare_keys))


_ABSOLUTE_TARGET = re.compile(rb"^[A-Za-z][A-Za-z0-9+.\-]*://[^/]*(\S*)$")


def _request_line_variants(line: bytes) -> list[bytes]:
    """请求行的几种"规范化"写法 —— 请求行与请求头一样，都是攻击者直接发送的。"""
    out: list[bytes] = []
    collapsed = b" ".join(line.split())
    if collapsed != line:
        out.append(collapsed)
    parts = collapsed.split(b" ")
    if len(parts) != 3:
        return out
    method, target, version = parts
    if method != method.upper():
        candidate = b" ".join([method.upper(), target, version])
        if candidate not in out:
            out.append(candidate)
    match = _ABSOLUTE_TARGET.match(target)
    if match:
        candidate = b" ".join([method, match.group(1) or b"/", version])
        if candidate not in out:
            out.append(candidate)
    return out


def ablate_headers(payload: bytes, div: Divergence, evaluate: Evaluator,
                   compare_keys: tuple[str, ...]) -> list[str]:
    """找出「把哪一处改掉，分歧就消失」—— 即这个分歧由谁承载。

    **分帧领域的消融实验**（``Http1FramingAdapter.ablate`` 调用它）。
    覆盖两类攻击者可直接发送的东西：
      * 每一条请求头（移除它）
      * 请求行本身（折叠空白 / 方法大写 / 绝对形式相对化）

    返回人类可读的描述；为空表示定位不到，判定器会保守地给 unknown。
    """
    msg = httpmsg.split(payload)
    if msg is None:
        return []

    def still_diverges_for(candidate: bytes) -> bool:
        return still_diverges(candidate, div, evaluate, compare_keys)

    carriers: list[str] = []

    for index, line in msg.header_lines():
        candidate = httpmsg.drop_line(msg, index).build()
        if candidate != payload and not still_diverges_for(candidate):
            carriers.append(f"移除请求头 `{line.decode('latin-1')}`")

    for variant in _request_line_variants(msg.lines[0]):
        candidate = httpmsg.Message(lines=[variant] + msg.lines[1:],
                                    eol=msg.eol, sep=msg.sep,
                                    tail=msg.tail).build()
        if not still_diverges_for(candidate):
            carriers.append(f"把请求行规范化成 `{variant.decode('latin-1')}`")

    return carriers


def judge(div: Divergence, kind: str, adapter, evaluate: Evaluator) -> Verdict:
    """判定一个分歧能否升级为安全影响。

    **判定权只在这里**：本函数是全仓唯一产出 ``Verdict`` 的地方。
    但"承载者是什么样"是**领域知识**，所以消融实验交给适配器
    （``adapter.ablate``）—— 判定器只负责用它给出的证据下结论。
    """
    boundary_kinds = adapter.boundary_kinds
    meta = adapter.meta(kind)
    keys = [d.key for d in div.diffs]

    # 只有"可能被升级"的类型才跑消融实验 —— 它要把两侧重放很多遍，不便宜
    carriers: list[str] = []
    if kind in boundary_kinds or kind == adapter.kind_acceptance:
        carriers = adapter.ablate(div, evaluate)
    controllable = bool(carriers)
    ablation = None
    if carriers:
        shown = "；".join(carriers[:3])
        more = f"；等 {len(carriers)} 处" if len(carriers) > 3 else ""
        ablation = (f"{shown}{more} —— 分歧消失，"
                    f"说明它由攻击者可直接发送的部分承载")

    if kind in boundary_kinds and controllable:
        level, reason = LEVEL_SECURITY, (
            f"结构字段分歧（{keys}），且消融实验定位到它由攻击者可直接发送的字节承载 "
            f"→ 具备可升级为安全影响的结构性前提（不等于已实机利用）；"
            f"具体后果与 CWE 见领域映射（{meta['cwe'] or '—'}）"
        )
    elif kind in boundary_kinds:
        level, reason = LEVEL_UNKNOWN, (
            f"结构字段分歧（{keys}），但消融实验无法定位到单条可控承载者 "
            f"→ 需人工复核"
        )
    elif kind == adapter.kind_acceptance and controllable:
        level, reason = LEVEL_UNKNOWN, (
            f"接受性分歧且由可控字节承载 → 防护绕过候选，需人工复核（保守不升级）"
        )
    else:
        level, reason = LEVEL_COMPAT, (
            f"仅诊断字段不同（{keys}），参与判定的结构字段一致，无安全后果"
        )

    return Verdict(level=level, kind=kind, reason=reason,
                   cwe=meta["cwe"], scenario=meta["scenario"],
                   controllable=controllable, ablation=ablation,
                   effect=meta["effect"], fix=meta["fix"])
