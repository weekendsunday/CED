"""可升级性判定器 —— 平台的知识资产。

核心公式：

    漏洞 ⇔ 语义分歧 ∧ 分歧点攻击者可控 ∧ 存在安全后果

其中「分歧由攻击者可直接发送的字节承载」这一前提，用**消融实验**机械地定位承载者，
而不是靠规则猜测：

    逐条移除请求头 → 重新对两侧求观测 → 若分歧消失，
    则该头就是这个分歧的承载者 —— 而请求头是攻击者可以直接发送的。

注意：消融实验定位的是承载者，不等于证明分歧可被实际利用；
`security` 的含义是「结构性前提成立」，最终结论以实机复现为准。

第一项（语义分歧）也要真成立：两侧观测**只差写法**（ASCII 字母大小写、参数书写顺序）
时判定停在 `unknown`（见 :func:`writing_only`）。捕获与手动检测里请求行/请求头本来就
全是攻击者发送的，"可控"这一条恒成立 —— 少了这道检查，`remoteStorage` /
`remotestorage` 这种差异会被满屏升成安全级（实测一次真实浏览：83/128 条安全级，其中
76% 的分歧只是 ASCII 大小写）。两道过滤器合起来才是与
"SAST 拿规则命中当结论"的根本区别。
"""
from __future__ import annotations

import re
from typing import Callable

from ..contracts import (LEVEL_COMPAT, LEVEL_SECURITY, LEVEL_UNKNOWN,
                         SEVERITY_CRITICAL, SEVERITY_INFO, SEVERITY_LOW,
                         SEVERITY_MEDIUM, Divergence, Observation,
                         ProbeRejected, Verdict, downgrade)
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


def ablate_via(ablations, div: Divergence, evaluate: Evaluator,
               compare_keys: tuple[str, ...]) -> list[str]:
    """通用消融实验：逐条"抹掉一类承载者"，看分歧是否消失。

    **消融的设计**（有哪几类承载者、各自怎么抹）是领域知识，由适配器给出
    （``*_axes.ABLATIONS``）；这里只承载"重放两侧 → 判定分歧是否还在"这套机制，
    与 :func:`ablate_headers` 是同一条原理，只是承载者的形态不同。
    """
    carriers: list[str] = []
    for label, transform in ablations:
        try:
            candidate = transform(div.payload)
        except Exception:          # noqa: BLE001 —— 变换对畸形输入无效即跳过
            continue
        if candidate == div.payload:
            continue               # 这条变换对当前输入没动作，不构成证据
        if not still_diverges(candidate, div, evaluate, compare_keys):
            carriers.append(label)
    return carriers


#: 序列字段（list/tuple）的比较：先按 ASCII 折叠、再排序，用来看"是不是只是书写顺序不同"
def _ascii_fold(text: str) -> str:
    """只折 **ASCII 字母** 的大小写，不碰任何非 ASCII 字符。

    刻意不用 ``str.casefold``：casefold 会把长 s ``ſ``（U+017F）折成 ``s``、把
    Kelvin ``K``（U+212A）折成 ``k`` —— 那恰好是"同一段字节被读成了不同的字"，
    是真分歧（见已知案例 ``enc-case-fold``）。这里要判的是相反的那一类：两侧只是把
    同一串 ASCII 字母写成了不同大小写（``remoteStorage`` / ``remotestorage``）。
    """
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def _writing_diff(left, right) -> str | None:
    """两个观测值是否只差"写法"；是则返回人话标签，否则 ``None``。

    三种"只是写法"：
      * ASCII 字母大小写不同（``remoteStorage`` / ``remotestorage``）；
      * 序列的书写顺序不同（``['appKey','local']`` / ``['local','appKey']``）；
      * ``&`` 分段的顺序不同（同一串参数换个书写顺序 —— 签名按排序后取值那类问题
        属于**序列化口径**，不是"读成了不同的内容"）。
    """
    if isinstance(left, str) and isinstance(right, str):
        if _ascii_fold(left) == _ascii_fold(right):
            return "ASCII 字母的大小写"
        if "&" in left and "&" in right:
            if (sorted(_ascii_fold(x) for x in left.split("&"))
                    == sorted(_ascii_fold(x) for x in right.split("&"))):
                return "参数的书写顺序"
        return None
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        if (sorted(_ascii_fold(str(x)) for x in left)
                == sorted(_ascii_fold(str(x)) for x in right)):
            return "序列的书写顺序"
        return None
    return None        # 数字 / 布尔：没有"写法"可谈，差异就是差异


def writing_only(div: Divergence, adapter) -> str | None:
    """这个分歧是否**只是写法差异** —— 是则返回人话标签，否则 ``None``。

    为什么需要这道检查：消融实验（``adapter.ablate``）只能证明"分歧由攻击者可以直接
    发送的字节承载"。而在**捕获 / 手动检测**这条路上，请求行与请求头本来就全都是
    攻击者直接发送的 —— 于是这道门槛恒成立，大小写敏感性、参数书写顺序这类**策略
    差异**会被统统升成安全级。实测一次真实浏览（Kimi / ChatGPT / 夸克，128 条已分析
    请求）：83 条被判安全级，其中 76% 的分歧只是 ``remoteStorage`` / ``remotestorage``
    这类 ASCII 大小写差异 —— 数字好看，但没有区分度。

    它不放宽"结构分歧"的定义，只是补上缺的那半个前提：**"同一段字节被读成了不同
    的东西"需要内容层面的错位**（非 ASCII 折叠、解码层数、截断口径、接受性），
    光差大小写/顺序的同一段内容不算。

    只看适配器声明的"承载内容"字段（``adapter.content_keys``）：像 ``codepoints``
    这种**由文本派生出来的**诊断字段不能参与判断 —— ``U+0053`` 与 ``U+0073`` 在
    ASCII 折叠下并不相等，拿它去比会把纯大小写差异又算成内容错位。
    """
    content = tuple(getattr(adapter, "content_keys", ()) or ())
    if not content:
        return None        # 没声明内容的领域（如分帧：观测的是边界而不是文本）不适用
    relevant = [d for d in div.diffs if d.key in content]
    if not relevant:
        return None
    labels: list[str] = []
    for diff in relevant:
        label = _writing_diff(diff.left, diff.right)
        if label is None:
            return None
        if label not in labels:
            labels.append(label)
    return "、".join(labels)


def grade(*, level: str, ceiling: str, controllable: bool,
          quantified=None) -> str:
    """按「类型上限 + 证据强度」定出**危险等级**。

    为什么要有这一层：``security`` 只说明"结构性前提成立"，而这个前提的后果差别
    巨大 —— 分帧边界错位能直接把下一条请求夹带进去（CWE-444），编码口径差异最多
    是过滤器绕过（CWE-180）。把两者塞进同一个"安全级"数字里，读的人只会把它读成
    "这么多漏洞"。所以：

    1. **类型上限**由领域给出（``adapter.meta(kind)["severity"]``）—— 这是"这类
       分歧最好情况下有多严重"，是领域知识，不是拍脑袋；
    2. 再用**证据**收紧或放宽 —— 这是"这一段字节到底撑不撑得起那个上限"。

    证据怎么用（顺序即优先级）：

    * **实机测量**（前置转发字节数 / 探针实测，而非模型推演）→ ``严重``。
      只有实测能把等级顶到这一档 —— 结构性前提成立永远只到"高"。
    * 量化出**确实错位**（两侧真读成了不同的资源/参数/站）→ 类型上限。
    * 量化不出来（含真实产品、本机算不了）→ 降一档，如实写"未量化"。
    * 量化出来但两侧**其实一致** → 降两档：没有错位，谈不上危害。
    * 量化结论是"**这条链路根本没串起来**"（前置直接拒绝）→ **不降档**：那说的是
      没有链路，不是两侧一致；把"前置严格"当成"危害小"会把整类分歧误压到最低档。
    * 仅写法差异 / 接受性分歧 / 定位不到承载者 / 仅诊断字段 → 低、信息。

    等级与 ``level`` 严格单调一致（security ≥ 中 > unknown = 低 > compat = 信息），
    所以按等级排序不会和按类别排序打架。
    """
    if level == LEVEL_COMPAT:
        return SEVERITY_INFO
    if level != LEVEL_SECURITY:
        return SEVERITY_LOW              # unknown：疑点，够不上安全问题
    if not controllable:
        return SEVERITY_LOW              # 防御性：定位不到承载者就别抬高
    if quantified is not None and getattr(quantified, "measured", False):
        return SEVERITY_CRITICAL
    if quantified is None or not quantified.verified:
        return downgrade(ceiling, 1)     # 未量化 → 降一档
    if getattr(quantified, "blocked", False):
        return ceiling                   # 这一对方向串不起来 ≠ 两侧读成一样
    if not getattr(quantified, "mismatch", True):
        return downgrade(ceiling, 2)     # 量化了，但两侧其实一致
    return ceiling


def finalize(verdict: Verdict, adapter, quantified=None) -> str:
    """量化跑完之后把等级**定下来**（就地写回 ``verdict.severity``）。

    定级要消费量化结果，而量化要等消融/最小化跑完，所以分两步：``judge`` 先给一个
    保守的临时等级，量化出来后再由这里收紧。凡是调过 ``judge`` 的地方都必须调它 ——
    漏调只会让等级偏低（保守），不会偏高。
    """
    ceiling = (adapter.meta(verdict.kind) or {}).get("severity") or SEVERITY_MEDIUM
    verdict.severity = grade(level=verdict.level, ceiling=ceiling,
                             controllable=verdict.controllable,
                             quantified=quantified)
    return verdict.severity


def judge(div: Divergence, kind: str, adapter, evaluate: Evaluator) -> Verdict:
    """判定一个分歧能否升级为安全影响。

    **判定权只在这里**：本函数是全仓唯一产出 ``Verdict`` 的地方。
    但"承载者是什么样"是**领域知识**，所以消融实验交给适配器
    （``adapter.ablate``）—— 判定器只负责用它给出的证据下结论。
    """
    boundary_kinds = adapter.boundary_kinds
    meta = adapter.meta(kind)
    keys = [d.key for d in div.diffs]

    # 便宜的前置检查：两侧只是"写法"不同（ASCII 大小写 / 参数书写顺序）就先别跑消融。
    # 理由见 :func:`writing_only` —— 消融实验只能证明"分歧由攻击者可直接发送的字节
    # 承载"，而捕获到的请求里请求行/请求头本来就全是攻击者发送的，这道门槛恒成立。
    written = writing_only(div, adapter)

    # 只有"可能被升级"的类型才跑消融实验 —— 它要把两侧重放很多遍，不便宜
    carriers: list[str] = []
    if (kind in boundary_kinds and written is None) or kind == adapter.kind_acceptance:
        carriers = adapter.ablate(div, evaluate)
    controllable = bool(carriers)
    ablation = None
    if carriers:
        shown = "；".join(carriers[:3])
        more = f"；等 {len(carriers)} 处" if len(carriers) > 3 else ""
        ablation = (f"{shown}{more} —— 分歧消失，"
                    f"说明它由攻击者可直接发送的部分承载")

    if kind in boundary_kinds and written is not None:
        level, reason = LEVEL_UNKNOWN, (
            f"结构字段分歧（{keys}），但两侧观测只差{written} —— 同一段内容换了写法，"
            f"不是被读成了不同的东西 → 不构成结构性安全前提，需人工复核"
        )
        controllable = True     # 承载者确实是可控字节，只是它撑不起"读成了不同内容"
        ablation = f"两侧观测在抹平{written}之后完全一致"
    elif kind in boundary_kinds and controllable:
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

    verdict = Verdict(level=level, kind=kind, reason=reason,
                      cwe=meta["cwe"], scenario=meta["scenario"],
                      controllable=controllable, ablation=ablation,
                      effect=meta["effect"], fix=meta["fix"])
    # 先给一个**保守**的临时等级（把量化当成"还没有"）；量化出来后调用
    # :func:`finalize` 才会收紧到类型上限。漏调只会偏低，不会偏高。
    finalize(verdict, adapter, None)
    return verdict
