"""领域适配器协议。

接入一个新领域（HTTP/2 分帧、URL 归一化、序列化格式……）
= 实现一个 DomainAdapter，其余模块（差分/判定/最小化/报告）全部复用。
"""
from __future__ import annotations

import random
from typing import Protocol

from ..contracts import DEFAULT_COMPARE_KEYS, ImplSpec


class DomainAdapter(Protocol):
    """领域适配器。运行时按鸭子类型约束，不做 ABC 强制。"""

    name: str
    #: 参与差分比对的观测字段（其余字段视为诊断信息，不参与）
    compare_keys: tuple[str, ...]
    #: 具备"分歧落在消息边界上"结构性前提的类型
    boundary_kinds: tuple[str, ...]
    #: 接受性分歧的类型
    kind_acceptance: str

    def meta(self, kind: str) -> dict:
        """分歧类型 → {effect, cwe, scenario, fix}。"""
        ...

    def specs(self) -> list[ImplSpec]:
        """参与差分的实现清单。"""
        ...

    def local_parser(self) -> tuple:
        """本领域的本地解析器：``(policy_of, parse)``。

        ``parse(payload, policy)`` 必须返回带 ``ok`` / ``reason`` / ``to_fields()``
        的对象。引擎靠它把 ``runner=local`` 的实现接到本领域的解析内核上 ——
        这是"加领域不改引擎"的关键接口。
        """
        ...

    def extract(self, raw: bytes) -> bytes:
        """从"某处收到的字节"里取出**本领域的观测对象**。

        输入有两种可能，实现必须都容忍：

        * **完整请求**（真实链路里前置转发出来的字节，含 ``HTTP/1.`` 请求行）——
          能认出就取本领域字段：``url-norm`` / ``enc-norm`` 取请求行的 target，
          ``host-norm`` 取 Host 头的值，``query-norm`` 取 target 里 ``?`` 之后的
          查询串（没有 ``?`` 则返回空字节 ``b""``）。
        * **本领域对象本身**（内置语料就是裸对象，没有请求行）—— 原样返回。

        ``http1-framing`` 的观测对象就是整条请求，永远原样返回。
        "能不能认出请求"由 ``ced.httpmsg.split`` 与请求行里的 ``HTTP/1.`` 判定；
        认不出就原样返回。
        """
        ...

    def pairs(self) -> dict[str, tuple[str, str]]:
        """定向对照：轴名 → (左实现, 右实现)。"""
        ...

    def corpus(self) -> list[tuple[str, bytes]]:
        """种子语料：(轴名, 原始字节)。"""
        ...

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        """定向变异。"""
        ...

    def classify(self, diff_keys: list[str]) -> str:
        """分歧字段 → 分歧类型。"""
        ...

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— **该领域的消融实验**。

        逐条"抹掉一类承载者"重放两侧：分歧消失了，说明它由那一类字节承载；
        而那些字节由攻击者直接发送 → 可控。判定器据此把 boundary 类分歧升级为
        ``security``，把定位不到的保守判为 ``unknown``。

        消融的**设计**是领域知识（分帧是逐条请求头，路径归一化是逐类字节），
        所以它属于适配器；判定权仍然唯一属于 ``classify.upgradability.judge``。
        """
        ...

    def quantify(self, payload: bytes, left_id: str, right_id: str,
                 div=None):
        """把"两侧理解不同"量化成"真的有东西错位了"（``Quantified`` 或 None）。

        ``div`` 是本次差分的 :class:`Divergence`（含两侧观测）—— 当任一侧是
        真实产品（runner=chain）时，适配器可以从链路观测里的**实测字段**
        （``forwarded_raw_len`` / ``leftover_len``）做实机量化，而不是返回 None。

        各领域的量化指标不同：分帧是**被夹带的字节数**，路径归一化是**资源路径的错位**。
        两侧都是本地参照实现时按模型口径算；含真实产品时优先用实测字段，
        实测也拿不到才返回 None，报告如实写"未量化"。
        """
        ...

    def minimize(self, payload: bytes, predicate) -> bytes:
        """在**该领域的语义单元**上压小样本，同时保持分歧仍在。

        最小化的粒度是领域知识：分帧是"请求头行"，路径归一化是"路径段"。
        ``predicate(candidate) -> bool`` 判断该候选是否仍然构成分歧。
        """
        ...

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的**领域片段**：``{imports, measure_body, report_body}``。

        脚本骨架（参数解析、合规门禁、--send）由 ``scenario/poc.py`` 统一提供；
        这里只填"怎么算这个领域的量化指标、怎么断言"。
        返回的 ``measure_body`` 是 ``measure()`` 的函数体（4 空格缩进），
        算不出来时返回 ``None``；``report_body`` 在拿到结果后打印并置 ``ok``。
        """
        ...


__all__ = ["DomainAdapter", "DEFAULT_COMPARE_KEYS", "axis_names",
           "http_request_fields"]


def http_request_fields(raw: bytes) -> tuple[bytes, bytes] | None:
    """认出完整 HTTP/1.x 请求 → ``(target, host)``；认不出 → ``None``。

    "完整请求"由两件事共同判定：``ced.httpmsg.split`` 能找到头部终止符（消息
    结构完整），且首行是含 ``HTTP/1.`` 的请求行（``GET /p HTTP/1.1``）。

    ``host`` 取 Host 头的值（去掉头名与两端空白）；没有 Host 头则为 ``b""``。
    裸对象（内置语料：一个请求目标 / 一段 Host / 一段查询串）不含请求行，
    因此返回 ``None``，由各适配器的 ``extract`` 原样返回。
    """
    from ..httpmsg import header_name, split

    msg = split(raw)
    if msg is None or not msg.lines:
        return None
    request_line = msg.lines[0]
    if b"HTTP/1." not in request_line:
        return None
    parts = request_line.split(b" ")
    target = parts[1] if len(parts) >= 2 else b""
    host = b""
    for line in msg.lines[1:]:
        if header_name(line) == b"host":
            _, _, value = line.partition(b":")
            host = value.strip()
            break
    return target, host


def axis_names(adapter) -> tuple[str, ...]:
    """适配器语料里出现的轴名（去重保序）。

    用领域自己的名字空间，而不是硬编码某个领域的 ``axes.AXES`` ——
    换领域时调用方不用改。
    """
    return tuple(dict.fromkeys(name for name, _ in adapter.corpus()))
