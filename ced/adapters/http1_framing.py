"""HTTP/1.1 消息分帧领域适配器。"""
from __future__ import annotations

import random

from ..classify.upgradability import ablate_headers
from ..contracts import DEFAULT_COMPARE_KEYS, ImplSpec, Quantified
from ..impls import reference
from ..mutate import axes, engine
from ..minimize.ddmin import minimize_headers
from ..orchestrate.chain import chain_evidence
from .registry import register

# ---- 分歧类型（判定器按此升级/降级）----
KIND_FRAMING_BOUNDARY = "framing_boundary"          # 消费字节数不同 —— 走私的结构性前提
KIND_FRAMING_INTERP = "framing_interpretation"      # 定帧来源/体长解释不同
KIND_ACCEPTANCE = "acceptance"                      # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"                # 仅诊断信息不同

#: 只有这两类具备"分歧落在消息边界上"的结构性前提
BOUNDARY_KINDS = (KIND_FRAMING_BOUNDARY, KIND_FRAMING_INTERP)

_KIND_MAP = {
    KIND_FRAMING_BOUNDARY: {
        "effect": "两条链路对『这条请求占用多少字节』判断不同 → 剩余字节被下游当成下一条请求 → 请求走私（CL.TE / TE.CL）",
        "cwe": "CWE-444",
        "scenario": "desync",
        "fix": "对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式",
    },
    KIND_FRAMING_INTERP: {
        "effect": "定帧来源或请求体长度解释不同 → 边界可能错位（是否可升级取决于字节能否被夹带）",
        "cwe": "CWE-444",
        "scenario": "desync",
        "fix": "统一 CL/TE 优先级与语法接受度；两侧对齐同一份定帧规范",
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝 → 上游放行下游拒绝（或反之），可造成防护绕过或拒绝服务",
        "cwe": "CWE-436",
        "scenario": "bypass",
        "fix": "统一对畸形语法的拒绝策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息（告警/备注）不同，观测到的消息结构一致 → 无直接安全后果",
        "cwe": None,
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


@register
class Http1FramingAdapter:
    """HTTP/1.1 分帧领域。"""
    name = "http1-framing"
    compare_keys: tuple[str, ...] = DEFAULT_COMPARE_KEYS
    #: 具备"分歧落在消息边界上"结构性前提的类型（判定器据此决定能否升级）
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    #: 接受性分歧的类型
    kind_acceptance: str = KIND_ACCEPTANCE

    def meta(self, kind: str) -> dict:
        """分歧类型 → 安全后果 / CWE / 场景 / 修复建议。"""
        return meta_of(kind)

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = engine.Mutator(variants_per_case=variants_per_case)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return reference.specs()

    def local_parser(self) -> tuple:
        """本地解析器：分帧内核 + 分帧参照实现的策略表。"""
        from ..impls.http_reader import parse_request
        return reference.policy_of, parse_request

    def extract(self, raw: bytes) -> bytes:
        """分帧领域的观测对象就是整条请求，原样返回。"""
        return raw

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 最小化

    def minimize(self, payload: bytes, predicate) -> bytes:
        """分帧领域的最小化单元是**请求头行**（请求行与头/体分隔保持不动）。"""
        return minimize_headers(payload, predicate)

    # ---------------------------------------------------------------- 分类与消融

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类。

        刻意不用子串匹配：任何诊断字段（诊断信息）都不应被误升级为边界分歧。
        """
        keys = set(diff_keys)
        if "consumed" in keys:
            return KIND_FRAMING_BOUNDARY
        if keys & {"framing_source", "leftover_len", "body_len", "cl", "te"}:
            return KIND_FRAMING_INTERP
        if keys & {"accepted", "status"}:
            return KIND_ACCEPTANCE
        return KIND_SYNTAX_DETAIL

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节：逐条移除请求头 / 规范化请求行。

        分帧领域的消融实验，实现在 ``classify.upgradability.ablate_headers`` ——
        消融的**设计**是领域知识，所以由适配器提供；判定器只消费它的结论。
        """
        return ablate_headers(div.payload, div, evaluate, self.compare_keys)

    # ---------------------------------------------------------------- 量化

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的分帧片段：算"前置转发 / 后端消费 / 夹带"三个数。"""
        return {
            "imports": ("from ced.impls import reference\n"
                        "from ced.orchestrate.chain import chain_evidence"),
            "measure_body": (
                "    try:\n"
                "        front_policy = reference.policy_of(FRONT)\n"
                "        back_policy = reference.policy_of(BACK)\n"
                "    except KeyError:\n"
                "        return None\n"
                "    ev = chain_evidence(PAYLOAD, front_policy, back_policy, FRONT, BACK)\n"
                "    return ev.forwarded, ev.back_consumed, ev.smuggled_len"),
            "report_body": (
                "        forwarded, consumed, smuggled = got\n"
                "        print(f\"前置转发    {forwarded} 字节\")\n"
                "        print(f\"后端消费    {consumed} 字节\")\n"
                "        print(f\"被夹带      {smuggled} 字节\")\n"
                "        if EXPECT[0] is not None:\n"
                "            ok = got == tuple(EXPECT)\n"
                "            print(f\"断言        {'PASS' if ok else 'FAIL'}（期望 {EXPECT}）\")"),
        }

    def quantify(self, payload: bytes, left_id: str, right_id: str, div=None):
        """量化：前置转发出去的字节里，后端只消费了多少 —— 差额即被夹带字节数。

        两侧都是参照实现 → 模型口径（chain_evidence 推演）；
        含真实产品（runner=chain）→ **实机口径**：链路观测里的
        ``forwarded_raw_len``（探针实测前置转发的字节数）与 ``leftover_len``
        （参照后端策略消费后剩下的字节）都是实测值，直接采用。
        """
        try:
            front = reference.policy_of(left_id)
            back = reference.policy_of(right_id)
        except KeyError:
            return self._quantify_real(div, left_id, right_id)
        evidence = chain_evidence(payload, front, back, left_id, right_id)
        return Quantified(
            label="被夹带字节数",
            describe=evidence.describe(),
            values={"front": left_id, "back": right_id,
                    "forwarded": evidence.forwarded,
                    "back_consumed": evidence.back_consumed,
                    "smuggled": evidence.smuggled_len},
            numbers=(evidence.forwarded, evidence.back_consumed,
                     evidence.smuggled_len),
            verified=True,
        )

    def _quantify_real(self, div, left_id: str, right_id: str):
        """实机量化：从链路观测的实测字段算被夹带字节数（不经过模型）。"""
        if div is None:
            return None
        obs = (div.left if div.left.fields.get("forwarded_raw_len")
               else div.right)
        forwarded = obs.fields.get("forwarded_raw_len")
        if not forwarded:
            return None        # 链路观测里没有实测字节数，如实写"未量化"
        leftover = obs.fields.get("leftover_len")
        consumed = obs.fields.get("consumed")
        back_consumed = (forwarded - leftover if leftover is not None
                         else (consumed or 0))
        smuggled = leftover if leftover is not None else forwarded - back_consumed
        return Quantified(
            label="被夹带字节数（实机测量）",
            describe=(
                f"**实机测量**：真实前置 `{obs.impl_id}` 转发了 {forwarded} 字节，"
                f"后端侧（探针参照策略）只消费 {back_consumed} 字节 → "
                f"**{smuggled} 字节成为后端眼里下一条请求的开头**"
                f"（实测值，非模型推演；PoC --chain 可在链路上复验）"),
            values={"front": left_id, "back": right_id,
                    "forwarded": forwarded,
                    "back_consumed": back_consumed,
                    "smuggled": smuggled},
            numbers=(forwarded, back_consumed, smuggled),
            verified=True,
        )
