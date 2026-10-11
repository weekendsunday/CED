"""查询串解析领域适配器 —— query-norm。

它继续证明"换一个领域，引擎一行都不用改"：差分、消融实验、最小化、量化、
端到端 PoC、落库、报告全部原样复用；变化只体现在这个文件里。

与 url-norm 的本质差别：观测对象从"请求目标"变成"查询串字节"，判定的是
**同一段查询串被认成不同的一组参数、或同一个参数取到不同的值**。
前置按自己的解析结果做校验、后端按自己的解析结果执行业务 —— 两者取到的值不一致，
就是 **HTTP 参数污染（HPP）/ 校验绕过** 原语。

**精度边界（必须如实知道）**：字符串不同 ≠ 语义不同。例如 `a=1&b=2` 与 `b=2&a=1`
在"是否排序"之外的所有口径里都是同一组参数。这类差异是否需要复核，看
``norm_front`` / ``norm_back`` 即知 —— 两侧解出的参数串随发现一起给出。

判定链刻意**不引入任何参数白名单/校验模型**：一旦某个领域有了专用判定器，
``judge()`` 就不再是单点真源。
"""
from __future__ import annotations

import random

from ..contracts import ImplSpec, Quantified
from ..classify.upgradability import still_diverges
from ..impls import query_reference
from ..impls.query_norm import parse_query
from ..minimize.ddmin import ddmin
from ..mutate import query_axes
from .base import http_request_fields
from .registry import register

# ---- 分歧类型（判定器按此升级/降级）----
KIND_HPP = "param_pollution"            # 重复参数取首/取尾/全要 → 参数污染（HPP）
KIND_PARAM_SET = "param_set"            # 参数集/名字/解释差异（分隔符/解码/括号/大小写/排序）
KIND_ACCEPTANCE = "acceptance"          # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"    # 仅诊断信息不同

#: 参与差分比对的观测字段。适配器可覆盖。
COMPARE_KEYS: tuple[str, ...] = (
    "accepted",
    "status",
    "norm_query",
    "keys",
    "param_count",
    "dup_kept",
)

#: 具备"分歧落在『带了哪些参数、取什么值』上"结构性前提的类型
BOUNDARY_KINDS = (KIND_HPP, KIND_PARAM_SET)

_FIX_COMMON = (
    "前置校验与后端业务必须共用同一份查询串解析实现（同一分隔符集、同一解码层数、"
    "同一重复参数策略）；对同名参数**先归一化再取值**（明确取首/取尾/拒绝）；"
    "不要在校验侧与业务侧分别解析同一份原始查询串；对 `;`、非规范编码、`+`、"
    "括号参数名、大小写不一致的请求，先规范化再比对，不一致就拒绝"
)

_KIND_MAP = {
    KIND_HPP: {
        "effect": "同一段查询串被两侧解析出**不同的参数取值**（重复参数取首 / 取尾 / 全要"
                  "不一致）→ 前置校验读到的是第一个值、业务逻辑吃到的是最后一个值（或反之），"
                  "用同一份输入就能让『被校验的值』与『被使用的值』分叉 "
                  "（HTTP 参数污染 HPP / 越权 / 金额篡改 / 校验绕过）",
        "cwe": "CWE-235",
        "scenario": "param",
        "fix": _FIX_COMMON,
    },
    KIND_PARAM_SET: {
        "effect": "同一段查询串被两侧解释成**不同的一组参数**（分隔符是否含 `;` / 解码层数 / "
                  "`+` 是否当空格 / 空值是否保留 / 括号参数名是否归一 / 参数名大小写 / "
                  "参数是否排序不一致）→ 前置与业务看到的参数集不同，"
                  "可造成参数污染、规则绕过、缓存键错位（HPP / 校验绕过 / 缓存投毒）",
        "cwe": "CWE-235",
        "scenario": "param",
        "fix": _FIX_COMMON,
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝同一段查询串 → 前置放行下游拒绝（或反之），"
                  "可造成防护绕过或可用性差异",
        "cwe": "CWE-436",
        "scenario": "bypass",
        "fix": "统一对非规范查询串的接受策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息不同，两侧认定的参数集一致 → 无直接安全后果",
        "cwe": None,
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


def _value_map(norm_query: str) -> dict[str, list[str]]:
    """把归一化后的查询串拆回 name → [values]，用于量化"两侧读到的值"。"""
    out: dict[str, list[str]] = {}
    for token in norm_query.split("&"):
        if token == "":
            continue
        name, _, value = token.partition("=")
        out.setdefault(name, []).append(value)
    return out


@register
class QueryNormAdapter:
    """查询串解析领域。"""

    name = "query-norm"
    compare_keys: tuple[str, ...] = COMPARE_KEYS
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    kind_acceptance: str = KIND_ACCEPTANCE

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的领域片段：算"前置读到的参数 / 后端读到的参数"。"""
        return {
            "imports": ("from ced.impls import query_reference\n"
                        "from ced.impls.query_norm import parse_query"),
            "measure_body": (
                "    try:\n"
                "        front_policy = query_reference.policy_of(FRONT)\n"
                "        back_policy = query_reference.policy_of(BACK)\n"
                "    except KeyError:\n"
                "        return None\n"
                "    front_res = parse_query(PAYLOAD, front_policy)\n"
                "    back_res = parse_query(PAYLOAD, back_policy)\n"
                "    return front_res.norm_query, back_res.norm_query"),
            "report_body": (
                "        front_q, back_q = got\n"
                "        print(f\"前置解析    {front_q}\")\n"
                "        print(f\"后端解析    {back_q}\")\n"
                "        print(f\"取值错位    {'是' if front_q != back_q else '否'}\")\n"
                "        expect_mismatch = EXPECT[0] != EXPECT[1]\n"
                "        ok = (front_q != back_q) == expect_mismatch\n"
                "        print(f\"断言        {'PASS' if ok else 'FAIL'}\"\n"
                "              f\"（期望错位={expect_mismatch}）\")"),
        }

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = query_axes.Mutator(variants_per_case=variants_per_case)

    def meta(self, kind: str) -> dict:
        return meta_of(kind)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return query_reference.specs()

    def local_parser(self) -> tuple:
        """本地解析器：查询串解析内核 + 参照实现的策略表。"""
        return query_reference.policy_of, parse_query

    def extract(self, raw: bytes) -> bytes:
        """能认出完整请求就取 target 里 ``?`` 之后的查询串；否则原样返回。

        认出请求但 target 里没有 ``?`` → 查询串为空，返回 ``b""``。
        """
        fields = http_request_fields(raw)
        if fields is None:
            return raw
        target = fields[0]
        return target.split(b"?", 1)[1] if b"?" in target else b""

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(query_reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return query_axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 分类

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类（刻意不用子串匹配，与其它领域同一条纪律）。"""
        keys = set(diff_keys)
        if "dup_kept" in keys:
            return KIND_HPP
        if keys & {"norm_query", "keys", "param_count"}:
            return KIND_PARAM_SET
        if keys & {"accepted", "status"}:
            return KIND_ACCEPTANCE
        return KIND_SYNTAX_DETAIL

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— 查询串领域的消融实验。

        逐条"抹掉一类承载者 / 统一一种解释"重放两侧：分歧消失了，
        说明它由那一类字节（或那一处解释差异）承载。查询串是攻击者直接发送的 → 可控。
        """
        carriers: list[str] = []
        for label, transform in query_axes.ABLATIONS:
            try:
                candidate = transform(div.payload)
            except Exception:      # noqa: BLE001 —— 变换对畸形输入无效即跳过
                continue
            if candidate == div.payload:
                continue           # 这条变换对当前输入没动作，不构成证据
            if not still_diverges(candidate, div, evaluate, self.compare_keys):
                carriers.append(label)
        return carriers

    # ---------------------------------------------------------------- 最小化

    def minimize(self, payload: bytes, predicate) -> bytes:
        """查询串领域的最小化单元是**参数**（用 `&` 重新拼接）。"""
        if not predicate(payload):
            return payload
        tokens = [tok for tok in payload.decode("latin-1").split("&") if tok != ""]
        if len(tokens) <= 1:
            return payload

        def build(keep: list[int]) -> bytes:
            return "&".join(tokens[i] for i in keep).encode("latin-1")

        everything = list(range(len(tokens)))
        if not predicate(build(everything)):
            # 重建本身就会改变语义（例如原串带 `;` 分隔）—— 宁可不最小化。
            return payload
        kept = ddmin(everything, lambda ks: bool(ks) and predicate(build(ks)))
        return build(list(kept))

    # ---------------------------------------------------------------- 量化

    def quantify(self, payload: bytes, left_id: str, right_id: str, div=None):
        """量化：**同一段查询串被前置与后端读成了不同的参数取值**。

        两侧都是本地参照实现时才能算；含真实产品时返回 None，报告如实写"未量化"。
        """
        try:
            front = query_reference.policy_of(left_id)
            back = query_reference.policy_of(right_id)
        except KeyError:
            return None        # 含真实产品，本机无法量化

        front_res = parse_query(payload, front)
        back_res = parse_query(payload, back)
        pair = f"**{left_id} → {right_id}**"

        rear = front_res.norm_query
        back_q = back_res.norm_query
        values = {"front": left_id, "back": right_id,
                  "norm_front": rear, "norm_back": back_q}

        if rear == back_q:
            describe = (f"若 {pair} 串联：两侧把同一段查询串都解析成 "
                        f"`{rear}` → 无取值错位")
        else:
            fmap, bmap = _value_map(rear), _value_map(back_q)
            diverging = next(
                (name for name in fmap
                 if name in bmap and fmap[name] != bmap[name]), None)
            if diverging is not None:
                fval = "|".join(fmap[diverging])
                bval = "|".join(bmap[diverging])
                detail = (f"参数 `{diverging}`：前置读到 `{fval}`、"
                          f"后端读到 `{bval}`")
            else:
                detail = (f"前置解析成 `{rear}`、后端解析成 `{back_q}`")
            describe = (f"若 {pair} 串联：{detail} → "
                        f"攻击者用同一份输入让『被校验的值』与『被使用的值』分叉")

        return Quantified(
            label="参数取值错位",
            describe=describe,
            values=values,
            numbers=(rear, back_q),
            verified=True,
        )


__all__ = ["QueryNormAdapter", "KIND_HPP", "KIND_PARAM_SET", "KIND_ACCEPTANCE",
           "KIND_SYNTAX_DETAIL", "BOUNDARY_KINDS", "COMPARE_KEYS", "meta_of"]
