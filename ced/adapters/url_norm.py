"""URL / 路径归一化领域适配器 —— 第二个领域。

它证明了一件对"平台"定位很关键的事：**换一个领域，引擎一行都不用改**。
差分、消融实验、最小化、链式复现、端到端 PoC、落库、报告、控制台全部原样复用；
变化只体现在这个文件里（语料、分类、后果映射）。

与 http1-framing 的差别只有一处本质：观测对象从"一条 HTTP 请求"变成
"一个请求目标（target）"，于是判定的是**同一段 target 被认成不同资源**。
前置按自己的归一化结果做鉴权、后端按自己的归一化结果路由 —— 两者不一致就是鉴权绕过。

**精度边界（必须如实知道）**：字符串不同 ≠ 资源不同。例如根目录下的 `/..` 与 `/`
在绝大多数实现里指向同一个资源，但它们的 ``norm_path`` 不同，因而会被判为 security。
这类发现**需要人工复核**：两侧解算结果、最小复现样本、端到端 PoC 都随发现一起给出，
看一眼 ``norm_front`` / ``norm_back`` 就能判。

判定链刻意**不引入鉴权模型**（不在模型里维护"受保护前缀表"）：
一旦某个领域有了专用判定器，``judge()`` 就不再是单点真源，创新点②自己就破了。
"""
from __future__ import annotations

import random
import re

from .. import httpmsg
from ..contracts import HardenedRequest, ImplSpec, Quantified
from ..classify.upgradability import ablate_via
from ..impls import url_reference
from ..impls.path_norm import normalize_target
from ..minimize.ddmin import minimize_segments
from ..mutate import url_axes
from .base import HARDEN_NOTE, HARDEN_NOOP_NOTE, http_request_fields
from .registry import register

# ---- 分歧类型（判定器按此升级/降级）----
KIND_PATH_TRAVERSAL = "path_traversal"          # 差异来自 `..` 被解算 → 跨目录
KIND_PATH_INTERP = "path_interpretation"        # 解码层数/大小写/分隔符等解释差异
KIND_ACCEPTANCE = "acceptance"                  # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"            # 仅诊断信息不同

#: 参与差分比对的观测字段。适配器可覆盖。
COMPARE_KEYS: tuple[str, ...] = (
    "accepted",
    "status",
    "norm_path",
    "traversal",
    "segments",
    "decoded",
)

#: 具备"分歧落在『这是哪个资源』上"结构性前提的类型
BOUNDARY_KINDS = (KIND_PATH_TRAVERSAL, KIND_PATH_INTERP)

_FIX_COMMON = (
    "鉴权必须建立在**归一化之后**的规范路径上，而不是原始 target 的字符串前缀上；"
    "前后端共用同一套归一化实现与同一份解码层数；后端不得对已解码路径再解码一次；"
    "含点段 / 反斜杠 / 矩阵参数 / 非规范百分号编码的请求，先规范化再比对，不一致就拒绝"
)

_KIND_MAP = {
    KIND_PATH_TRAVERSAL: {
        "effect": "同一段 target 被两侧解算成**不同资源**，且差异来自跨目录（`..`）"
                  "→ 若前置按自己的解算结果放行、后端按自己的解算结果路由，"
                  "受保护资源可被绕过访问（路径穿越 / 鉴权绕过）",
        "cwe": "CWE-22",
        "severity": "high",   # 类型上限（证据不足时按规则降档）
        "scenario": "authz",
        "fix": _FIX_COMMON,
    },
    KIND_PATH_INTERP: {
        "effect": "同一段 target 被两侧解释成**不同路径**（解码层数 / 百分号大小写 / "
                  "反斜杠 / 连续斜杠 / 矩阵参数 / 尾随点不一致）"
                  "→ 鉴权与路由可能落在不同资源上（鉴权绕过 / 路由绕过 / WAF 绕过）",
        "cwe": "CWE-863",
        "severity": "medium",   # 类型上限（证据不足时按规则降档）
        "scenario": "authz",
        "fix": _FIX_COMMON,
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝同一个 target → 前置放行下游拒绝（或反之），"
                  "可造成防护绕过或可用性差异",
        "cwe": "CWE-436",
        "severity": "low",   # 类型上限（证据不足时按规则降档）
        "scenario": "bypass",
        "fix": "统一对非规范 target 的接受策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息不同，两侧认定的资源一致 → 无直接安全后果",
        "cwe": None,
        "severity": "info",   # 类型上限（证据不足时按规则降档）
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


@register
class UrlNormAdapter:
    """URL / 路径归一化领域。"""

    name = "url-norm"
    content_keys: tuple[str, ...] = ("norm_path",)
    compare_keys: tuple[str, ...] = COMPARE_KEYS
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    kind_acceptance: str = KIND_ACCEPTANCE

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = url_axes.Mutator(variants_per_case=variants_per_case)

    def meta(self, kind: str) -> dict:
        return meta_of(kind)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return url_reference.specs()

    def local_parser(self) -> tuple:
        """本地解析器：路径归一化内核 + 归一化参照实现的策略表。"""
        return url_reference.policy_of, normalize_target

    def extract(self, raw: bytes) -> bytes:
        """能认出完整请求就取请求行的 target；否则视作裸对象原样返回。"""
        fields = http_request_fields(raw)
        return fields[0] if fields is not None else raw

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(url_reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return url_axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 分类

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类（刻意不用子串匹配，与分帧领域同一条纪律）。"""
        keys = set(diff_keys)
        if "traversal" in keys:
            return KIND_PATH_TRAVERSAL
        if keys & {"norm_path", "segments", "decoded"}:
            return KIND_PATH_INTERP
        if keys & {"accepted", "status"}:
            return KIND_ACCEPTANCE
        return KIND_SYNTAX_DETAIL

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— URL 领域的消融实验。

        逐条"抹掉一类字节"重放两侧：分歧消失了，说明它由那一类字节承载。
        而 target 是攻击者直接发送的 → 可控。
        与分帧领域"逐条移除请求头"完全同一条原理，只是承载者的形态不同。
        """
        return ablate_via(url_axes.ABLATIONS, div, evaluate, self.compare_keys)

    # ---------------------------------------------------------------- 最小化

    def minimize(self, payload: bytes, predicate) -> bytes:
        """路径领域的最小化单元是**路径段**（开头的斜杠与查询串保持不动）。"""
        return minimize_segments(payload, predicate)

    # ---------------------------------------------------------------- 量化

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的路径片段：算"前置认的资源 / 后端认的资源"。"""
        return {
            "imports": ("from ced.impls import url_reference\n"
                        "from ced.impls.path_norm import normalize_target"),
            "measure_body": (
                "    try:\n"
                "        front_policy = url_reference.policy_of(FRONT)\n"
                "        back_policy = url_reference.policy_of(BACK)\n"
                "    except KeyError:\n"
                "        return None\n"
                "    front_res = normalize_target(PAYLOAD, front_policy)\n"
                "    forwarded = PAYLOAD\n"
                "    if front_policy.forward_form == \"normalized\":\n"
                "        forwarded = front_res.norm_path.encode(\"latin-1\")\n"
                "    back_res = normalize_target(forwarded, back_policy)\n"
                "    return front_res.norm_path, back_res.norm_path"),
            "report_body": (
                "        front_path, back_path = got\n"
                "        print(f\"前置认的资源  {front_path}\")\n"
                "        print(f\"后端认的资源  {back_path}\")\n"
                "        print(f\"资源错位      {'是' if front_path != back_path else '否'}\")\n"
                "        ok = (front_path != back_path) == bool(EXPECT[0])\n"
                "        expect_mismatch = EXPECT[0] != EXPECT[1]\n"
                "        print(f\"断言        {'PASS' if ok else 'FAIL'}\"\n"
                "              f\"（期望错位={expect_mismatch}）\")"),
        }

    def quantify(self, payload: bytes, left_id: str, right_id: str, div=None):
        """量化：**同一段 target 被前置与后端解成了不同资源**。

        模型与分帧领域完全同构，只是数字的含义不同 ——
        分帧是"夹带了多少字节"，这里是"前置认的资源 vs 后端认的资源"。
        前置转发出去的形式由它自己的 ``forward_form`` 决定（原文 / 归一化后），
        这正是"后端会再解释一次"的现实来源。
        """
        try:
            front = url_reference.policy_of(left_id)
            back = url_reference.policy_of(right_id)
        except KeyError:
            return None        # 含真实产品，本机无法量化

        front_res = normalize_target(payload, front)
        forwarded = payload
        if front.forward_form == "normalized":
            forwarded = front_res.norm_path.encode("latin-1")
        back_res = normalize_target(forwarded, back)

        same = front_res.norm_path == back_res.norm_path
        pair = f"**{left_id} → {right_id}**"
        if same:
            describe = (f"若 {pair} 串联：两侧把同一段 target 都解成 "
                        f"`{front_res.norm_path}` → 无资源错位")
        else:
            describe = (f"若 {pair} 串联：前置解成 `{front_res.norm_path}`"
                        f"（它据此做鉴权），后端解成 `{back_res.norm_path}`"
                        f"（它据此路由）→ 攻击者触及的是**后者**，"
                        f"而按前置的判定他本不该触及")

        return Quantified(
            label="归一化路径错位",
            describe=describe,
            values={"front": left_id, "back": right_id,
                    "norm_front": front_res.norm_path,
                    "norm_back": back_res.norm_path},
            numbers=(front_res.norm_path, back_res.norm_path),
            verified=True,
            mismatch=not same,
        )

    # ---------------------------------------------------------------- 修复形态

    #: 基准实现 —— 修复形态 = 按它的口径归一化之后的写法
    baseline_id = "url-gateway"

    def harden(self, payload: bytes):
        """把 target 重写成**基准口径归一化后**的无歧义写法。

        路径歧义的来源都是"这段字节还没被解算清楚"：``%2e%2e`` 究竟是 ``..`` 还是
        字面量、反斜杠是不是分隔符、斜杠要不要折叠、大小写敏不敏感。全部解算掉再按
        规范百分号编码写回去，每个实现读到的就是同一个资源 —— 歧义消失。
        """
        target = self.extract(payload)
        if not target:
            return None
        try:
            policy = url_reference.policy_of(self.baseline_id)
        except KeyError:
            return None
        # 查询串不是本领域的观测对象 —— 只重写 `?` 之前那段（见 httpmsg.with_path）
        path_part = target.partition(b"?")[0]
        result = normalize_target(target, policy)
        # 绝对形式（`http://host/p`）的 authority 不是本领域的观测对象 ——
        # 它是"发给谁"，不是"要哪个资源"。归一化只针对路径，前缀原样带上。
        prefix = b""
        matched = re.match(rb"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/?#]*", path_part)
        if matched:
            prefix = matched.group(0)
        canonical = prefix + httpmsg.percent_encode(
            result.norm_path, safe="/").encode("ascii")
        if canonical == path_part:
            return HardenedRequest(domain=self.name, fixed=payload,
                                   note=HARDEN_NOOP_NOTE)

        changes = [f"target 归一化：`{httpmsg.brief(path_part)}` → "
                   f"`{httpmsg.brief(canonical)}`（查询串原样保留）"]
        if result.traversal:
            changes.append("`..` 已解算 —— 原始写法里带着跨目录语义")
        if result.decoded:
            changes.append(f"百分号转义已解掉 {result.decoded} 层，"
                           f"并按规范大写十六进制重写")
        return HardenedRequest(domain=self.name,
                               fixed=httpmsg.with_path(payload, canonical),
                               changes=changes, note=HARDEN_NOTE)

__all__ = ["UrlNormAdapter", "KIND_PATH_TRAVERSAL", "KIND_PATH_INTERP",
           "KIND_ACCEPTANCE", "KIND_SYNTAX_DETAIL", "BOUNDARY_KINDS",
           "COMPARE_KEYS", "meta_of"]
