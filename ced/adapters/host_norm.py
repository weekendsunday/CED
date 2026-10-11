"""Host / 路由归一化领域适配器 —— 第三个领域。

与 ``url_norm`` 的区别只有一处本质：观测对象从"请求目标"变成 **Host 头的值**，
于是判定的是**同一段 Host 被两侧认成不同虚拟主机（路由 / 缓存键）**。
前置按自己的归一化结果选路由或算缓存键、后端按自己的归一化结果选站 ——
两者不一致就是**虚拟主机绕过**或**缓存投毒**（CWE-436）。

**精度边界（必须如实知道）**：字符串不同 ≠ 主机不同。例如 `example.com.` 与
`example.com` 在多数解析器里指向同一个站，但它们的 ``norm_host`` 不同，因而会被
判为 security。这类发现**需要人工复核**：两侧最终认到的站、最小复现样本、
端到端 PoC 都随发现一起给出，看一眼 ``norm_front`` / ``norm_back`` 就能判。

判定链刻意**不引入路由模型**（不在模型里维护"受保护 vhost 表"）：
一旦某个领域有了专用判定器，``judge()`` 就不再是单点真源。
"""
from __future__ import annotations

import random

from ..contracts import ImplSpec, Quantified
from ..classify.upgradability import still_diverges
from ..impls import host_reference
from ..impls.host_norm import normalize_host
from ..minimize.ddmin import ddmin
from ..mutate import host_axes
from .base import http_request_fields
from .registry import register

# ---- 分歧类型（判定器按此升级/降级）----
KIND_HOST_NORM = "host_interpretation"    # 差异来自目标虚拟主机 / 缓存键的归一化口径
KIND_ACCEPTANCE = "acceptance"            # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"      # 仅诊断信息不同

#: 参与差分比对的观测字段。适配器可覆盖。
COMPARE_KEYS: tuple[str, ...] = (
    "accepted",
    "status",
    "norm_host",
    "port",
    "is_ip",
    "has_userinfo",
)

#: 具备"分歧落在『这是哪个站 / 哪个缓存键』上"结构性前提的类型
BOUNDARY_KINDS = (KIND_HOST_NORM,)

_FIX_COMMON = (
    "路由与缓存键必须建立在**归一化之后**的规范主机名上，而不是原始 Host 字符串；"
    "前后端共用同一套 Host 归一化口径（尾随点 / 大小写 / 默认端口 / userinfo / "
    "空标签 / IDN / IPv6 / 百分号编码全部先统一再比对）；含 userinfo 或非规范写法的 "
    "Host 直接拒绝，不要静默接受"
)

_KIND_MAP = {
    KIND_HOST_NORM: {
        "effect": "同一段 Host 头被两侧认成**不同虚拟主机**（尾随点 / 大小写 / "
                  "默认端口 / userinfo / 空标签 / IDN / IPv6 / 百分号编码口径不一致）"
                  "→ 前置据此选路由或算缓存键、后端据此选站；"
                  "若落在不同站点或不同缓存键上，就是虚拟主机绕过或缓存投毒"
                  "（一条响应被缓存到另一个键下喂给别人）",
        "cwe": "CWE-436",
        "scenario": "poison",
        "fix": _FIX_COMMON,
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝同一个 Host 值 → 前置放行下游拒绝（或反之），"
                  "可造成防护绕过或可用性差异",
        "cwe": "CWE-436",
        "scenario": "bypass",
        "fix": "统一对非规范 Host 的接受策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息不同，两侧认定的虚拟主机一致 → 无直接安全后果",
        "cwe": None,
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


@register
class HostNormAdapter:
    """Host / 路由归一化领域。"""

    name = "host-norm"
    compare_keys: tuple[str, ...] = COMPARE_KEYS
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    kind_acceptance: str = KIND_ACCEPTANCE

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = host_axes.Mutator(variants_per_case=variants_per_case)

    def meta(self, kind: str) -> dict:
        return meta_of(kind)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return host_reference.specs()

    def local_parser(self) -> tuple:
        """本地解析器：Host 归一化内核 + 归一化参照实现的策略表。"""
        return host_reference.policy_of, normalize_host

    def extract(self, raw: bytes) -> bytes:
        """能认出完整请求就取 Host 头的值；否则视作裸对象原样返回。"""
        fields = http_request_fields(raw)
        return fields[1] if fields is not None else raw

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(host_reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return host_axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 分类

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类（刻意不用子串匹配，与另两个领域同一条纪律）。"""
        keys = set(diff_keys)
        if keys & {"norm_host", "port"}:
            return KIND_HOST_NORM
        if keys & {"accepted", "status"}:
            return KIND_ACCEPTANCE
        return KIND_SYNTAX_DETAIL

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— Host 领域的消融实验。

        逐条"抹掉一类字节"重放两侧：分歧消失了，说明它由那一类字节承载。
        而 Host 是攻击者直接发送的 → 可控。
        与分帧领域"逐条移除请求头"同一条原理，只是承载者的形态不同。
        """
        carriers: list[str] = []
        for label, transform in host_axes.ABLATIONS:
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
        """Host 领域没有路径段这种天然单元，故按**字节**做 ddmin。

        保持"分歧仍在"的前提下把 Host 压到最短 —— 例如 `example.com.` 可能压成 `.`。
        """
        if not predicate(payload):
            return payload
        units = list(range(len(payload)))

        def keeps(indices: list[int]) -> bool:
            if not indices:
                return False
            return predicate(bytes(payload[i] for i in indices))

        kept = ddmin(units, keeps)
        return bytes(payload[i] for i in kept)

    # ---------------------------------------------------------------- 量化

    def quantify(self, payload: bytes, left_id: str, right_id: str, div=None):
        """量化：**同一段 Host 被前置与后端认成了不同虚拟主机**。

        模型与路径领域完全同构 —— 路径是"前置认的资源 vs 后端认的资源"，
        Host 是"前置认的站/缓存键 vs 后端认的站/缓存键"。
        前置转发出去的形式由它自己的 ``forward_form`` 决定（原文 / 归一化后），
        这正是"后端会再解释一次"的现实来源。
        """
        try:
            front = host_reference.policy_of(left_id)
            back = host_reference.policy_of(right_id)
        except KeyError:
            return None        # 含真实产品，本机无法量化

        front_res = normalize_host(payload, front)
        forwarded = payload
        if front.forward_form == "normalized":
            forwarded = front_res.norm_host.encode("utf-8", "surrogateescape")
        back_res = normalize_host(forwarded, back)

        same = front_res.norm_host == back_res.norm_host
        pair = f"**{left_id} → {right_id}**"
        if same:
            describe = (f"若 {pair} 串联：两侧把同一段 Host 都认成 "
                        f"`{front_res.norm_host}` → 无站点 / 缓存键错位")
        else:
            describe = (f"若 {pair} 串联：前置认成 `{front_res.norm_host}`"
                        f"（它据此选路由 / 算缓存键），后端认成 "
                        f"`{back_res.norm_host}`（它据此选站）→ "
                        f"攻击者实际到达的是**后者**，而按前置的判定他本不该到达")

        return Quantified(
            label="虚拟主机错位",
            describe=describe,
            values={"front": left_id, "back": right_id,
                    "norm_front": front_res.norm_host,
                    "norm_back": back_res.norm_host},
            numbers=(front_res.norm_host, back_res.norm_host),
            verified=True,
        )

    # ---------------------------------------------------------------- PoC 片段

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的 Host 片段：算"前置认的站 / 后端认的站"。"""
        return {
            "imports": ("from ced.impls import host_reference\n"
                        "from ced.impls.host_norm import normalize_host"),
            "measure_body": (
                "    try:\n"
                "        front_policy = host_reference.policy_of(FRONT)\n"
                "        back_policy = host_reference.policy_of(BACK)\n"
                "    except KeyError:\n"
                "        return None\n"
                "    front_res = normalize_host(PAYLOAD, front_policy)\n"
                "    forwarded = PAYLOAD\n"
                "    if front_policy.forward_form == \"normalized\":\n"
                "        forwarded = front_res.norm_host.encode(\"utf-8\")\n"
                "    back_res = normalize_host(forwarded, back_policy)\n"
                "    return front_res.norm_host, back_res.norm_host"),
            "report_body": (
                "        front_host, back_host = got\n"
                "        print(f\"前置认的站    {front_host}\")\n"
                "        print(f\"后端认的站    {back_host}\")\n"
                "        print(f\"站点错位      {'是' if front_host != back_host else '否'}\")\n"
                "        expect_mismatch = EXPECT[0] != EXPECT[1]\n"
                "        ok = (front_host != back_host) == expect_mismatch\n"
                "        print(f\"断言        {'PASS' if ok else 'FAIL'}\"\n"
                "              f\"（期望错位={expect_mismatch}）\")"),
        }


__all__ = ["HostNormAdapter", "KIND_HOST_NORM", "KIND_ACCEPTANCE",
           "KIND_SYNTAX_DETAIL", "BOUNDARY_KINDS", "COMPARE_KEYS", "meta_of"]
