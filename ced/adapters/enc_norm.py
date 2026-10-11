"""编码 / Unicode 归一化领域适配器 —— 第三个领域。

它再次证明"加领域不改引擎"：差分、消融、最小化、链式量化、端到端 PoC、
落库、报告、控制台全部原样复用；变化只体现在这个文件里（语料、分类、后果映射）。

观测对象是一段**待解释的字节**（一个参数值 / 关键字的原文，可含百分号转义与
原始高字节）。判定的是**同一段字节被两侧读成了不同文本**。

与 url-norm 的分工：url-norm 管**路径结构**（`..` 解算、斜杠折叠、大小写……），
本领域管**字节到文本的解释**（过长 UTF-8、UTF-8/Latin-1、Unicode 规范化、
全角折叠、`%uXXXX`、孤立代理项、`%00`）。两者可以串联，但语料与开关不重叠。

判定链刻意**不引入专用模型**（不在模型里维护"危险关键字表"）：
一旦某个领域有了专用判定器，``judge()`` 就不再是单点真源，创新点②自己就破了。
"""
from __future__ import annotations

import random

from ..contracts import ImplSpec, Quantified
from ..classify.upgradability import still_diverges
from ..impls import enc_reference
from ..impls.enc_norm import interpret
from ..mutate import enc_axes
from .base import http_request_fields
from .registry import register

# ---- 分歧类型（判定器按此升级/降级）----
KIND_ENC_INTERP = "enc_interpretation"     # 差异来自"这段字节被读成了不同文本"
KIND_ENC_ACCEPT = "enc_acceptance"         # 一侧接受一侧拒绝
KIND_SYNTAX_DETAIL = "syntax_detail"       # 仅诊断信息不同

#: 参与差分比对的观测字段。适配器可覆盖。
COMPARE_KEYS: tuple[str, ...] = (
    "accepted",
    "status",
    "norm_text",
    "codepoints",
    "decoded_layers",
)

#: 具备"分歧落在『这段字节读成了什么』上"结构性前提的类型
BOUNDARY_KINDS = (KIND_ENC_INTERP,)

_FIX_COMMON = (
    "检查侧与执行侧必须共用同一套解码与 Unicode 规范化口径：显式拒绝过长 UTF-8 与"
    "孤立代理项、明确字节的字符编码（UTF-8 还是 Latin-1）、统一是否做 NFC/NFD 与"
    "全角折叠、不认 `%uXXXX` 遗留转义、在 NUL 处不做隐式截断；"
    "先解码/规范化成规范形式，再在规范形式上做匹配与执行，两侧不一致就拒绝"
)

_KIND_MAP = {
    KIND_ENC_INTERP: {
        "effect": "同一段字节被两侧读成了**不同文本**（过长 UTF-8 / UTF-8 与 Latin-1 / "
                  "NFC 与 NFD / 全角折叠 / `%uXXXX` / 大小写折叠 / 孤立代理项 / NUL 截断"
                  "口径不一致）→ 检查侧看到的无害形式与执行侧解出的危险形式不同，"
                  "关键字黑名单 / 路径前缀 / 扩展名白名单等过滤器被绕过（CWE-180）",
        "cwe": "CWE-180",
        "scenario": "filter",
        "fix": _FIX_COMMON,
    },
    KIND_ENC_ACCEPT: {
        "effect": "一侧接受、一侧拒绝同一段字节 → 检查侧放行、执行侧拒绝（或反之），"
                  "可造成过滤器绕过或可用性差异",
        "cwe": "CWE-436",
        "scenario": "bypass",
        "fix": "统一对非规范编码的接受策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息不同，两侧读到的文本一致 → 无直接安全后果",
        "cwe": None,
        "scenario": None,
        "fix": "无需修复；可作为兼容性记录",
    },
}


def meta_of(kind: str) -> dict:
    return _KIND_MAP.get(kind, _KIND_MAP[KIND_SYNTAX_DETAIL])


@register
class EncNormAdapter:
    """编码 / Unicode 归一化领域（字节 → 文本解释）。"""

    name = "enc-norm"
    compare_keys: tuple[str, ...] = COMPARE_KEYS
    boundary_kinds: tuple[str, ...] = BOUNDARY_KINDS
    kind_acceptance: str = KIND_ENC_ACCEPT

    def __init__(self, variants_per_case: int = 6) -> None:
        self._mutator = enc_axes.Mutator(variants_per_case=variants_per_case)

    def meta(self, kind: str) -> dict:
        return meta_of(kind)

    # ---------------------------------------------------------------- 实现与语料

    def specs(self) -> list[ImplSpec]:
        return enc_reference.specs()

    def local_parser(self) -> tuple:
        """本地解析器：编码解释内核 + 解释参照实现的策略表。"""
        return enc_reference.policy_of, interpret

    def extract(self, raw: bytes) -> bytes:
        """能认出完整请求就取请求行的 target；否则视作裸对象原样返回。"""
        fields = http_request_fields(raw)
        return fields[0] if fields is not None else raw

    def pairs(self) -> dict[str, tuple[str, str]]:
        return dict(enc_reference.AXIS_PAIRS)

    def corpus(self) -> list[tuple[str, bytes]]:
        return enc_axes.corpus()

    def expand(self, cases: list[tuple[str, bytes]],
               rng: random.Random) -> list[tuple[str, bytes]]:
        return self._mutator.expand(cases, rng)

    # ---------------------------------------------------------------- 分类

    def classify(self, diff_keys: list[str]) -> str:
        """按**精确字段名**分类（刻意不用子串匹配，与其它领域同一条纪律）。"""
        keys = set(diff_keys)
        if keys & {"norm_text", "codepoints", "decoded_layers"}:
            return KIND_ENC_INTERP
        if keys & {"accepted", "status"}:
            return KIND_ENC_ACCEPT
        return KIND_SYNTAX_DETAIL

    def ablate(self, div, evaluate) -> list[str]:
        """承载分歧的可控字节 —— 编码领域的消融实验。

        逐条"抹掉一类承载者"重放两侧：分歧消失了，说明它由那一类字节承载。
        而这些字节是攻击者直接发送的 → 可控。
        与分帧领域"逐条移除请求头"完全同一条原理，只是承载者的形态不同。
        """
        carriers: list[str] = []
        for label, transform in enc_axes.ABLATIONS:
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
        """解释领域的最小化单元是**转义片段 / 字节**（不是路径段）。"""
        return enc_axes.minimize_bytes(payload, predicate)

    # ---------------------------------------------------------------- 量化

    def quantify(self, payload: bytes, left_id: str, right_id: str, div=None):
        """量化：**同一段字节被检查侧与执行侧读成了不同文本**。

        模型与分帧 / 路径领域同构，只是数字的含义不同 ——
        分帧是"夹带了多少字节"，路径是"资源路径的错位"，
        这里是"检查侧看到的字符串 vs 执行侧看到的字符串"。
        """
        try:
            front = enc_reference.policy_of(left_id)
            back = enc_reference.policy_of(right_id)
        except KeyError:
            return None        # 含真实产品，本机无法量化

        front_res = interpret(payload, front)
        back_res = interpret(payload, back)

        same = front_res.norm_text == back_res.norm_text
        pair = f"**{left_id} → {right_id}**"
        if same:
            describe = (f"若 {pair} 串联：两侧把同一段字节都读成 "
                        f"`{front_res.norm_text}` → 无解释错位")
        else:
            describe = (f"若 {pair} 串联：检查侧读成 `{front_res.norm_text}`"
                        f"（它据此做检查），执行侧读成 `{back_res.norm_text}`"
                        f"（它据此执行）→ 检查侧漏看而执行侧认得的，"
                        f"正是攻击者可用以绕过过滤器的那部分")

        return Quantified(
            label="编码/解释错位",
            describe=describe,
            values={"front": left_id, "back": right_id,
                    "norm_front": front_res.norm_text,
                    "norm_back": back_res.norm_text},
            numbers=(front_res.norm_text, back_res.norm_text),
            verified=True,
        )

    # ---------------------------------------------------------------- PoC 脚本片段

    def poc_block(self) -> dict:
        """端到端 PoC 脚本的解释领域片段：算"检查侧看到的 / 执行侧看到的"。

        骨架（参数解析、合规门禁、--send）由 ``scenario/poc.py`` 统一提供，
        这里只填"怎么算这个领域的量化指标、怎么断言"。
        """
        return {
            "imports": ("from ced.impls import enc_reference\n"
                        "from ced.impls.enc_norm import interpret"),
            "measure_body": (
                "    try:\n"
                "        front_policy = enc_reference.policy_of(FRONT)\n"
                "        back_policy = enc_reference.policy_of(BACK)\n"
                "    except KeyError:\n"
                "        return None\n"
                "    front_res = interpret(PAYLOAD, front_policy)\n"
                "    back_res = interpret(PAYLOAD, back_policy)\n"
                "    return front_res.norm_text, back_res.norm_text"),
            "report_body": (
                "        front_text, back_text = got\n"
                "        print(f\"检查侧看到  {front_text}\")\n"
                "        print(f\"执行侧看到  {back_text}\")\n"
                "        print(f\"解释错位      {'是' if front_text != back_text else '否'}\")\n"
                "        expect_mismatch = EXPECT[0] != EXPECT[1]\n"
                "        ok = (front_text != back_text) == expect_mismatch\n"
                "        print(f\"断言        {'PASS' if ok else 'FAIL'}\"\n"
                "              f\"（期望错位={expect_mismatch}）\")"),
        }


__all__ = ["EncNormAdapter", "KIND_ENC_INTERP", "KIND_ENC_ACCEPT",
           "KIND_SYNTAX_DETAIL", "BOUNDARY_KINDS", "COMPARE_KEYS", "meta_of"]
