"""HTTP/1.1 消息分帧领域适配器。"""
from __future__ import annotations

import random

from ..classify.upgradability import ablate_headers
from .. import httpmsg
from ..contracts import (DEFAULT_COMPARE_KEYS, HardenedRequest, ImplSpec,
                         Quantified)
from ..impls import reference
from ..mutate import axes, engine
from ..minimize.ddmin import minimize_headers
from ..orchestrate.chain import chain_evidence
from .base import HARDEN_NOTE, HARDEN_NOOP_NOTE, HARDEN_REJECT_NOTE
from .base import HARDEN_NOTE, HARDEN_NOOP_NOTE, HARDEN_REJECT_NOTE
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
        "severity": "high",   # 类型上限（证据不足时按规则降档）
        "scenario": "desync",
        "fix": "对 CL 与 TE 并存、非规范 CL、冲突 CL、TE 终编码非 chunked 的请求一律 400 拒绝；上游必须在转发前完成定帧并重写为规范形式",
    },
    KIND_FRAMING_INTERP: {
        "effect": "定帧来源或请求体长度解释不同 → 边界可能错位（是否可升级取决于字节能否被夹带）",
        "cwe": "CWE-444",
        "severity": "medium",   # 类型上限（证据不足时按规则降档）
        "scenario": "desync",
        "fix": "统一 CL/TE 优先级与语法接受度；两侧对齐同一份定帧规范",
    },
    KIND_ACCEPTANCE: {
        "effect": "一侧接受、一侧拒绝 → 上游放行下游拒绝（或反之），可造成防护绕过或拒绝服务",
        "cwe": "CWE-436",
        "severity": "low",   # 类型上限（证据不足时按规则降档）
        "scenario": "bypass",
        "fix": "统一对畸形语法的拒绝策略，避免一侧宽容一侧严格",
    },
    KIND_SYNTAX_DETAIL: {
        "effect": "仅诊断信息（告警/备注）不同，观测到的消息结构一致 → 无直接安全后果",
        "cwe": None,
        "severity": "info",   # 类型上限（证据不足时按规则降档）
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
    #: 空 = 本领域观测的是消息边界而不是文本，"只是写法差异"无处适用
    content_keys: tuple[str, ...] = ()
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

    #: 基准实现 —— 修复形态（单一 CL、纯十进制、不并存 TE）按它的口径写
    baseline_id = "ref-cl-first"

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
            # 只有真被夹带了字节，才算"确实错位"（两侧都消费同样多 → 没有错位）
            mismatch=evidence.smuggled_len != 0,
            # 前置一个字节都没转发 → 这条链路不成立（不是"两侧读成一样"）
            blocked=evidence.forwarded == 0,
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
            mismatch=smuggled != 0,
            measured=True,          # 前置转发的字节数是探针实测，不是模型推演
        )

    # ---------------------------------------------------------------- 修复形态

    def harden(self, payload: bytes):
        """把请求重写成**无歧义的分帧形态**（也就是"上游转发前该重写成什么"）。

        规范形态：行尾统一 CRLF、请求行只留单空格、``obs-fold`` 折行展开、
        ``Content-Length`` 只留一条且是纯十进制、不与 ``Transfer-Encoding`` 并存、
        ``TE`` 的终编码必须是 ``chunked``。

        这些写法本来就应该**直接 400 拒绝**（RFC 7230 §3.3.3）。所以
        ``reject=True`` 时仍把规范形态一并给出来 —— 先看清是哪几个字节在制造歧义，
        才有得选：拒绝，还是在你控得住的上游把它重写掉。
        """
        msg = httpmsg.split(payload)
        if msg is None:
            return None

        lines = list(msg.lines)
        changes: list[str] = []
        reject = False

        head = lines[0].strip()
        parts = head.split()
        if len(parts) == 3:
            canonical_line = b" ".join(parts)
            if canonical_line != lines[0]:
                changes.append("请求行空白折叠为单空格")
            lines[0] = canonical_line

        headers: list[bytes] = []
        for line in lines[1:]:
            if line[:1] in (b" ", b"\t") and headers:
                headers[-1] = headers[-1] + b" " + line.strip()
                if "obs-fold 折行展开为单行" not in changes:
                    changes.append("obs-fold 折行展开为单行")
            else:
                headers.append(line)

        def value_of(line: bytes) -> bytes:
            idx = line.find(b":")
            return line[idx + 1:].strip() if idx >= 0 else b""

        cl = [i for i, ln in enumerate(headers)
              if httpmsg.header_name(ln) == b"content-length"]
        te = [i for i, ln in enumerate(headers)
              if httpmsg.header_name(ln) == b"transfer-encoding"]

        drop: set[int] = set()
        if len(cl) > 1:
            reject = True
            changes.append(f"重复的 Content-Length（{len(cl)} 条）只保留第一条")
            drop.update(cl[1:])
        if cl:
            raw_value = value_of(headers[cl[0]])
            digits = raw_value[1:] if raw_value[:1] == b"+" else raw_value
            if not digits.isdigit():
                reject = True
                changes.append(f"Content-Length 不是十进制"
                               f"（`{httpmsg.brief(raw_value)}`）→ 无法规范化，只能拒绝")
            else:
                canonical_value = str(int(digits)).encode()
                if canonical_value != raw_value:
                    headers[cl[0]] = b"Content-Length: " + canonical_value
                    changes.append(f"Content-Length 去掉多余写法："
                                   f"`{httpmsg.brief(raw_value)}` → "
                                   f"`{httpmsg.brief(canonical_value)}`")
        if te:
            if cl:
                reject = True
                changes.append("Content-Length 与 Transfer-Encoding 并存"
                               " → 删掉 TE，只留一种定帧依据")
                drop.update(te)
            else:
                final = value_of(headers[te[-1]]).rsplit(b",", 1)[-1].strip().lower()
                if final != b"chunked":
                    reject = True
                    changes.append(f"Transfer-Encoding 终编码不是 chunked"
                                   f"（`{httpmsg.brief(final)}`）→ 不能作为定帧依据")

        if b"\n" in msg.tail.replace(b"\r\n", b""):
            changes.append("请求体里还有裸 LF —— 分块体必须以 CRLF 终止"
                           "（本工具只重写头部，体里的写法要在实现侧改）")

        sep = msg.sep
        if msg.eol != httpmsg.CRLF:
            changes.append("行尾统一为 CRLF")
            sep = httpmsg.CRLF + httpmsg.CRLF
        kept = [ln for i, ln in enumerate(headers) if i not in drop]
        fixed = httpmsg.Message(lines=[lines[0]] + kept, eol=httpmsg.CRLF,
                                sep=sep, tail=msg.tail).build()

        note = (HARDEN_REJECT_NOTE if reject
                else HARDEN_NOTE if changes else HARDEN_NOOP_NOTE)
        return HardenedRequest(domain=self.name, fixed=fixed, changes=changes,
                               note=note, reject=reject)
