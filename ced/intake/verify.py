"""验证层 —— 做扫描器的裁判。

外部发现（nuclei / Burp / HAR / curl / 普通清单）在这里被当作**待验证的假设**，
喂进与手写语料**完全相同**的差分 oracle 链：按领域抽取待测对象 → 跑适配器声明的
两两对照 → ``differ.comparator.compare`` 判结构分歧 → ``classify.upgradability.judge``
定分级与可控性。输出三态，口径是硬的：

    confirmed     至少一对实现产生了结构分歧（level 原样采信 judge，不自己判）
    refuted       所有对的全部实现对这份输入理解一致
    unverifiable  这份输入无法被任何领域的解析器接受（缺什么就写清缺什么）

任何单条异常都被收进 ``unverifiable.detail``，绝不让一批里的一条拖垮整批。
"""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import urlsplit

from ..adapters import get, names as all_domains
from ..classify.upgradability import finalize, judge
from ..differ.comparator import compare, diff_keys
from ..probe import Evaluator
from .model import Hypothesis, Verification

CONFIRMED = "confirmed"
REFUTED = "refuted"
UNVERIFIABLE = "unverifiable"


# --------------------------------------------------------------------------- 抽取

def _to_bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def _split(target: str):
    try:
        return urlsplit(target)
    except ValueError:
        return None


def _path_payload(h: Hypothesis) -> bytes | None:
    """url-norm / enc-norm：URL 的 path；target 不是 URL 时用原文。

    target 本身为空 → 没有任何可测对象，返回 None（该领域跳过）。
    """
    split = _split(h.target)
    path = split.path if split is not None else ""
    if not path:
        path = h.target
    if not path.strip():
        return None
    return _to_bytes(path)


def _host_payload(h: Hypothesis) -> bytes | None:
    """host-norm：URL 的 host；裸目标则取第一个 '/' 之前的部分。"""
    split = _split(h.target)
    host = split.hostname if split is not None else None
    if not host:
        core = h.target.split("/", 1)[0]
        core = core.split("@")[-1].split(":")[0]
        host = core if core else None
    if not host:
        return None
    return _to_bytes(host)


def _query_payload(h: Hypothesis) -> bytes | None:
    """query-norm：URL 的 query；target 里没有 ``?`` 就跳过本领域。"""
    if "?" not in h.target:
        return None
    split = _split(h.target)
    query = split.query if split is not None else h.target.split("?", 1)[1]
    return _to_bytes(query)


def _framing_payload(h: Hypothesis) -> bytes | None:
    """http1-framing：只有 raw 里存在完整请求（含 ``HTTP/1.``）时才试。"""
    raw = h.raw or ""
    if "HTTP/1." not in raw:
        return None
    return raw.encode("latin-1", "replace")


#: 领域 → 抽取函数。新领域默认按 url-norm 的 path 口径抽取。
EXTRACTORS = {
    "url-norm": _path_payload,
    "enc-norm": _path_payload,
    "host-norm": _host_payload,
    "query-norm": _query_payload,
    "http1-framing": _framing_payload,
}

#: 领域 → 跳过时"缺什么"的人话描述
_MISSING = {
    "url-norm": "可解析的请求目标",
    "enc-norm": "可解析的请求目标",
    "host-norm": "可解析的 host（target 里没有主机名）",
    "query-norm": "URL 查询串（target 里没有 `?`）",
    "http1-framing": "完整请求字节（raw 里没有 `HTTP/1.` 请求行）",
}


def _case_id(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()[:8]


def _candidates(h: Hypothesis, domains: list[str]):
    """按领域抽取待测对象，返回 ``(候选, 跳过说明)``。"""
    candidates: list[tuple[str, object, bytes]] = []
    skipped: list[str] = []
    for domain in domains:
        try:
            adapter = get(domain)
        except KeyError:
            skipped.append(f"{domain}（领域未注册）")
            continue
        extractor = EXTRACTORS.get(domain, _path_payload)
        try:
            payload = extractor(h)
        except Exception as exc:      # noqa: BLE001 —— 抽取失败只影响本领域
            skipped.append(f"{domain}（抽取失败：{type(exc).__name__}: {exc}）")
            continue
        if payload is None:
            skipped.append(f"{domain}（缺 {_MISSING.get(domain, '可用输入')}）")
            continue
        candidates.append((domain, adapter, payload))
    return candidates, skipped


# --------------------------------------------------------------------------- 单领域验证

def _minimize_b64(adapter, evaluator, left_id: str, right_id: str,
                  payload: bytes) -> str | None:
    """在该领域的语义单元上压小样本，只保留仍构成分歧的最小字节。"""
    def keeps_divergence(candidate: bytes) -> bool:
        left = evaluator(left_id, candidate)
        right = evaluator(right_id, candidate)
        return bool(diff_keys(left, right, adapter.compare_keys))

    if not keeps_divergence(payload):
        return None
    minimized = adapter.minimize(payload, keeps_divergence)
    return base64.b64encode(minimized).decode("ascii")


def _run_domain(h: Hypothesis, domain: str, adapter, payload: bytes
                ) -> Verification | None:
    """在本领域跑全部对照对；命中返回 confirmed，全一致返回 None。"""
    evaluator = Evaluator(adapter.specs())
    for axis, pair in adapter.pairs().items():
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            continue
        left_id, right_id = pair
        if left_id not in evaluator.specs or right_id not in evaluator.specs:
            continue
        left = evaluator(left_id, payload)
        right = evaluator(right_id, payload)
        div = compare(_case_id(payload), axis, payload, left, right,
                      adapter.compare_keys)
        if div is None:
            continue

        kind = adapter.classify(list(div.keys))
        verdict = judge(div, kind, adapter, evaluator)
        quantified = None
        if verdict.is_security:
            try:
                quantified = adapter.quantify(payload, left_id, right_id, div=div)
            except Exception:      # noqa: BLE001 —— 量化失败只影响档位，不影响结论
                quantified = None
        # 与内建样本、网页控制台同一条定级口径：量化结果参与定级，别只在一条链路上生效
        finalize(verdict, adapter, quantified)
        try:
            minimized_b64 = _minimize_b64(adapter, evaluator, left_id, right_id,
                                          payload)
        except Exception as exc:      # noqa: BLE001 —— 最小化失败不影响结论
            minimized_b64 = None
            minimize_note = f"（最小化失败：{type(exc).__name__}: {exc}）"
        else:
            minimize_note = ""

        detail = (f"{domain}：{left_id} 与 {right_id} 在轴 `{axis}` 上产生结构分歧"
                  f"（字段 {list(div.keys)}）；judge 级别={verdict.level}　危险等级={verdict.severity}{minimize_note}")
        return Verification(
            hypothesis=h, verdict=CONFIRMED, domain=domain,
            left=left_id, right=right_id, level=verdict.level, kind=kind,
            severity=verdict.severity,
            reason=verdict.reason, evidence=verdict.ablation or "",
            quantified=(quantified.describe if quantified else ""),
            payload=bytes(payload),
            minimized_b64=minimized_b64, detail=detail,
        )
    return None


# --------------------------------------------------------------------------- 入口

def verify(hypotheses: list[Hypothesis], *,
           domains: list[str] | None = None) -> list[Verification]:
    """把一批假设喂进 oracle 链，逐条给出三态结论。

    ``domains`` 为空或 None 表示用 ``ced.adapters.names()`` 的全部领域。
    单条假设的任何异常都会被收进该条的 ``unverifiable.detail``，不影响其余条目。
    """
    if not domains:
        domains = all_domains()
    else:
        domains = list(domains)

    results: list[Verification] = []
    for hypothesis in hypotheses:
        try:
            results.append(_verify_one(hypothesis, domains))
        except Exception as exc:      # noqa: BLE001 —— 单条失败绝不丢整批
            results.append(Verification(
                hypothesis=hypothesis, verdict=UNVERIFIABLE,
                detail=f"验证过程异常：{type(exc).__name__}: {exc}"))
    return results


def _verify_one(h: Hypothesis, domains: list[str]) -> Verification:
    candidates, skipped = _candidates(h, domains)
    if not candidates:
        reason = "；".join(skipped) if skipped else "没有可用的验证领域"
        return Verification(
            hypothesis=h, verdict=UNVERIFIABLE,
            detail=f"没有任何领域能接受这份输入 —— {reason}")

    tried: list[str] = []
    for domain, adapter, payload in candidates:
        try:
            result = _run_domain(h, domain, adapter, payload)
        except Exception as exc:      # noqa: BLE001 —— 换下一个领域继续
            tried.append(f"{domain} 验证异常：{type(exc).__name__}: {exc}")
            continue
        if result is not None:
            return result
        tried.append(f"{domain}：全部实现对同一份输入理解一致")

    return Verification(
        hypothesis=h, verdict=REFUTED,
        domain=",".join(domain for domain, _, _ in candidates),
        detail=("未证实 —— " + "；".join(tried)
                + "。注意：这只说明**这些领域的参照实现看不出分歧**，"
                  "不等于这条发现是假的（真实产品可能有本工具未建模的归一化口径）"))


__all__ = ["CONFIRMED", "REFUTED", "UNVERIFIABLE", "EXTRACTORS", "verify"]
