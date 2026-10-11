"""扫描主流程：计划 → 差分 → 判定 → 最小化 → 链式复现。

这个是"编排"，不含领域知识；领域知识全在 adapter 里。
"""
from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass, field

from .classify.upgradability import judge
from .contracts import Divergence, Finding, ProbeRejected
from .differ.comparator import compare, diff_keys


def case_id_of(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()[:8]


def plan_jobs(adapter, impl_ids: list[str], mode: str = "axis") -> list[tuple[str, str, str]]:
    """返回 (left, right, axis) 列表。

    axis  —— 适配器声明的定向对照（每个轴一对，归因清晰），
             **外加**任何未被定向对照覆盖的实现（例如客户自己的产品）
             与其余实现的交叉对照 —— 否则客户交了产品却被静默跳过。
    cross —— 全部两两组合（交叉矩阵，用于发现未预设的分歧）
    """
    if mode == "cross":
        return [(a, b, "cross") for a, b in itertools.combinations(impl_ids, 2)]

    known = set(impl_ids)
    jobs: list[tuple[str, str, str]] = []
    covered: set[str] = set()
    seen: set[frozenset] = set()

    for axis, (left, right) in adapter.pairs().items():
        if left in known and right in known:
            jobs.append((left, right, axis))
            covered.update((left, right))
            seen.add(frozenset((left, right)))

    for impl in impl_ids:
        if impl in covered:
            continue
        for other in impl_ids:
            if other == impl:
                continue
            key = frozenset((impl, other))
            if key in seen:
                continue
            seen.add(key)
            jobs.append((impl, other, "cross"))

    return jobs


@dataclass
class ScanResult:
    total_cases: int = 0
    jobs: int = 0
    divergences: list[Divergence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: 参与判定的观测字段（供报告/前端渲染"双侧观测"表，避免各处重复定义）
    compare_keys: tuple[str, ...] = ()
    #: 参与本次扫描的全部实现 id（热力图需要完整矩阵，而不只是出过分歧的对）
    impl_ids: list[str] = field(default_factory=list)
    #: 本次扫描的领域适配器名 —— 决定 PoC 量化口径与报告口径
    domain: str = ""
    #: 前置按自身策略拒绝、因而**不可观测**的用例数（跳过，不合成观测）
    rejected_cases: int = 0

    @property
    def security(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict.is_security]


def scan(adapter, evaluator, *, mode: str = "axis", limit: int | None = None,
         seed: int = 42, do_minimize: bool = True, on_progress=None) -> ScanResult:
    """跑一次差分扫描。

    语料只有一处来源：领域适配器自带的手写轴（``adapter.corpus()`` 经
    ``adapter.expand`` 定向变异）。模型不参与"往哪里搜" —— 它的位置在结论之后。

    ``on_progress(done, total, result)`` 每个实现对跑完时调用一次；第三个参数是
    **活的** ScanResult —— 中断时调用方能拿到已完成的部分结果，而不是全丢。
    """
    rng = random.Random(seed)
    impl_ids = list(evaluator.specs)
    handwritten = adapter.expand(adapter.corpus(), rng)
    if limit is not None:
        handwritten = handwritten[:limit]

    jobs = plan_jobs(adapter, impl_ids, mode)
    result = ScanResult(total_cases=len(handwritten),
                        jobs=len(jobs),
                        compare_keys=tuple(adapter.compare_keys),
                        impl_ids=list(impl_ids),
                        domain=adapter.name)

    def run_case(left_id: str, right_id: str, axis: str, payload: bytes) -> None:
        try:
            left = evaluator(left_id, payload)
            right = evaluator(right_id, payload)
        except ProbeRejected:
            # 前置按自身策略拒绝了这条请求 → 后端视角不存在。
            # 跳过并计数：既不中止整轮扫描，也绝不合成一个"看起来像观测"的结果。
            result.rejected_cases += 1
            return
        div = compare(case_id_of(payload), axis, payload,
                      left, right, adapter.compare_keys)
        if div is None:
            return
        result.divergences.append(div)

        kind = adapter.classify([d.key for d in div.diffs])
        verdict = judge(div, kind, adapter, evaluator)
        finding = Finding(divergence=div, verdict=verdict,
                          original_len=len(payload))

        if do_minimize and verdict.is_security:
            def keeps_divergence(candidate: bytes) -> bool:      # 最小化用的谓词
                try:
                    lv = evaluator(left_id, candidate)
                    rv = evaluator(right_id, candidate)
                except ProbeRejected:
                    # 前置拒了这条更小的候选 → 观测不到，别拿它替换原样本
                    # （最小化只是让样本更好读，不值得为它冒任何风险）
                    return False
                return bool(diff_keys(lv, rv, adapter.compare_keys))

            minimized = adapter.minimize(payload, keeps_divergence)
            finding.minimized = minimized
            finding.minimized_len = len(minimized)

        if verdict.is_security:
            # 链路量化必须针对**这条发现自己的那一对**，而不是拓扑里固定的链路，
            # 否则会出现"安全级发现"配着"两侧理解一致"的自相矛盾。
            # 量化口径是**领域知识**（分帧=被夹带字节数，路径=资源错位），故由适配器给出。
            # 含真实产品（chain 观测）时适配器改用实测字段量化 —— 不再一律"未量化"。
            quantified = adapter.quantify(finding.minimized or payload,
                                          left_id, right_id, div=div)
            if quantified is not None:
                finding.chain_evidence = quantified.describe

        result.findings.append(finding)

    for done, (left_id, right_id, axis) in enumerate(jobs, start=1):
        for _, payload in handwritten:
            run_case(left_id, right_id, axis, payload)
        if on_progress is not None:
            on_progress(done, len(jobs), result)

    return result
