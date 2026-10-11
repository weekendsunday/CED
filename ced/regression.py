"""已知案例反验证：平台有效性自证（方案 §6 的验收基线）。

**先证明能重新挖出已知的，再谈能发现未知的。**

每次改动归一化 / 分类 / 判定 / 最小化后都必须跑。断言刻意做成**非空转**的：

  1. 必须真的产出分歧 —— 不是"没跑通也算过"；
  2. 分歧类型必须符合案例标注的**已知类别**（标注来自 RFC / 公开研究，不是工具的输出）；
  3. 必须在**预期的结构字段**上出现差异，而不是只要 kind 对就算过；
  4. 对照的两个实现必须是**不同的策略** —— 防"自己跟自己比"。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
from pathlib import Path

from .adapters import get as get_adapter
from .contracts import ImplSpec
from .differ.comparator import compare
from .pipeline import case_id_of
from .probe import Evaluator

CASES_DIR = Path(__file__).resolve().parent / "cases" / "known"


@dataclass
class CaseOutcome:
    name: str
    passed: bool
    detail: str


def load_cases(directory: Path | str = CASES_DIR) -> list[dict]:
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(directory.glob("*.json"))]


def _knobs(policy):
    """策略的可比部分（排除仅用于标识的 name）。"""
    return replace(policy, name="")


def _evaluate(adapter, spec: dict) -> CaseOutcome:
    name = spec["id"]
    left_id, right_id = spec["left"], spec["right"]

    try:
        left_policy = policy_for(adapter, left_id)
        right_policy = policy_for(adapter, right_id)
    except KeyError as exc:
        return CaseOutcome(name, False, f"案例引用了不存在的实现：{exc}")

    if _knobs(left_policy) == _knobs(right_policy):
        return CaseOutcome(name, False, "对照的两个实现策略完全相同 —— 空转")

    domain = adapter.name
    payload = base64.b64decode(spec["payload_b64"])
    evaluator = Evaluator([
        ImplSpec(impl_id=left_id, name=left_id, runner="local",
                 policy=left_id, domain=domain),
        ImplSpec(impl_id=right_id, name=right_id, runner="local",
                 policy=right_id, domain=domain),
    ])
    left = evaluator(left_id, payload)
    right = evaluator(right_id, payload)
    div = compare(case_id_of(payload), spec.get("axis", "known"), payload,
                  left, right, adapter.compare_keys)
    if div is None:
        return CaseOutcome(name, False, "未检出分歧")

    kind = adapter.classify([d.key for d in div.diffs])
    expect_kind = spec.get("expect_kind")
    if expect_kind and kind != expect_kind:
        return CaseOutcome(name, False, f"类型不符：{kind} != {expect_kind}")

    keys = set(div.keys)
    missing = [f for f in spec.get("expect_fields", []) if f not in keys]
    if missing:
        return CaseOutcome(name, False, f"预期字段未出现：{missing}")

    return CaseOutcome(name, True, f"{kind} @ {sorted(keys)}")


def policy_for(adapter, impl_id: str):
    """取某个领域里某个参照实现的策略（各领域的注册表不同，统一走 impls）。"""
    from .impls import policy_for as lookup
    return lookup(adapter.name, impl_id)


def real_obs_summary(cases: list[dict] | None = None,
                     directory: Path | str = CASES_DIR) -> str:
    """已知案例里带实机观测记录（``real_obs``）的条数与产品清单。

    ``real_obs`` 是 docker 实机采到的真实产品观测（拒绝状态码 / 转发后的定帧
    字段），只作证据存档与口径对照，**不参与** 47/47 的判定 —— 模型内反验证与
    实机观测是两回事，混在一起就会互相污染口径。
    """
    cases = cases if cases is not None else load_cases(directory)
    with_obs = [c for c in cases if c.get("real_obs")]
    if not with_obs:
        return "实机观测记录：无（cases/known 里没有 real_obs 字段）"
    products = sorted({p for c in with_obs for p in c["real_obs"]
                       if p != "captured"})
    return (f"实机观测记录：{len(with_obs)}/{len(cases)} 条案例带真实产品观测"
            f"（{', '.join(products)}）")


def run(directory: Path | str = CASES_DIR,
        cases: list[dict] | None = None) -> list[CaseOutcome]:
    """跑全部已知案例。每个案例按自己的 ``domain`` 选适配器（缺省分帧领域）。"""
    from .adapters import get as get_adapter

    cases = cases if cases is not None else load_cases(directory)
    adapters: dict[str, object] = {}
    outcomes: list[CaseOutcome] = []
    for spec in cases:
        domain = spec.get("domain", "http1-framing")
        if domain not in adapters:
            try:
                adapters[domain] = get_adapter(domain)
            except KeyError:
                outcomes.append(CaseOutcome(
                    spec.get("id", "?"), False, f"案例引用了不存在的领域：{domain}"))
                continue
        outcomes.append(_evaluate(adapters[domain], spec))
    return outcomes
