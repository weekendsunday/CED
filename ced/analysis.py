"""结构化分析层：把一次差分做成字典。

**单一真源**：判定逻辑只在这里调用一次 ——
CLI、网页、报告都从这里取结果，避免各写一遍导致漂移。
"""
from __future__ import annotations

import base64

from .classify.upgradability import finalize, judge
from .differ.comparator import compare, diff_keys
from .pipeline import case_id_of
from .report.fixview import fix_view


def analyze(payload: bytes, left_id: str, right_id: str,
            evaluator, adapter, *, minimize: bool = False) -> dict:
    """对一份字节做一次差分分析。**总是返回字典**，用 diverged 表示有无分歧。"""
    left = evaluator(left_id, payload)
    right = evaluator(right_id, payload)

    result: dict = {
        "left": left_id,
        "right": right_id,
        "diverged": False,
        "payload_len": len(payload),
        "payload_repr": repr(payload),
        "observations": {k: [left.get(k), right.get(k)]
                         for k in adapter.compare_keys},
    }

    div = compare(case_id_of(payload), "probe", payload,
                  left, right, adapter.compare_keys)
    if div is None:
        return result

    kind = adapter.classify([d.key for d in div.diffs])
    verdict = judge(div, kind, adapter, evaluator)
    quantified = None
    if verdict.is_security:
        quantified = adapter.quantify(payload, left_id, right_id, div=div)
    # 量化结果参与定级（实测→严重；有错位→类型上限；量化不了→降档）
    finalize(verdict, adapter, quantified)

    result.update({
        "diverged": True,
        "diff_keys": div.keys,
        "kind": kind,
        "level": verdict.level,
        "severity": verdict.severity,
        "severity_label": verdict.severity_label,
        "quantified": (quantified.describe if quantified else ""),
        "fix_view": fix_view(adapter.name, payload),
        "reason": verdict.reason,
        "controllable": verdict.controllable,
        "ablation": verdict.ablation,
        "cwe": verdict.cwe,
        "scenario": verdict.scenario,
        "effect": verdict.effect,
        "fix": verdict.fix,
        "is_security": verdict.is_security,
    })

    if minimize and verdict.is_security:
        def keeps_divergence(candidate: bytes) -> bool:
            a = evaluator(left_id, candidate)
            b = evaluator(right_id, candidate)
            return bool(diff_keys(a, b, adapter.compare_keys))

        mini = adapter.minimize(payload, keeps_divergence)
        result["minimized_b64"] = base64.b64encode(mini).decode()
        result["minimized_len"] = len(mini)
        result["minimized_repr"] = repr(mini)

    return result

