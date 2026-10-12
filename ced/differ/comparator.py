"""差分比对器。

只比较适配器声明的 ``compare_keys`` —— 其余字段属于诊断信息，
一律不参与"是否构成耦合误差"的判定。
"""
from __future__ import annotations

from ..contracts import Divergence, FieldDiff, Observation


def compare(case_id: str, axis: str, payload: bytes,
            left: Observation, right: Observation,
            compare_keys: tuple[str, ...]) -> Divergence | None:
    """一致返回 None；不一致返回 Divergence。"""
    diffs = [
        FieldDiff(key, left.get(key), right.get(key))
        for key in compare_keys
        if left.get(key) != right.get(key)
    ]
    if not diffs:
        return None
    return Divergence(case_id=case_id, axis=axis, payload=payload,
                      left=left, right=right, diffs=diffs)


def diff_keys(left: Observation, right: Observation,
              compare_keys: tuple[str, ...]) -> list[str]:
    """只取差异字段名（判定器与最小化复用）。"""
    return [k for k in compare_keys if left.get(k) != right.get(k)]
