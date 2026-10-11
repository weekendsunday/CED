"""指标与交叉矩阵热力图：纯计算，不碰网络、不读文件。

输入是 ``ced.pipeline.ScanResult``，输出是可直接序列化的字典 —— 控制台的
``/api/scan/metrics`` 与 ``/api/scan/heatmap`` 两个端点直接把它转成 JSON。

口径（前端的 ``title`` 逐条照抄这同一份说法，避免两处描述漂移）：
  * 安全占比        = 安全级发现数 / 分歧数
  * 消融定位率      = 安全级发现里 controllable 为真的比例（没有安全级时记 0）
  * 唯一化压缩比    = 唯一 case_id 数 / 分歧数（越低说明同一份字节被反复计入）
  * 最小化压缩比    = Σ最小化长度 / Σ原始长度，只统计真的被最小化过的发现
"""
from __future__ import annotations

#: 级别排序：数字越小越严重。决定一格（以及一整条发现列表）里谁代表最严重级别。
_LEVEL_RANK = {"security": 0, "unknown": 1, "compatibility": 2}


def scan_metrics(result, *, elapsed: float | None = None) -> dict:
    """一次扫描的汇总指标；``elapsed`` 由调用方透传（秒，不参与四舍五入）。

    返回值**恰好**是下面这些键 —— 前端按名字取用，多一个少一个都会漂移。
    """
    findings = list(getattr(result, "findings", None) or [])
    divergences = len(getattr(result, "divergences", None) or [])
    total_cases = int(getattr(result, "total_cases", 0) or 0)
    jobs = int(getattr(result, "jobs", 0) or 0)

    by_level = {"security": 0, "unknown": 0, "compatibility": 0}
    for f in findings:
        level = f.verdict.level
        if level in by_level:
            by_level[level] += 1
    security = by_level["security"]

    # 分母为 0 时各比率都有各自的"空"约定，不是统一给 0 —— 见模块 docstring
    security_share = round(security / divergences, 4) if divergences else 0.0

    sec_findings = [f for f in findings if f.verdict.level == "security"]
    controllable_rate = (
        round(sum(1 for f in sec_findings if f.verdict.controllable)
              / len(sec_findings), 4)
        if sec_findings else 0.0)

    unique_case_ratio = (
        round(len({f.case_id for f in findings}) / divergences, 4)
        if divergences else 1.0)

    # 只统计 minimized_len > 0 的发现：没最小化的发现不该把压缩比稀释成 1
    min_sizes = [f.minimized_len for f in findings if f.minimized_len > 0]
    orig_sizes = [f.original_len for f in findings if f.minimized_len > 0]
    total_orig = sum(orig_sizes)
    minimize_ratio = round(sum(min_sizes) / total_orig, 4) if total_orig else 1.0

    if elapsed is None or total_cases == 0:
        avg_seconds_per_case = None
    else:
        avg_seconds_per_case = round(elapsed / total_cases, 4)

    return {
        "total_cases": total_cases,
        "jobs": jobs,
        "divergences": divergences,
        "by_level": by_level,
        "security": security,
        "security_share": security_share,
        "controllable_rate": controllable_rate,
        "unique_case_ratio": unique_case_ratio,
        "minimize_ratio": minimize_ratio,
        "minimized_count": len(min_sizes),
        "elapsed": elapsed,
        "avg_seconds_per_case": avg_seconds_per_case,
    }


def matrix_heatmap(result, impl_ids: list[str]) -> dict:
    """交叉矩阵热力图：行 = 左实现，列 = 右实现。

    一格代表「这两个实现」这一对，**与方向无关**：同一条发现同时记到
    ``cells[左][右]`` 与 ``cells[右][左]``，所以横着看、竖着看都能得到
    「这两个实现合不来」。对角线恒为空 —— 一个实现跟自己对不出分歧。

    同一格里多条发现：只保留最严重级别、第一个非空 kind，case_ids 取前 5 个。
    """
    impls = list(impl_ids)
    index = {impl: i for i, impl in enumerate(impls)}
    n = len(impls)

    # 先把每条 finding 的引用撒进两个对称格，再统一折叠成摘要 ——
    # 边撒边折叠的话，第二次写入时信息已经被第一次揉掉了
    buckets: list[list[list]] = [[[] for _ in range(n)] for _ in range(n)]
    for f in getattr(result, "findings", None) or []:
        div = f.divergence
        left, right = div.left.impl_id, div.right.impl_id
        if left == right or left not in index or right not in index:
            continue
        buckets[index[left]][index[right]].append(f)
        buckets[index[right]][index[left]].append(f)

    cells: list[list[dict]] = []
    max_count = 0
    for i in range(n):
        row: list[dict] = []
        for j in range(n):
            items = buckets[i][j]
            count = len(items)
            max_count = max(max_count, count)
            if not count:
                row.append({"count": 0, "security": 0, "level": None,
                            "kind": "", "case_ids": []})
                continue
            level = min((f.verdict.level for f in items),
                        key=lambda lv: _LEVEL_RANK.get(lv, 3))
            kind = next((f.verdict.kind for f in items if f.verdict.kind), "")
            row.append({
                "count": count,
                "security": sum(1 for f in items
                                if f.verdict.level == "security"),
                "level": level,
                "kind": kind,
                "case_ids": [f.case_id for f in items[:5]],
            })
        cells.append(row)

    return {"impls": impls, "max": max(1, max_count), "cells": cells}
