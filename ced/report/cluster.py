"""发现归并：把「同一对实现的同一类分歧」压成一条，并保留组内条数。

为什么要它（实测）：每个领域 40 用例就能产出上百条安全级发现，
但它们按 `(左实现, 右实现, 分歧类型)` 归并后往往只剩几十组 ——
enc 6.5×、url 5.2×、query 6.4×、host **13.8×**。报告里列上百条几乎相同的东西，
真正有区分度的几十条反而被淹没。

判据刻意做成**可机械执行**的（不靠人去判断"像不像重复"）：
    同一对实现 + 同一个分歧类型 = 同一类事实，只留一条**代表**。

代表怎么选（确定性，写在代码里而不是靠感觉）：
    1. 级别优先（security > unknown > compatibility）
    2. 然后取**最小化后最短**的那条 —— 样本越小越容易看懂，也越像可提交的 PoC
    3. 最后按 case_id 兜底排序，保证同一份输入每次选出同一条
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts import SEVERITY_RANK

#: 组内最多保留多少个 case_id（报告里只列前几个，完整清单在 JSON 里）
MAX_IDS = 10

_LEVEL_ORDER = {"security": 0, "unknown": 1, "compatibility": 2}


@dataclass(frozen=True)
class Cluster:
    """一类分歧：同一对实现 + 同一分歧类型。"""

    left: str
    right: str
    kind: str
    level: str                       # 组内最严重的**类别**
    count: int                       # 组内发现条数
    representative: object           # 保留的那条 Finding
    case_ids: list[str] = field(default_factory=list)
    #: 组内最严重的**危险等级**（五档之一）—— 报告表格按它分档，而不是按类别
    severity: str = ""

    @property
    def case_id(self) -> str:
        return self.representative.case_id

    @property
    def axis(self) -> str:
        return self.representative.divergence.axis


def _representative_key(finding) -> tuple:
    """代表选择键：级别 → **是否带实测链路证据** → 最小化后长度 → case_id。

    第二项是刻意加的：组内如果有一条拿到过"真实链路实测"（``chain_evidence``），
    就该让代表是它 —— 否则最强的证据会被同类里更短的那条顶掉。
    """
    level = _LEVEL_ORDER.get(finding.verdict.level, 9)
    severity = SEVERITY_RANK.get(getattr(finding.verdict, "severity", ""), 9)
    no_chain = 0 if getattr(finding, "chain_evidence", None) else 1
    length = finding.minimized_len or finding.original_len or 1 << 30
    return (level, severity, no_chain, length, finding.case_id)


def cluster(findings) -> list[Cluster]:
    """按 ``(左, 右, 类型)`` 归并发现；组按 严重级别 → 组内条数 排序。

    组内**所有**发现都还在 ``ScanResult.findings`` 里 —— 归并只影响展示与报告，
    不丢数据（JSON 与落库仍是完整清单）。
    """
    buckets: dict[tuple[str, str, str], list] = {}
    for finding in findings:
        divergence = finding.divergence
        key = (divergence.left.impl_id, divergence.right.impl_id,
               finding.verdict.kind)
        buckets.setdefault(key, []).append(finding)

    out: list[Cluster] = []
    for (left, right, kind), group in buckets.items():
        group.sort(key=_representative_key)
        best = group[0]
        out.append(Cluster(
            left=left, right=right, kind=kind,
            level=best.verdict.level,
            count=len(group),
            representative=best,
            case_ids=[f.case_id for f in group[:MAX_IDS]],
            severity=min((getattr(f.verdict, "severity", "") for f in group),
                         key=lambda sv: SEVERITY_RANK.get(sv, 9), default=""),
        ))
    out.sort(key=lambda c: (_LEVEL_ORDER.get(c.level, 9), -c.count,
                            c.left, c.right, c.kind))
    return out


def cluster_payload(findings) -> list[dict]:
    """给报告 / 网页 / SSE 用的可序列化形式（不含细节，细节在 findings 里）。"""
    return [{
        "left": c.left, "right": c.right, "kind": c.kind, "level": c.level,
        "severity": c.severity,
        "count": c.count, "case_id": c.case_id, "axis": c.axis,
        "case_ids": c.case_ids,
    } for c in cluster(findings)]


def redundancy(findings) -> float:
    """冗余倍数 = 发现总数 / 归并后组数（1.0 表示没有重复）。"""
    groups = cluster(findings)
    return round(len(findings) / len(groups), 2) if groups else 1.0


__all__ = ["Cluster", "cluster", "cluster_payload", "redundancy", "MAX_IDS"]
