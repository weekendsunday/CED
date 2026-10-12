"""把一条**捕获到的请求**喂进引擎的差分 oracle。

为什么这条路不用新写任何比对逻辑：适配器协议里已经有 ``extract(raw)`` ——
「从链路收到的字节里取出本领域要观测的那一段」。所以**同一条捕获到的 HTTP 请求**
可以同时喂给 5 个领域：

    http1-framing   整条请求（消息边界）
    url-norm        请求行的 target
    host-norm       Host 头的值
    query-norm      `?` 之后的查询串
    enc-norm        请求行 target（一段待解释的字节）

产出是**一条条事实**，不是形容词：每个领域比了多少对、发现几对分歧、其中几条安全级、
最强的那一条是谁（前端"一键出最小复现样本 / PoC"就靠它）。

一句话边界：这里比的是「**这份字节**在参照实现之间有没有分歧」——
参照实现给的是**疑点**，不是"客户产品有漏洞"的断言。要拿到耦合结论，得走 chain
（探针夹在客户链路里），那是另一条路径（见 docker/README.md）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from ..adapters import get as get_adapter
from ..adapters import names as domain_names
from ..classify.upgradability import finalize, judge
from ..contracts import SEVERITY_RANK, Finding, worst_severity
from ..differ.comparator import compare
from ..pipeline import case_id_of, plan_jobs
from ..probe import Evaluator

@lru_cache(maxsize=None)
def _kit(domain: str) -> tuple:
    """按领域缓存 (adapter, evaluator, impl_ids)。

    捕获是长跑（浏览器一个页面几百条请求），别每条请求都重建适配器与评估器。
    三者构造后只读，故可跨线程复用。
    """
    adapter = get_adapter(domain)
    specs = adapter.specs()
    return adapter, Evaluator(specs), tuple(s.impl_id for s in specs)


@dataclass
class Hit:
    """某个领域里最严重的那条分歧 —— 前端证据面板直接用这一条。"""

    domain: str
    case_id: str
    level: str
    kind: str
    left: str
    right: str
    reason: str
    cwe: str = ""
    scenario: str = ""
    ablation: str = ""
    effect: str = ""
    fix: str = ""
    #: 危险等级（五档）—— 前端徽章与分档统计都按它
    severity: str = ""
    #: 量化说明（"前置认的资源 vs 后端认的资源"这类），没有就是空串
    quantified: str = ""

    def to_dict(self) -> dict:
        return {"domain": self.domain, "case_id": self.case_id, "level": self.level,
                "severity": self.severity, "kind": self.kind, "left": self.left,
                "right": self.right, "reason": self.reason, "cwe": self.cwe,
                "scenario": self.scenario, "ablation": self.ablation,
                "effect": self.effect, "fix": self.fix,
                "quantified": self.quantified}


@dataclass
class Analysis:
    """一条捕获请求的差分结论（跨领域汇总）。"""

    case_id: str
    raw_len: int
    domains: dict[str, dict] = field(default_factory=dict)
    top: Hit | None = None
    #: 最强那条的 Finding —— 只给"一键出 PoC"用，不进 JSON（里面有大对象）
    top_finding: object = None

    @property
    def divergences(self) -> int:
        return sum(int(d["divergences"]) for d in self.domains.values())

    @property
    def security(self) -> int:
        return sum(int(d["security"]) for d in self.domains.values())

    @property
    def severities(self) -> dict:
        """按危险等级汇总（五档）—— 前端汇总卡用它，不再只报一个"安全级"数字。"""
        out: dict[str, int] = {}
        for item in self.domains.values():
            for name, count in (item.get("severities") or {}).items():
                out[name] = out.get(name, 0) + int(count)
        return out

    @property
    def severity(self) -> str:
        """这条请求里最严重的等级（没有分歧就是空串）。"""
        return worst_severity(self.severities)

    @property
    def level(self) -> str:
        if self.security:
            return "security"
        if self.divergences:
            return "unknown"
        return "none"

    def to_dict(self) -> dict:
        return {"case_id": self.case_id, "raw_len": self.raw_len,
                "divergences": self.divergences, "security": self.security,
                "severity": self.severity, "severities": self.severities,
                "level": self.level, "domains": self.domains,
                "top": self.top.to_dict() if self.top else None}


def analyze(raw: bytes, domains: list[str] | None = None) -> Analysis:
    """拿一份原始字节，逐领域跑差分 + 判定。"""
    case_id = case_id_of(raw)
    out = Analysis(case_id=case_id, raw_len=len(raw))
    best: Hit | None = None
    best_finding = None
    best_rank = 99

    for name in (domains or domain_names()):
        adapter, evaluator, impl_ids = _kit(name)
        payload = adapter.extract(raw)          # ← 同一条请求，各领域各取所需
        if not payload:
            out.domains[name] = {"pairs": 0, "divergences": 0, "security": 0,
                                 "kinds": {}, "severities": {},
                                 "note": "该领域从这份字节里取不到观测对象"}
            continue

        jobs = plan_jobs(adapter, impl_ids, "cross")
        divergences = security = 0
        kinds: dict[str, int] = {}
        severities: dict[str, int] = {}
        for left_id, right_id, axis in jobs:
            left = evaluator(left_id, payload)
            right = evaluator(right_id, payload)
            div = compare(case_id, axis, payload, left, right, adapter.compare_keys)
            if div is None:
                continue
            divergences += 1
            kind = adapter.classify([d.key for d in div.diffs])
            kinds[kind] = kinds.get(kind, 0) + 1
            verdict = judge(div, kind, adapter, evaluator)
            quantified = None
            if verdict.is_security:
                security += 1
                quantified = adapter.quantify(payload, left_id, right_id, div=div)
            # 量化决定等级档位（实测→严重；有错位→类型上限；量化不了→降档）
            finalize(verdict, adapter, quantified)
            severities[verdict.severity] = severities.get(verdict.severity, 0) + 1
            rank = SEVERITY_RANK.get(verdict.severity, 9)
            if rank < best_rank:
                best_rank = rank
                best = Hit(domain=name, case_id=case_id, level=verdict.level,
                           severity=verdict.severity, kind=kind,
                           left=left_id, right=right_id,
                           reason=verdict.reason, cwe=verdict.cwe or "",
                           scenario=verdict.scenario or "",
                           ablation=verdict.ablation or "",
                           effect=verdict.effect or "", fix=verdict.fix or "",
                           quantified=(quantified.describe if quantified else ""))
                best_finding = Finding(divergence=div, verdict=verdict,
                                       original_len=len(payload))

        out.domains[name] = {"pairs": len(jobs), "divergences": divergences,
                             "security": security, "kinds": kinds,
                             "severities": severities}

    out.top = best
    out.top_finding = best_finding
    return out


__all__ = ["Analysis", "Hit", "analyze"]
