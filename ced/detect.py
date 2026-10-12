"""单一入口：输入丢进来，**自动判断它是什么、自动调用对应工具、跑完整链路**。

为什么要有它：此前用户得在几个入口之间自己选（原始字节 → 探测文件；别人的命中 →
验证外部发现；要主动搜 → 扫描控制台；真实产品 → 拓扑……）。**选择不该由用户做** ——
输入是什么，工具就自动选哪条路，并且把"它自动做了什么"逐步报出来（给前端的 DAG 与实时报告）。

两条路由：

    输入像 HTTP 请求（首行是请求行） → 差分 oracle：扇出 5 个领域 → 逐对差分 → 消融判定 → 分级
    输入像外部工具结果（nuclei/Burp/HAR/curl/清单） → 验证层：解析成假设 → 同一条 oracle 链 → 三态

认不出来就报人话错误并列出接受的形态（其中 pcap 明确不支持：请用自动捕获，或导出 HAR）。

事件（``emit`` 回调）三种，前端据此画 DAG 与实时报告：

    {"type": "stage",  "node": <identify|extract|diff|judge|poc|report>, "state": running|done, "detail": str}
    {"type": "report", "line": str}        # 报告逐行吐，边跑边看
    {"type": "finding", ...}               # 每定出一条就推一条
    {"type": "interpret", "key": str, ...}  # 解读层（可选）事后补的一段模型解读

解读层（``interpreter``）是**可选的加法**：它跑在内核出完级之后，只往 ``Finding`` 上
挂一个 ``interpret`` 字段，判定字段一个都不碰；没传或返回不可用就不挂，报告原样。
"""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .adapters import get as get_adapter
from .adapters import names as domain_names
from .classify.upgradability import finalize, judge
from .contracts import SEVERITY_RANK, Finding, severity_label, worst_severity
from .differ.comparator import compare
from .intake import CONFIRMED, REFUTED, UNVERIFIABLE, load, verify
from .pipeline import plan_jobs
from .probe import Evaluator
from .report.fixview import fix_view
from .scenario.poc import build_poc

#: DAG 的固定节点（前端据此预画图，事件只更新节点状态）
STAGES = ("identify", "extract", "diff", "judge", "poc", "report")

#: 报告行里一条发现最多写多少字（防止一条超长的理由把报告刷爆）
_MAX_REASON = 220

_REQUEST_LINE = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
                 "TRACE", "CONNECT")

_UNKNOWN_INPUT = (
    "认不出这是什么输入（{reason}）。\n"
    "接受的形态：① 一条 HTTP 请求的原始字节；② nuclei JSON/JSONL；③ Burp XML；"
    "④ HAR；⑤ curl 命令行；⑥ URL 清单。\n"
    "抓包文件（pcap）不支持 —— 请在 wireshark 里导出 HAR，"
    "或直接用控制台的「自动捕获」把请求收进来。")


def _looks_like_request(text: str) -> bool:
    """首行是不是 HTTP 请求行？—— 这是"原始字节"与"URL 清单"的分水岭。"""
    head = text.lstrip("\ufeff \t\r\n")
    first = head.split("\n", 1)[0]
    parts = first.rstrip("\r").split(" ")
    return (len(parts) == 3 and parts[0] in _REQUEST_LINE
            and parts[2].startswith("HTTP/"))


def _junk_list(text: str) -> bool:
    """兜底解析出来的"URL 清单"其实是乱码吗？

    ``intake`` 把认不出的文本兜底当 URL 清单（裸清单本来就没有标记，这个兜底是对的），
    但用户粘一段说明文字进来时，我们宁可**当场说认不出**，也不要拿它跑一遍三态、
    吐一堆"证不了"给他看。判据刻意保守：**含空格的多词内容**且整份没有任何
    URL/主机特征（``.`` / ``/`` / ``:``）才算乱码 —— 单个词的清单（如 ``admin``）照收。
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return True
    has_hint = any(("." in ln or "/" in ln or ":" in ln) for ln in lines)
    has_space = any(" " in ln or "\t" in ln for ln in lines)
    return has_space and not has_hint


def identify(text: str) -> tuple[str, str, list]:
    """判断输入是什么。返回 ``(kind, 依据, 假设清单)``（假设清单仅外部格式非空）。"""
    if _looks_like_request(text):
        return "raw-request", "首行是 HTTP 请求行（METHOD 目标 HTTP/1.x）", []
    try:
        hypotheses = load(text, "auto")
    except ValueError as exc:
        raise ValueError(_UNKNOWN_INPUT.format(reason=exc)) from exc
    kind = hypotheses[0].source if hypotheses else "list"
    if kind == "list" and _junk_list(text):
        raise ValueError(_UNKNOWN_INPUT.format(reason="内容既不像 HTTP 请求，也不像 URL 清单"))
    return kind, f"解析出 {len(hypotheses)} 条待验证假设（来源：{kind}）", hypotheses


@dataclass
class Detection:
    """一次检测的完整结果（也是 SSE 最后一帧 ``done`` 里带的载荷）。"""

    kind: str
    why: str
    chain: list[str] = field(default_factory=list)
    domains: dict[str, dict] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    report: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "why": self.why, "chain": self.chain,
                "domains": self.domains, "findings": self.findings,
                "summary": self.summary, "report": self.report}


class _Reporter:
    """把报告**逐行**吐给前端 —— 边跑边看，而不是最后一次性给。"""

    def __init__(self, emit: Callable[[dict], None] | None) -> None:
        self.lines: list[str] = []
        self._emit = emit

    def line(self, text: str = "") -> None:
        self.lines.append(text)
        if self._emit:
            self._emit({"type": "report", "line": text})

    def stage(self, node: str, state: str, detail: str = "") -> None:
        if self._emit:
            self._emit({"type": "stage", "node": node, "state": state,
                        "detail": detail})

    def finding(self, payload: dict) -> None:
        if self._emit:
            self._emit({"type": "finding", **payload})

    def interpret(self, key: str, payload: dict) -> None:
        """解读层完成后单独推 —— 它比 finding 晚，前端按 key 补到既有条目上。"""
        if self._emit:
            self._emit({"type": "interpret", "key": key, "interpret": payload})

    def text(self) -> str:
        return "\n".join(self.lines)


# --------------------------------------------------------------------------- 解读层（可选）

def _interpret_findings(findings: list[dict],
                        interpreter: Callable[[dict], dict] | None,
                        rep: _Reporter) -> None:
    """给已定级的发现补一段模型解读。**纯加法**：拿不到就什么都不挂。

    为什么并发：一条发现一次模型调用，5 个领域串行会等几十秒；它们彼此独立，
    并发跑把等待压到单次调用的量级。预算由调用方（服务端）决定，这里不设上限 ——
    发现数天然被领域数（5）封顶。
    """
    if interpreter is None or not findings:
        return
    rep.stage("judge", "running", "模型解读中（可选，非判定）…")
    try:
        with ThreadPoolExecutor(max_workers=min(4, len(findings))) as pool:
            results = list(pool.map(interpreter, findings))
    except Exception as exc:                     # noqa: BLE001 —— 解读挂了不该拖垮检测
        results = [{"ok": False, "error": f"{type(exc).__name__}: {exc}"}] * len(findings)

    ok = 0
    for finding, data in zip(findings, results):
        data = data if isinstance(data, dict) else {"ok": False, "error": "解读返回非对象"}
        if data.get("ok"):
            ok += 1
        else:
            data = {"ok": False, "error": data.get("error") or "解读不可用"}
        finding["interpret"] = data
        rep.interpret(str(finding.get("case_id") or finding.get("target") or ""), data)

    if ok:
        rep.stage("judge", "done", f"模型解读 {ok}/{len(findings)} 条（非判定，仅供参考）")
    else:
        rep.stage("judge", "done", "模型解读不可用，已回落内核原文案")


def _interpret_lines(item: dict) -> list[str]:
    """报告里那个加出来的解读小栏 —— 明确标注"非判定"，与上面几行分开。"""
    data = item.get("interpret")
    if not isinstance(data, dict) or not data.get("ok"):
        return []
    out = [f"- 模型解读（**非判定**，仅供参考）：{data.get('impact') or '—'}"]
    if data.get("cwe_hint"):
        out.append(f"- 模型 CWE 建议（非判定）：{data['cwe_hint']}")
    if data.get("fix"):
        out.append(f"- 模型修复建议（非判定）：{data['fix']}")
    return out


# --------------------------------------------------------------------------- 原始请求字节

def _severity_line(security: int, counts: dict[str, int]) -> str:
    """判定阶段的进度文案：安全级 + 五档分布。"""
    if not counts:
        return f"安全级 {security} 条（其余为疑点/兼容性）"
    parts = "、".join(f"{severity_label(name)} {counts[name]}"
                      for name in sorted(counts,
                                         key=lambda n: SEVERITY_RANK.get(n, 99)))
    return f"安全级 {security} 条　危险等级：{parts}"


def _fix_lines(item: dict) -> list[str]:
    """把「修复形态 vs 原始输入」渲染成报告里的对照块。"""
    view = item.get("fix_view")
    if not view:
        return []
    out = ["", "**修复形态（右栏 = 规范化后的同一条请求）**", ""]
    if view["changes"]:
        for change in view["changes"]:
            out.append(f"- {change}")
    else:
        out.append("- 无需改写字节：这条分歧来自两侧策略不同")
    if view.get("reject"):
        out.append("- ⚠️ 按修复口径这条请求应当**直接拒绝**（规范形态只是用来看清歧义在哪）")
    out.append("")
    out.append("```diff")
    for row in view["rows"]:
        if row["tag"] == "same":
            out.append(f"  {row['orig']}")
        elif row["tag"] == "del":
            out.append(f"- {row['orig']}")
        else:
            out.append(f"+ {row['fixed']}")
    out.append("```")
    out.append("")
    if view.get("note"):
        out.append(view["note"])
    return out


def _run_raw(raw: bytes, domains: list[str] | None, rep: _Reporter,
             result: Detection,
             interpreter: Callable[[dict], dict] | None = None) -> None:
    """一条请求扇出 5 个领域，逐对差分 + 消融判定。"""
    result.chain.append(f"扇出领域：{len(domains or domain_names())} 个")
    rep.stage("extract", "running", "按领域各取一段（整条请求 / target / Host / 查询串 / 字节）")
    slices: list[tuple[str, object, bytes]] = []
    for name in (domains or domain_names()):
        adapter = get_adapter(name)
        payload = adapter.extract(raw)
        if not payload:
            result.domains[name] = {"pairs": 0, "divergences": 0, "security": 0,
                                    "kinds": {}, "severities": {},
                                    "note": "该领域从这份字节里取不到观测对象"}
        slices.append((name, adapter, payload))
    rep.stage("extract", "done", f"{sum(1 for _, _, p in slices if p)} 个领域取到了观测对象")

    rep.line("| 领域 | 对照对数 | 分歧 | 安全级 | 最高危险等级 | 类型 |")
    rep.line("|---|---|---|---|---|---|")
    rep.stage("diff", "running")
    total_pairs = total_div = total_sec = 0
    total_sev: dict[str, int] = {}
    for name, adapter, payload in slices:
        if not payload:
            rep.line(f"| `{name}` | 0 | 0 | 0 | — | 取不到观测对象 |")
            continue
        specs = adapter.specs()
        impl_ids = [s.impl_id for s in specs]
        evaluator = Evaluator(specs)
        jobs = plan_jobs(adapter, impl_ids, "cross")
        case_id = hashlib.sha1(payload).hexdigest()[:8]
        found = sec = 0
        kinds: dict[str, int] = {}
        severities: dict[str, int] = {}
        hit: dict | None = None
        for left_id, right_id, axis in jobs:
            left = evaluator(left_id, payload)
            right = evaluator(right_id, payload)
            div = compare(case_id, axis, payload, left, right, adapter.compare_keys)
            if div is None:
                continue
            found += 1
            kind = adapter.classify([d.key for d in div.diffs])
            kinds[kind] = kinds.get(kind, 0) + 1
            rep.stage("judge", "running", f"{name}：第 {found} 条分歧做消融")
            verdict = judge(div, kind, adapter, evaluator)
            quantified = None
            if verdict.is_security:
                sec += 1
                quantified = adapter.quantify(payload, left_id, right_id, div=div)
            # 量化决定等级档位（实测→严重；有错位→类型上限；量化不了→降档）
            finalize(verdict, adapter, quantified)
            severities[verdict.severity] = severities.get(verdict.severity, 0) + 1
            rank = SEVERITY_RANK.get(verdict.severity, 9)
            if hit is None or rank < hit["_rank"]:
                poc = None
                if verdict.is_security:
                    built = build_poc(
                        Finding(divergence=div, verdict=verdict,
                                original_len=len(payload)), domain=name)
                    if built is not None:
                        poc = {"title": built.title, "scenario": built.scenario,
                               "cwe": built.cwe or "", "steps": list(built.steps),
                               "script": built.script, "chain_desc": built.chain_desc,
                               "sample_len": built.sample_len}
                hit = {"_rank": rank, "domain": name, "case_id": case_id,
                       "level": verdict.level, "severity": verdict.severity,
                       "kind": kind, "left": left_id,
                       "right": right_id, "reason": verdict.reason,
                       "cwe": verdict.cwe or "", "scenario": verdict.scenario or "",
                       "ablation": verdict.ablation or "", "effect": verdict.effect or "",
                       "fix": verdict.fix or "",
                       "quantified": (quantified.describe if quantified else ""),
                       # 修复形态：**拿原始输入**（不是领域切片）来对照，
                       # 用户看到的才是"我贴进去的那份请求"改完长什么样
                       "fix_view": fix_view(name, raw),
                       "poc": poc}
        total_pairs += len(jobs); total_div += found; total_sec += sec
        for key, value in severities.items():
            total_sev[key] = total_sev.get(key, 0) + value
        result.domains[name] = {"pairs": len(jobs), "divergences": found,
                                "security": sec, "kinds": kinds,
                                "severities": severities}
        top_sev = min((key for key, n in severities.items() if n),
                      key=lambda key: SEVERITY_RANK.get(key, 99), default="")
        rep.line(f"| `{name}` | {len(jobs)} | {found} | {sec} | "
                 f"{severity_label(top_sev) if top_sev else '—'} | "
                 f"{'、'.join(f'{k}×{v}' for k, v in sorted(kinds.items())) or '—'} |")
        if hit is not None:
            hit.pop("_rank", None)
            result.findings.append(hit)
            rep.stage("diff", "running", f"{name}：发现 {found} 条分歧")
            rep.finding(hit)
    rep.stage("diff", "done", f"对照 {total_pairs} 对，分歧 {total_div} 条")
    rep.stage("judge", "done", _severity_line(total_sec, total_sev))

    # 发现按危险等级从高到低排（同档保持领域顺序）—— 报告与界面都先说最要紧的那条
    result.findings.sort(key=lambda item: SEVERITY_RANK.get(item.get("severity", ""), 99))

    result.summary = {"input_items": 1, "pairs": total_pairs,
                      "divergences": total_div, "security": total_sec,
                      "by_severity": total_sev,
                      "severity": worst_severity(total_sev),
                      "confirmed": 0, "refuted": 0, "unverifiable": 0}
    result.chain.append(f"逐对差分：{total_pairs} 对 → 分歧 {total_div} 条")
    result.chain.append(
        "消融判定：" + _severity_line(total_sec, total_sev)
        + "；未定位到承载者的一律按疑点处理")

    _interpret_findings(result.findings, interpreter, rep)

    # 报告：把每条发现的原因/证据写全（实时报告已经逐行吐过，这里补细节）
    secure = [f for f in result.findings if f["level"] == "security"]
    # 疑点也要给修复形态：没升级只说明"证据不足以定级"，不代表这份输入不必改。
    # 以前它们连一行细节都没有 —— 报告里只有一张汇总表，读者看不到该动哪几个字节。
    doubts = [f for f in result.findings if f["level"] != "security"]
    if secure:
        rep.line("")
        rep.line("## 安全级发现（结构前提成立 · 按危险等级从高到低 · 每条都由消融定位到承载者）")
        rep.line("")
        rep.line("> `安全级`是**类别**（结构性前提成立，不等于漏洞），方括号里才是"
                 "**危险等级**（这条有多严重）。")
        for item in secure:
            rep.line("")
            rep.line(f"### [{severity_label(item.get('severity'))}] "
                     f"`{item['case_id']}` · {item['domain']} · "
                     f"{item['left']} ↔ {item['right']}")
            rep.line(f"- 类型：`{item['kind']}`　CWE：{item['cwe'] or '—'}"
                     f"　场景：{item['scenario'] or '—'}")
            rep.line(f"- 判定理由：{item['reason'][:_MAX_REASON]}")
            rep.line(f"- 消融证据：{item['ablation'] or '—'}")
            rep.line(f"- 安全后果：{item['effect'] or '—'}")
            rep.line(f"- 修复建议：{item['fix'] or '—'}")
            for extra in _fix_lines(item):
                rep.line(extra)
            for extra in _interpret_lines(item):
                rep.line(extra)
        rep.stage("poc", "done", f"{len(secure)} 条安全级发现可直接生成端到端 PoC")
    else:
        rep.line("")
        rep.line("## 没有安全级发现 —— 这份输入在 5 个领域里没有可升级的结构性分歧")
        rep.stage("poc", "done", "无需生成 PoC（宁可不升级，也不夸大）")
    if doubts:
        rep.line("")
        rep.line("## 疑点（未升级：结构前提不成立 / 未定位到可控承载者）")
        rep.line("")
        rep.line("> 疑点不等于没问题：这里说的是**证据不足以定级**，改动清单照样给。")
        for item in doubts:
            rep.line("")
            rep.line(f"### [{severity_label(item.get('severity'))}] "
                     f"`{item['case_id']}` · {item['domain']} · "
                     f"{item['left']} ↔ {item['right']}")
            rep.line(f"- 类型：`{item['kind']}`　危险等级："
                     f"{severity_label(item.get('severity')) or '—'}")
            rep.line(f"- 判定理由：{item['reason'][:_MAX_REASON]}")
            for extra in _fix_lines(item):
                rep.line(extra)


# --------------------------------------------------------------------------- 外部工具结果

def _run_external(text: str, kind: str, hypotheses: list, domains: list[str] | None,
                  rep: _Reporter, result: Detection,
                  interpreter: Callable[[dict], dict] | None = None) -> None:
    result.chain.append(f"解析外部发现：{len(hypotheses)} 条假设（{kind}）")
    rep.stage("extract", "running", f"解析 {kind} → {len(hypotheses)} 条假设")
    rep.stage("extract", "done", f"{len(hypotheses)} 条假设就绪")
    rep.line("| # | 结论 | 目标 | 领域 | 危险等级 | 说明 |")
    rep.line("|---|---|---|---|---|---|")
    rep.stage("diff", "running", "逐条喂进同一条 oracle 链")
    verdicts = verify(hypotheses, domains=domains)
    counts = {CONFIRMED: 0, REFUTED: 0, UNVERIFIABLE: 0}
    severities: dict[str, int] = {}
    shown: list[dict] = []
    for index, item in enumerate(verdicts, 1):
        counts[item.verdict] = counts.get(item.verdict, 0) + 1
        if item.severity:
            severities[item.severity] = severities.get(item.severity, 0) + 1
        label = {CONFIRMED: "已证实", REFUTED: "未证实",
                 UNVERIFIABLE: "证不了"}.get(item.verdict, item.verdict)
        note = (item.reason or item.detail or "")[:_MAX_REASON]
        rep.line(f"| {index} | **{label}** | `{item.hypothesis.target}` | "
                 f"`{item.domain or '—'}` | "
                 f"{severity_label(item.severity) if item.severity else '—'} | {note} |")
        payload = {"verdict": item.verdict, "target": item.hypothesis.target,
                   "domain": item.domain, "level": item.level, "kind": item.kind,
                   "severity": item.severity,
                   "severity_label": severity_label(item.severity) if item.severity else "",
                   "reason": item.reason, "evidence": item.evidence,
                   "quantified": item.quantified,
                   "detail": item.detail, "left": item.left, "right": item.right,
                   # 修复形态：与扫描/手动检测同一条口径 —— 拿喂进去的那份待测对象对照
                   "fix_view": (fix_view(item.domain, item.payload)
                                if item.payload and item.domain else None),
                   "source": item.hypothesis.source}
        result.findings.append(payload)
        rep.finding(payload)
        if item.verdict == CONFIRMED and payload["fix_view"]:
            shown.append(payload)
    rep.stage("diff", "done", f"三态：已证实 {counts[CONFIRMED]} / 未证实 {counts[REFUTED]} / "
                              f"证不了 {counts[UNVERIFIABLE]}")
    rep.stage("judge", "done", "判定全部由内核给出，不由报告方自述")
    _interpret_findings(result.findings, interpreter, rep)
    if shown:
        # 与"安全级发现"一节同一套写法：改动清单 + 逐行对照
        rep.line("")
        rep.line("## 修复形态（右栏 = 规范化后的同一条输入）")
        for item in shown:
            rep.line("")
            rep.line(f"### [{severity_label(item['severity'])}] "
                     f"`{item['target']}` · {item['domain']} · "
                     f"{item['left']} ↔ {item['right']}")
            for extra in _fix_lines(item):
                rep.line(extra)
    rep.stage("poc", "done", "已证实的条目可用最小复现样本复现（见各条的领域）")
    result.summary = {"input_items": len(hypotheses), "pairs": 0, "divergences": 0,
                      "security": counts[CONFIRMED],
                      "by_severity": severities,
                      "severity": worst_severity(severities),
                      "confirmed": counts[CONFIRMED], "refuted": counts[REFUTED],
                      "unverifiable": counts[UNVERIFIABLE]}
    result.chain.append(
        f"三态裁定：已证实 {counts[CONFIRMED]} / 未证实 {counts[REFUTED]} / "
        f"证不了 {counts[UNVERIFIABLE]}")


# --------------------------------------------------------------------------- 入口

def run(text: str, *, domains: list[str] | None = None,
        emit: Callable[[dict], None] | None = None,
        interpreter: Callable[[dict], dict] | None = None) -> dict:
    """跑一次完整检测。``emit`` 收到实时事件（阶段 / 报告行 / 发现）。

    ``interpreter`` 是**可选**的解读层回调：传入则在判定完成后给每条发现补一段模型
    解读（``Finding['interpret']``），不传就完全不调用模型。回调返回
    ``{"ok": bool, ...}``，内部异常由 ``_interpret_findings`` 兜住，不影响检测结果。
    """
    rep = _Reporter(emit)
    rep.stage("identify", "running")
    kind, why, hypotheses = identify(text)          # 认不出会抛 ValueError（人话）
    result = Detection(kind=kind, why=why)
    rep.stage("identify", "done", f"{kind} —— {why}")

    rep.line("# 检测报告")
    rep.line("")
    rep.line(f"- 输入形态：**{kind}**（{why}）")
    raw_len = len(text.encode("latin-1", "replace"))
    rep.line(f"- 输入规模：{raw_len} 字节 / {len(hypotheses) or 1} 条")
    rep.line("")
    rep.line("## 自动链路")
    rep.line("")

    if kind == "raw-request":
        raw = text.encode("latin-1", "replace")
        rep.line(f"1. 识别输入 —— 原始请求字节（{len(raw)} 字节）")
        _run_raw(raw, domains, rep, result, interpreter)
    else:
        rep.line(f"1. 识别输入 —— {kind}（{len(hypotheses)} 条假设）")
        _run_external(text, kind, hypotheses, domains, rep, result, interpreter)

    rep.line("")
    rep.line("## 链路小结")
    rep.line("")
    for index, step in enumerate(result.chain, 1):
        rep.line(f"{index}. {step}")
    rep.stage("report", "done", f"{len(rep.lines)} 行")
    result.report = rep.text()
    return result.to_dict()


__all__ = ["STAGES", "Detection", "identify", "run"]
