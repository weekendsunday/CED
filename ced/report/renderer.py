"""报告渲染。

原则：**不夸大**。消融实验未能定位到承载者的分歧只标 unknown，绝不写成漏洞结论。

``result_payload`` 是**单一真源**：报告 JSON、网页控制台、SSE 事件都从这里取形状，
避免各写一遍导致字段漂移。
"""
from __future__ import annotations

import base64
import json

from ..contracts import SEVERITY_ORDER, severity_label
from ..scenario import build_pocs
from .cluster import cluster, cluster_payload, redundancy
from .fixview import fix_view

#: repr 截断上限 —— 一条请求不该有 8KB 以上的可读表示；超了说明输入不是单条请求
REPR_LIMIT = 8192


def _preview(payload: bytes, limit: int = 140) -> str:
    text = repr(payload[:limit])
    return text + ("...(截断)" if len(payload) > limit else "")


def _pretty(payload: bytes, limit: int = REPR_LIMIT) -> str:
    text = repr(payload)
    if len(text) <= limit:
        return text
    return text[:limit] + f"...(截断，原始 {len(payload)} 字节)"


def _quant_cell(poc) -> str:
    """把量化结果压成表格里的一格 —— 领域无关（分帧是字节数，路径是资源名）。"""
    quant = poc.quant
    if quant is None:
        return "—（未量化）"
    pairs = [(k, v) for k, v in quant.values.items() if k not in ("front", "back")]
    body = "、".join(f"{k}={v}" for k, v in pairs) or quant.describe
    return f"{quant.label}：{body}"


def measured_ids(result) -> set[str]:
    """参与了**实测**的实现 id（观测来自真实产品）。

    定义只有一处：``impl_brief`` 里 ``runner`` 是 chain / socket 才算实测。
    "A 侧实测、B 侧离线"这句话能不能说、每条发现该标"实测"还是"推演",
    都看这一个集合。
    """
    return {str(i.get("id")) for i in (getattr(result, "impls", None) or [])
            if i.get("measured")}


def is_measured(result, divergence) -> bool:
    """这条发现是不是**实测**得来的（两侧里有一侧是真实产品）。"""
    measured = measured_ids(result)
    return (divergence.left.impl_id in measured
            or divergence.right.impl_id in measured)


def summary_of(result) -> dict:
    """等级/类别/类型分布 —— 报告、控制台、SSE 完成事件共用同一份口径。"""
    by_level: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    n_measured = 0
    for f in result.findings:
        by_level[f.verdict.level] = by_level.get(f.verdict.level, 0) + 1
        name = f.verdict.severity
        by_severity[name] = by_severity.get(name, 0) + 1
        by_kind[f.verdict.kind] = by_kind.get(f.verdict.kind, 0) + 1
        if is_measured(result, f.divergence):
            n_measured += 1
    return {"by_level": by_level, "by_severity": by_severity,
            "by_kind": by_kind, "measured": n_measured}


def render_markdown(result, *, domain: str = "http1-framing",
                    topo_desc: str = "", poc_dir: str | None = None) -> str:
    stats = summary_of(result)
    out: list[str] = []
    out.append("# 产品耦合误差报告")
    out.append("")
    out.append(f"- 领域：`{domain}`")
    if topo_desc:
        out.append(f"- 拓扑：{topo_desc}")
    out.append(f"- 用例数：{result.total_cases}　实现对：{result.jobs}")
    rejected = getattr(result, "rejected_cases", 0)
    if rejected:
        out.append(f"- 前置拒绝、不可观测而跳过的用例：**{rejected}**"
                   f"（不合成观测；真实前置对畸形请求返回 4xx 属正常行为）")
    out.append(f"- 耦合误差：{len(result.divergences)}　"
               f"其中安全级（结构前提成立）：{len(result.security)}")
    out.append("")

    out.append("## 危险等级")
    out.append("")
    out.append("> 等级 = **类型上限**（这类分歧最好情况下有多严重，领域知识）+ **证据强度**"
               "（实机测量 / 有量化错位 / 量化不出来）。")
    out.append("> `安全级`只说明「结构性前提成立」，不等于漏洞；等级才回答「有多严重」。")
    out.append("")
    out.append("| 等级 | 数量 |")
    out.append("|---|---|")
    for name in SEVERITY_ORDER:
        if stats["by_severity"].get(name):
            out.append(f"| {severity_label(name)} | {stats['by_severity'][name]} |")
    out.append("")
    out.append("| 类别 | 数量 |")
    out.append("|---|---|")
    for level in ("security", "unknown", "compatibility"):
        if stats["by_level"].get(level):
            out.append(f"| {level} | {stats['by_level'][level]} |")
    out.append("")
    out.append("| 分歧类型 | 数量 |")
    out.append("|---|---|")
    for kind, n in sorted(stats["by_kind"].items()):
        out.append(f"| {kind} | {n} |")
    out.append("")

    pocs = build_pocs(result)
    poc_by_case = {poc.case_id: poc for poc in pocs}
    if pocs:
        out.append("## 攻击场景升级（端到端 PoC）")
        out.append("")
        out.append("> 只对 `security` 级发现升级。`unknown` / `compatibility` 一律不升级。")
        out.append("")
        out.append("| 用例 | 场景 | 链路 | 量化 | 脚本 |")
        out.append("|---|---|---|---|---|")
        for poc in pocs:
            out.append(f"| `{poc.case_id}` | {poc.title} | "
                       f"{poc.left} → {poc.right} | {_quant_cell(poc)} | "
                       f"{(f'`{poc_dir}/{poc.file_name}`' if poc_dir else poc.file_name)} |")
        out.append("")

    if not result.findings:
        out.append("> 未发现任何耦合误差。注意：这**不等于**安全，只说明在本次语料范围内两侧理解一致。")
        out.append("")
        return "\n".join(out)

    clusters = cluster(result.findings)
    out.append("## 同类归并")
    out.append("")
    out.append("> 判据：**同一对实现 + 同一分歧类型 = 同一类事实**，只留一条代表。")
    out.append(f"> {len(result.findings)} 条发现归并后是 **{len(clusters)} 类**"
               f"（冗余 **{len(result.findings) / len(clusters):.1f}×**）。"
               f"完整清单仍在 JSON 与结果库里。")
    out.append("")
    out.append("| 等级 | 链路 | 类型 | 条数 | 代表 |")
    out.append("|---|---|---|---|---|")
    for item in clusters:
        out.append(f"| {severity_label(item.level)} | {item.left} ↔ {item.right} "
                   f"| `{item.kind}` | "
                   f"{item.count} | `{item.case_id}` |")
    out.append("")

    out.append("## 误差明细（每类一条代表）")
    out.append("")
    for item in clusters:
        f = item.representative
        v = f.verdict
        out.append(f"### [{v.severity_label}] `{f.case_id}` — {v.kind}"
                   + (f"　（同类共 {item.count} 条）" if item.count > 1 else ""))
        out.append("")
        out.append(f"- 对照：**{f.divergence.left.impl_id}** ↔ "
                   f"**{f.divergence.right.impl_id}**（轴：`{f.divergence.axis}`）")
        if item.count > 1:
            others = "、".join(f"`{cid}`" for cid in item.case_ids[1:6])
            more = f"…等 {item.count - 1} 条" if item.count > 6 else ""
            out.append(f"- 同类其它样本：{others}{more}")
        out.append(f"- 判定理由：{v.reason}")
        if v.ablation:
            out.append(f"- 消融证据：{v.ablation}")
        out.append(f"- 安全后果：{v.effect}")
        out.append(f"- CWE（候选，以实机复现为准）：{v.cwe or '—'}"
                   + (f"　场景：**{v.scenario}**" if v.scenario else ""))
        out.append(f"- 修复建议：{v.fix}")
        out.append("")
        out.append("| 观测字段 | " + f.divergence.left.impl_id +
                   " | " + f.divergence.right.impl_id + " |")
        out.append("|---|---|---|")
        for d in f.divergence.diffs:
            out.append(f"| `{d.key}` | `{d.left!r}` | `{d.right!r}` |")
        out.append("")
        if f.minimized is not None:
            out.append(f"- 最小复现样本（{f.original_len} → {f.minimized_len} 字节）：")
        else:
            out.append("- 原始样本：")
        out.append("")
        out.append("  ```")
        out.append("  " + _preview(f.minimized if f.minimized is not None
                                   else f.divergence.payload))
        out.append("  ```")
        out.append("")
        if f.chain_evidence:
            out.append(f"- 链路量化：{f.chain_evidence}")
            out.append("")

        view = fix_view(getattr(result, "domain", "") or domain,
                        f.divergence.payload)
        if view is not None:
            # 只有真要画对照表时才提"右栏"：字节没变的情况（只能拒绝、
            # 或说明只涉及实现侧）根本没有右栏可看。
            shows_table = bool(view["changed"] and view["rows"])
            out.append("**修复形态**" + ("（右栏 = 规范化后的同一条请求）"
                                        if shows_table else ""))
            out.append("")
            for change in view["changes"] or ["无需改写字节：这条分歧来自两侧策略不同"]:
                out.append(f"- {change}")
            if view["reject"]:
                out.append("- ⚠️ 按修复口径这条请求应当**直接拒绝**"
                           + ("，规范形态只是用来看清歧义在哪"
                              if view["changed"] and view["rows"] else
                              "（这类写法规范化不出来，没有可对照的形态）"))
            out.append("")
            # 字节没变就不摆对照表：两栏一模一样，那不叫对照、叫噪声
            # （看着像"修复没生效"，其实这条根本没有可改的字节）。
            if view["changed"] and view["rows"]:
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
            elif view["changed"]:
                out.append("（字节有改动，但这段输入太长，没做逐行对照。）")
                out.append("")
            out.append(view["note"])
            out.append("")

        poc = poc_by_case.get(f.case_id)
        if poc is not None:
            out.append(f"**攻击场景**：{poc.title}"
                       f"（`{poc.scenario}`，CWE {poc.cwe or '—'}）")
            out.append("")
            out.append(poc.impact)
            out.append("")
            out.append("复现步骤：")
            out.append("")
            for index, step in enumerate(poc.steps, 1):
                out.append(f"{index}. {step}")
            out.append("")
            if poc.quant is not None:
                out.append(f"- **{poc.quant.label}**：{poc.quant.describe}")
            else:
                out.append("- 量化：无法计算（两侧含非本地实现）—— 需在真实拓扑上复现")
            if poc_dir:
                out.append(f"- 可执行 PoC：`{poc_dir}/{poc.file_name}`"
                           f"（离线算账；`--chain http://127.0.0.1:8801` 实机取证；"
                           f"`--send HOST:PORT --i-am-authorized` 可真发）")
            out.append("")

    out.append("---")
    out.append("")
    out.append("> `security` 级 = 结构性分歧 ∧ 由攻击者可直接发送的字节承载"
               "（结构性前提成立，不等于已实机利用）。")
    out.append("> **危险等级**在它之上再分五档：严重（实机测量到错位）＞高（类型上限且"
               "确实错位）＞中（未量化）＞低（仅疑点）＞信息（仅诊断字段）。")
    out.append("> 消融实验未能定位承载者的分歧一律标为 `unknown`，不作结论。")
    return "\n".join(out)


def result_payload(result) -> dict:
    """一次扫描的可序列化结果 —— 报告与网页控制台共用这一份形状。"""
    keys = tuple(getattr(result, "compare_keys", ()) or ())
    findings: list[dict] = []
    for f in result.findings:
        div = f.divergence
        item = {
            "case_id": f.case_id,
            "axis": div.axis,
            "left": div.left.impl_id,
            "right": div.right.impl_id,
            "level": f.verdict.level,
            "severity": f.verdict.severity,
            "severity_label": f.verdict.severity_label,
            "kind": f.verdict.kind,
            "reason": f.verdict.reason,
            "controllable": f.verdict.controllable,
            "ablation": f.verdict.ablation,
            "cwe": f.verdict.cwe,
            "scenario": f.verdict.scenario,
            "effect": f.verdict.effect,
            "fix": f.verdict.fix,
            "diffs": {d.key: [d.left, d.right] for d in div.diffs},
            "payload_repr": _pretty(div.payload),
            "payload_b64": base64.b64encode(div.payload).decode(),
            "original_len": f.original_len,
            "minimized_len": f.minimized_len,
            "minimized_b64": (base64.b64encode(f.minimized).decode()
                              if f.minimized is not None else None),
            "minimized_repr": (_pretty(f.minimized)
                               if f.minimized is not None else None),
            "chain_evidence": f.chain_evidence,
            # 实测 / 推演：这条发现的两侧里有没有真实产品参与观测。
            # 结果页据此在每条发现旁标注，不让"离线推演"看着像"实机结论"。
            "measured": is_measured(result, div),
            "fix_view": fix_view(getattr(result, "domain", ""), div.payload),
        }
        if keys:
            # 证据视图要的是"两侧完整观测并排"，而不只是差异字段
            item["observations"] = {k: [div.left.get(k), div.right.get(k)]
                                    for k in keys}
        findings.append(item)

    impls = list(getattr(result, "impls", None) or [])
    measured = measured_ids(result)
    return {
        "total_cases": result.total_cases,
        "jobs": result.jobs,
        "domain": getattr(result, "domain", ""),
        "compare_keys": list(keys),
        "rejected_cases": getattr(result, "rejected_cases", 0),
        # 结果页顶部那三行全靠这里：A 侧是谁在哪、B 侧是谁几个、有没有真实产品参与。
        "impls": impls,
        "measured_impls": sorted(measured),
        "has_product": bool(measured),
        # 观测缓存的本轮账：真实动作跑了几次、省了几次（接产品时最能看出效果）
        "cache": {"hits": int(getattr(result, "cache_hits", 0) or 0),
                  "trips": int(getattr(result, "cache_trips", 0) or 0)},
        "summary": summary_of(result),
        "redundancy": redundancy(result.findings),
        "clusters": cluster_payload(result.findings),
        "pocs": [poc.to_dict() for poc in build_pocs(result)],
        "findings": findings,
    }


def render_json(result) -> str:
    return json.dumps(result_payload(result), ensure_ascii=False, indent=2)
