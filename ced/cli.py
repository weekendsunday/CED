"""命令行入口。

    python -m ced scan  --mode axis --limit 60 --out report.md --db ced.db
    python -m ced scan  --mode cross --topology topo.yaml
    python -m ced serve --policy ref-te-first --port 8800
    python -m ced impls
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from pathlib import Path

from .adapters import ADAPTERS, get as get_adapter
from .impls import reference
from .orchestrate.topology import demo, load
from .pipeline import scan
from .contracts import ProbeUnreachable
from .probe import Evaluator
from .report.renderer import render_json, render_markdown
from . import artifacts, store


def _print_event(event: dict) -> None:
    """把任务事件流打到终端 —— CLI 与网页控制台消费的是同一套事件。"""
    kind = event.get("type")
    if kind == "stage":
        print(f"[{event.get('stage', '')}] {event.get('detail', '')}")
    elif kind == "progress":
        print(f"[进度] {event.get('done')}/{event.get('total')}　"
              f"分歧 {event.get('divergences')}　安全级 {event.get('security')}")


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        adapter = get_adapter(args.domain)
    except KeyError as exc:
        raise SystemExit(f"[!] {exc}") from exc
    topo = load(args.topology) if args.topology else demo(args.domain)
    if args.mode:
        topo_mode = args.mode
    else:
        topo_mode = "axis"
    evaluator = Evaluator(topo.impls)

    try:
        result = scan(adapter, evaluator, mode=topo_mode, limit=args.limit,
                      seed=args.seed, do_minimize=not args.no_minimize)
    except ProbeUnreachable as exc:
        # 链路探测失败绝不产出"发现" —— 那会是一整片假阳性
        raise SystemExit(f"[!] 链路不可用，已中止（不产出任何结论）：{exc}") from exc

    report = render_markdown(result, domain=topo.domain, topo_desc=topo.describe(),
                             poc_dir=args.poc_dir)
    artifacts.write_text(args.out, report)

    print("-" * 62)
    print(f"[结果] 用例 {result.total_cases} | 实现对 {result.jobs} | "
          f"耦合误差 {len(result.divergences)} | 安全级 {len(result.security)}")
    if result.rejected_cases:
        print(f"[说明] 前置按自身策略拒绝了 {result.rejected_cases} 条用例"
              f"（后端视角不存在），已跳过 —— 不合成观测，也不中止扫描")
    for f in result.security:
        print(f"  [!!] {f.case_id}  {f.divergence.left.impl_id} ↔ "
              f"{f.divergence.right.impl_id}  {f.verdict.kind}"
              f"{f'  最小化 {f.original_len}→{f.minimized_len}B' if f.minimized else ''}")
    print(f"[产物] {args.out}")

    # 攻击场景升级：只对 security 级出 PoC（判定器没升级的，这里不替它升级）
    from .scenario import build_pocs, write_pocs

    pocs = build_pocs(result)
    if pocs:
        paths = write_pocs(result, args.poc_dir)
        print(f"[产物] {args.poc_dir}  （{len(paths)} 个端到端 PoC 脚本）")
        for path in paths[:3]:
            print(f"        {path}")
        if len(paths) > 3:
            print(f"        … 等 {len(paths)} 个")
    else:
        print("[产物] 无 security 级发现，因此没有 PoC（不夸大）")

    if args.json:
        artifacts.write_text(args.json, render_json(result))
        print(f"[产物] {args.json}")
    if args.db:
        conn = store.open_fresh(args.db)
        store.save_scan(conn, result, adapter.name)
        if pocs:
            store.save_pocs(conn, pocs, script_dir=args.poc_dir)
        print(f"[产物] {args.db}  {store.stats(conn)}")
        conn.close()
    return 0


def _cmd_regression(_: argparse.Namespace) -> int:
    from . import regression
    outcomes = regression.run()
    if not outcomes:
        print("[!] cases/known/ 下没有案例文件")
        return 1
    width = max(len(o.name) for o in outcomes)
    for o in outcomes:
        print(f"  [{'PASS' if o.passed else 'FAIL'}] {o.name:<{width}}  {o.detail}")
    passed = sum(1 for o in outcomes if o.passed)
    print(f"== 已知案例反验证：{passed}/{len(outcomes)} 通过 ==")
    print(f"== {regression.real_obs_summary()} ==")
    return 0 if passed == len(outcomes) else 1


def _cmd_cases(_: argparse.Namespace) -> int:
    from . import regression
    cases = regression.load_cases()
    if not cases:
        print("[!] cases/known/ 下没有案例文件")
        return 1
    print(f"{'案例':<28}{'分歧轴':<18}{'对照':<46}期望")
    print("-" * 108)
    for c in cases:
        pair = f"{c['left']} ↔ {c['right']}"
        print(f"{c['id']:<28}{c['axis']:<18}{pair:<46}{c.get('expect_kind', '')}")
    print(f"\n共 {len(cases)} 个案例。看详情：python -m ced case <id>")
    return 0


def _dump(payload: bytes) -> None:
    parts = payload.split(b"\r\n")
    for i, part in enumerate(parts):
        suffix = "\\r\\n" if i < len(parts) - 1 else ""
        print(f"    {part.decode('latin-1')}{suffix}")


def _cmd_case(args: argparse.Namespace) -> int:
    import base64

    from . import regression
    from .adapters import get as get_adapter
    from .classify.upgradability import judge
    from .contracts import ImplSpec
    from .differ.comparator import compare
    from .impls import reference
    from .probe import Evaluator

    cases = {c["id"]: c for c in regression.load_cases()}
    if args.id not in cases:
        raise SystemExit(f"[!] 没有这个案例：{args.id}\n"
                         f"    可选：{', '.join(sorted(cases))}")
    spec = cases[args.id]
    payload = base64.b64decode(spec["payload_b64"])

    if args.raw:                       # 直接吐原始字节，可管道给 nc / curl
        sys.stdout.flush()
        sys.stdout.buffer.write(payload)
        return 0

    adapter = get_adapter(spec.get("domain", "http1-framing"))
    left_id, right_id = spec["left"], spec["right"]
    evaluator = Evaluator([
        ImplSpec(impl_id=left_id, name=left_id, runner="local",
                 policy=left_id, domain=adapter.name),
        ImplSpec(impl_id=right_id, name=right_id, runner="local",
                 policy=right_id, domain=adapter.name),
    ])
    left = evaluator(left_id, payload)
    right = evaluator(right_id, payload)

    print(f"案例      {spec['id']}")
    print(f"分歧轴    {spec['axis']}")
    print(f"对照      {left_id}  ↔  {right_id}")
    print(f"期望      {spec.get('expect_kind')} · 字段 {spec.get('expect_fields')}")
    print(f"出处      {spec.get('reference', '—')}")
    print(f"说明      {spec.get('note', '—')}")
    print(f"\n原始字节（{len(payload)} B）：")
    _dump(payload)

    div = compare(spec["id"], spec["axis"], payload, left, right, adapter.compare_keys)
    print(f"\n两侧观测：")
    print(f"    {'字段':<18}{left_id:<26}{right_id}")
    for key in adapter.compare_keys:
        mark = "  ←" if (div and key in div.keys) else ""
        print(f"    {key:<18}{str(left.get(key)):<26}{right.get(key)}{mark}")

    if div is None:
        print("\n结果      两侧理解一致 —— 未构成耦合误差（期望值可能写错了）")
        return 1

    kind = adapter.classify([d.key for d in div.diffs])
    verdict = judge(div, kind, adapter, evaluator)
    print(f"\n分歧字段  {', '.join(div.keys)}")
    print(f"分类      {kind}")
    print(f"判定      {verdict.level}")
    print(f"理由      {verdict.reason}")
    if verdict.ablation:
        print(f"消融证据    {verdict.ablation}")
    print(f"CWE       {verdict.cwe or '—'}"
          + (f"　场景 {verdict.scenario}" if verdict.scenario else ""))
    print(f"安全后果  {verdict.effect}")
    print(f"修复建议  {verdict.fix}")

    outcome = regression.run(cases=[spec])[0]
    print(f"\n回归      {'PASS' if outcome.passed else 'FAIL'}  {outcome.detail}")
    return 0 if outcome.passed else 1


def _observations(left, right, compare_keys, diff_keys) -> None:
    print(f"     {'字段':<18}{left.impl_id:<26}{right.impl_id}")
    for key in compare_keys:
        mark = "  ←" if key in diff_keys else ""
        print(f"     {key:<18}{str(left.get(key)):<26}{right.get(key)}{mark}")


def _cmd_probe(args: argparse.Namespace) -> int:
    """探测一份原始字节：对全部（或指定）实现做差分，直接出判定。"""
    import itertools

    from .classify.upgradability import judge
    from .differ.comparator import compare

    payload = (sys.stdin.buffer.read() if args.file == "-"
               else Path(args.file).read_bytes())
    if not payload:
        raise SystemExit("[!] 输入为空")

    topo = load(args.topology) if args.topology else demo(args.domain)
    adapter = get_adapter(args.domain)
    evaluator = Evaluator(topo.impls)

    print(f"输入      {args.file}  （{len(payload)} 字节）")
    print(f"拓扑      {topo.describe()}")
    print("\n原始字节：")
    _dump(payload)

    if args.pair:
        missing = [i for i in args.pair if i not in evaluator.specs]
        if missing:
            raise SystemExit(f"[!] 拓扑里没有这些实现：{missing}\n"
                             f"    可选：{', '.join(evaluator.specs)}")
        pairs = [tuple(args.pair)]
    else:
        pairs = list(itertools.combinations(list(evaluator.specs), 2))

    hits = []
    for left_id, right_id in pairs:
        left = evaluator(left_id, payload)
        right = evaluator(right_id, payload)
        div = compare("probe", "probe", payload, left, right, adapter.compare_keys)
        if div is None:
            if args.show:
                print(f"\n[—] {left_id} ↔ {right_id}：两侧理解一致")
                _observations(left, right, adapter.compare_keys, set())
            continue
        kind = adapter.classify([d.key for d in div.diffs])
        verdict = judge(div, kind, adapter, evaluator)
        hits.append((left_id, right_id, left, right, div, kind, verdict))

    print(f"\n比较      {len(pairs)} 组 → 发现分歧 {len(hits)} 组")
    if not hits:
        print("\n所有组合在结构字段上理解一致。")
        print("注意：这不等于安全，只说明在这份输入上两侧没有分歧。")
        return 0

    for left_id, right_id, obs_l, obs_r, div, kind, verdict in hits:
        print(f"\n{'-' * 72}")
        print(f"{left_id}  ↔  {right_id}      判定 {verdict.level}  （{kind}）")
        if args.pair:
            print()
            _observations(obs_l, obs_r, adapter.compare_keys, set(div.keys))
        print(f"  分歧字段  {', '.join(div.keys)}")
        print(f"  理由      {verdict.reason}")
        if verdict.ablation:
            print(f"  消融证据    {verdict.ablation}")
        if verdict.cwe:
            print(f"  CWE       {verdict.cwe}　场景 {verdict.scenario}")
        print(f"  后果      {verdict.effect}")
        print(f"  修复      {verdict.fix}")

    if not args.pair:
        print(f"\n{'=' * 72}")
        print("看某一对的完整观测：python -m ced probe <file> --pair "
              f"{hits[0][0]} {hits[0][1]}")
    return 0


def _cmd_poc(args: argparse.Namespace) -> int:
    """摊开一条 security 级发现的端到端 PoC：场景 + 字节归属 + 步骤 + 可执行脚本。

    刻意**重跑一次同 seed 的扫描**来重建这条发现 —— 扫描是确定性的，
    所以这比"从库里捞上一次的残留"更可复现，也避免读到别的实验留下的数据。
    """
    from .scenario import build_pocs

    try:
        adapter = get_adapter(args.domain)
    except KeyError as exc:
        raise SystemExit(f"[!] {exc}") from exc

    topo = load(args.topology) if args.topology else demo(args.domain)
    evaluator = Evaluator(topo.impls)
    try:
        result = scan(adapter, evaluator, mode=args.mode, limit=args.limit,
                      seed=args.seed, do_minimize=not args.no_minimize)
    except ProbeUnreachable as exc:
        raise SystemExit(f"[!] 链路不可用，已中止（不产出任何结论）：{exc}") from exc

    pocs = {p.case_id: p for p in build_pocs(result)}
    if not pocs:
        raise SystemExit("[!] 本次扫描没有 security 级发现，因此没有 PoC 可出。\n"
                         "    判定器没升级的分歧不会生成 PoC —— 这是刻意的。")
    if args.case_id not in pocs:
        raise SystemExit(f"[!] 没有这个用例的 PoC：{args.case_id}\n"
                         f"    可选：{', '.join(sorted(pocs))}")

    poc = pocs[args.case_id]

    if args.stdout:
        # 这个模式就是给管道用的：只吐脚本，不掺人类可读的前言
        sys.stdout.write(poc.script)
        return 0

    print(f"用例      {poc.case_id}　　场景 {poc.scenario}　{poc.title}")
    print(f"链路      {poc.left} → {poc.right}　　判定 {poc.level}　CWE {poc.cwe or '—'}")
    if poc.quant is None:
        print("字节归属  无法量化（两侧含非本地实现）—— 需在真实拓扑上复现")
    else:
        print(f"字节归属  {poc.quant.describe}")
    print(f"样本      {poc.original_len} → {poc.sample_len} 字节")

    print(f"\n影响\n  {poc.impact}")
    print(f"\n消融证据\n  {poc.evidence}")
    print(f"\n链式复现\n  {poc.chain_desc}")

    print("\n复现步骤")
    for index, step in enumerate(poc.steps, 1):
        print(f"  {index}. {step}")

    print(f"\n最小复现样本（{poc.sample_len} 字节）")
    _dump(poc.request)

    directory = Path(args.out)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / poc.file_name
    artifacts.write_text(path, poc.script)
    print(f"\nPoC 脚本  {path}")
    print(f"          python {path}                                     # 离线算字节账")
    print(f"          python {path} --send HOST:PORT --i-am-authorized   # 授权后真发")
    return 0


def _cmd_web(args: argparse.Namespace) -> int:
    from .web.server import main as web_main
    argv = ["--port", str(args.port), "--host", args.host]
    if args.no_open:
        argv.append("--no-open")
    return web_main(argv)


def _cmd_serve(args: argparse.Namespace) -> int:
    from .probe.front import MODES
    from .probe.front import serve as front_serve
    from .probe.server import serve

    if args.front:
        if args.front_mode not in MODES and args.front_mode not in reference.REFERENCES:
            raise SystemExit(
                f"[!] 未知前置模式：{args.front_mode}\n"
                f"    可选：{', '.join(MODES)}，或参照实现策略名"
                f"（{', '.join(reference.REFERENCES)}）")
        # 两个进程一条真实链路：客户端 → 替身前置 → 探针（扮演后端）
        threading.Thread(
            target=front_serve,
            args=(args.front_mode, args.front_port, args.data_port, args.host),
            daemon=True).start()

    from .impls import local_specs

    adapter = ADAPTERS[args.domain]()
    policy_of, _ = adapter.local_parser()
    impl_id = args.policy or local_specs(args.domain)[0].impl_id
    serve(args.host, args.data_port, args.api_port, policy_of(impl_id),
          domain=args.domain)
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    """自动捕获：把本机真实请求**自动**送进差分 oracle。

    本机 HTTP 代理：明文 HTTP 把请求收全；HTTPS 先尝试本地 CA 解密
    （装有 `pip install cryptography` 时自动生成 CA，按提示信任后明文进差分，
    解密只发生本机），客户端拒绝本地 CA（证书固定）或未装可选依赖时退回
    CONNECT 隧道直通、如实计数。浏览器 / 客户端 / 系统代理指向本端口即可。
    """
    from .capture import Config, serve

    def show(record: dict) -> None:
        stamp = str(record.get("ts", ""))[11:]
        label = (f"{record.get('method', '')} "
                 f"{record.get('host', '')}{record.get('path') or ''}")
        head = f"[{stamp}] #{record.get('seq', 0):<4} {label}"
        if record.get("tunnel"):
            print(f"{head:<72} {record.get('skip') or '未拆'}", flush=True)
            return
        times = f" ×{record['count']}" if record.get("count", 1) > 1 else ""
        analysis = record.get("analysis")
        if not analysis:
            print(f"{head:<72} {record.get('skip') or '（未分析）'}", flush=True)
            return
        tag = {"security": "!! 安全级", "unknown": "疑点"}.get(analysis["level"], "已检·一致")
        per = "  ".join(f"{name}:{row['divergences']}"
                        for name, row in analysis["domains"].items()
                        if row["divergences"])
        print(f"{head:<72}{times} 分歧 {analysis['divergences']:<3} {tag:<7} "
              f"{record.get('elapsed_ms')}ms  {per}", flush=True)
        top = analysis.get("top")
        if top and analysis["level"] == "security":
            print(f"{'':<72} └ {top['domain']}｜{top['left']} ↔ {top['right']}｜"
                  f"{top['kind']} {top['cwe']}｜{top['reason'][:44]}", flush=True)

    return serve(Config(host=args.host, port=args.port,
                        jsonl=Path(args.jsonl) if args.jsonl else None,
                        domains=args.domain or None,
                        analyze_all=args.analyze_all,
                        mitm=not args.no_mitm, on_result=show,
                        upstream=args.upstream))


def _cmd_verify(args: argparse.Namespace) -> int:
    """验证层：**做扫描器的裁判**。

    把外部发现（nuclei / Burp / HAR / curl / 普通清单）当成「待验证的假设」，
    喂进与扫描完全相同的 oracle 链（差分 → 消融 → 判定 → 最小化），
    输出**已证实 / 未证实 / 证不了** —— 判定仍由内核给出，不由报告方自述。

    「未证实」的口径刻意保守：它只说明**在试过的这些领域的参照实现之间看不出分歧**，
    不等于这条发现是假的（真实产品可能有本工具尚未建模的归一化口径）。
    """
    from .intake import load, verify as verify_hypotheses

    path = Path(args.input)
    text = sys.stdin.read() if args.input == "-" else path.read_text(
        encoding="utf-8", errors="replace")
    try:
        hypotheses = load(text, fmt=args.format)
    except Exception as exc:
        raise SystemExit(f"[!] 读不了这份清单：{exc}") from exc
    if not hypotheses:
        raise SystemExit("[!] 这份清单里没有可验证的条目（格式识别到了，但内容为空）")

    try:
        results = verify_hypotheses(hypotheses, domains=args.domain or None)
    except Exception as exc:
        raise SystemExit(f"[!] 验证过程出错：{type(exc).__name__}: {exc}") from exc

    order = {"confirmed": 0, "refuted": 1, "unverifiable": 2}
    results = sorted(results, key=lambda v: (order.get(v.verdict, 9), v.domain))
    counts = {k: sum(1 for v in results if v.verdict == k)
              for k in ("confirmed", "refuted", "unverifiable")}

    print("-" * 66)
    print(f"[验证] 共 {len(results)} 条假设　"
          f"已证实 {counts['confirmed']}　未证实 {counts['refuted']}　"
          f"证不了 {counts['unverifiable']}")
    labels = {"confirmed": "已证实", "refuted": "未证实", "unverifiable": "证不了"}
    for item in results:
        head = f"  [{labels.get(item.verdict, item.verdict)}] {item.hypothesis.target[:60]}"
        if item.verdict == "confirmed":
            print(f"{head}\n        {item.domain}　{item.left} ↔ {item.right}　"
                  f"{item.level}（{item.kind}）")
        else:
            print(f"{head}\n        {item.detail[:100]}")

    if args.out:
        lines = ["# 外部发现验证报告", "",
                 f"- 清单：`{args.input}`　共 {len(results)} 条",
                 f"- 已证实：{counts['confirmed']}　未证实：{counts['refuted']}　"
                 f"证不了：{counts['unverifiable']}", "",
                 "> 判定由确定性内核给出（差分 + 消融），不是报告方的自述。",
                 "> `已证实` = 至少一对实现产生了结构分歧；分级见 `level` 列。", "",
                 "| 结论 | 目标 | 领域 | 对照 | 级别 | 类型 | 说明 |",
                 "|---|---|---|---|---|---|---|"]
        for item in results:
            lines.append(
                f"| {labels.get(item.verdict, item.verdict)} | "
                f"`{item.hypothesis.target[:70]}` | {item.domain or '—'} | "
                f"{item.left} ↔ {item.right} | {item.level or '—'} | "
                f"{item.kind or '—'} | {(item.detail or item.reason)[:90]} |")
        artifacts.write_text(args.out, "\n".join(lines) + "\n")
        print(f"[产物] {args.out}")
    if args.json:
        from dataclasses import asdict

        payload = [
            {"verdict": v.verdict, "domain": v.domain, "left": v.left,
             "right": v.right, "level": v.level, "kind": v.kind,
             "reason": v.reason, "evidence": v.evidence,
             "minimized_b64": v.minimized_b64, "detail": v.detail,
             "hypothesis": asdict(v.hypothesis)}
            for v in results
        ]
        artifacts.write_text(
            args.json, json.dumps(payload, ensure_ascii=False, indent=2))
        print(f"[产物] {args.json}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    """仓库规模数字单一真源 —— README 指标表从这里生成，不许手写。"""
    from .stats import render_markdown

    print(render_markdown())
    return 0


def _cmd_impls(args: argparse.Namespace) -> int:
    from .impls import axis_pairs, domains, local_specs, policy_for

    for domain in ([args.domain] if getattr(args, "domain", None) else domains()):
        print(f"=== 领域 {domain} ===")
        base = _base_of(domain)
        for spec in local_specs(domain):
            policy = policy_for(domain, spec.impl_id)
            delta = {k: v for k, v in policy.__dict__.items()
                     if k != "name" and base.get(k) != v}
            print(f"  {spec.impl_id:<26} 偏离基线: {delta or '(基线本身)'}")
        print("\n  定向对照：")
        for axis, (left, right) in axis_pairs(domain).items():
            print(f"    {axis:<20} {left} ↔ {right}")
        print()
    return 0


def _base_of(domain: str) -> dict:
    """某个领域的基线策略 —— 从该领域 ``policy_of`` **所属模块**里取 ``BASE``。

    刻意不按领域名拼模块名：``url-norm`` 的参照模块叫 ``url_reference``（不是
    ``url_norm_reference``），``host-norm`` 同理 —— 拼名字必然会错。
    """
    import importlib

    from .impls import local_parser

    policy_of, _ = local_parser(domain)
    module = importlib.import_module(policy_of.__module__)
    return getattr(module, "BASE", {})


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ced", description="CED — 产品耦合误差检测")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="跑一次差分扫描并出报告")
    s.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS),
                   help="领域适配器（新增领域见 ced/adapters/__init__.py 的注册表）")
    s.add_argument("--topology", default=None, help="拓扑文件（YAML/JSON）；缺省用内置 demo")
    s.add_argument("--mode", choices=["axis", "cross"], default=None,
                   help="axis=按分歧轴定向对照；cross=全部两两组合")
    s.add_argument("--limit", type=int, default=None, help="用例数上限")
    s.add_argument("--seed", type=int, default=42, help="随机种子（可复现）")
    s.add_argument("--no-minimize", action="store_true", help="跳过最小化")
    s.add_argument("--out", default="report.md")
    s.add_argument("--poc-dir", default="results/pocs",
                   help="端到端 PoC 脚本输出目录（只对 security 级发现生成）")
    s.add_argument("--json", default=None)
    s.add_argument("--db", default=None)
    s.set_defaults(func=_cmd_scan)

    w = sub.add_parser("web", help="启动本地网页界面（点鼠标操作，不用记命令）")
    w.add_argument("--port", type=int, default=8777)
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    w.set_defaults(func=_cmd_web)

    v = sub.add_parser("serve", help="起探针服务（供 socket / chain 方式接入真实产品）")
    v.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS),
                   help="探针服务的领域（新增领域见 ced/adapters/__init__.py 的注册表）")
    v.add_argument("--policy", default=None,
                   help="参照实现策略名，默认取该领域第一个参照实现")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--data-port", type=int, default=8800)
    v.add_argument("--api-port", type=int, default=8801)
    v.add_argument("--front", action="store_true",
                   help="同时起一个替身前置（无 Docker 时演示「前置 → 后端」链路）")
    v.add_argument("--front-port", type=int, default=18080,
                   help="替身前置的对外入口（别用 8080：Windows 常保留该端口）")
    v.add_argument("--front-mode", default="pass",
                   help="pass | rewrite_cl | drop | 参照实现策略名（如 ref-te-first）")
    v.set_defaults(func=_cmd_serve)

    cap = sub.add_parser("capture", help="自动捕获：本机代理，收到的请求自动进差分 oracle")
    cap.add_argument("--host", default="127.0.0.1")
    cap.add_argument("--port", type=int, default=18081,
                     help="代理端口（别用 8080：Windows 常保留该端口）")
    cap.add_argument("--jsonl", default=None, help="把每条记录追加写到这个文件")
    cap.add_argument("--domain", action="append", default=None, choices=sorted(ADAPTERS),
                     help="只跑这些领域（可重复；缺省 = 全部 5 个）")
    cap.add_argument("--analyze-all", action="store_true",
                     help="连静态资源也分析（默认跳过 .css/.js/图片等）")
    cap.add_argument("--no-mitm", action="store_true",
                     help="关闭本地 CA 解密：HTTPS 一律隧道直通（不拆包）")
    cap.add_argument("--upstream", default=None, metavar="HOST:PORT",
                     help="上游代理（例 127.0.0.1:10090）：流量链 浏览器 → 捕获 → 上游")
    cap.set_defaults(func=_cmd_capture)

    r = sub.add_parser("regression", help="已知案例反验证（平台有效性自证，改判定后必跑）")
    r.set_defaults(func=_cmd_regression)

    cs = sub.add_parser("cases", help="列出全部已知案例")
    cs.set_defaults(func=_cmd_cases)

    c = sub.add_parser("case", help="摊开一个已知案例（原始字节 + 两侧观测 + 判定）")
    c.add_argument("id", help="案例 id，见 python -m ced cases")
    c.add_argument("--raw", action="store_true",
                   help="只输出原始字节，可管道给 nc/curl 打靶")
    c.set_defaults(func=_cmd_case)

    p = sub.add_parser("probe", help="探测一份原始字节文件（任意请求），对全部或指定实现做差分")
    p.add_argument("file", help="原始字节文件；用 - 从 stdin 读")
    p.add_argument("--pair", nargs=2, metavar=("LEFT", "RIGHT"),
                   help="只比较指定的一对实现，并打印两侧完整观测")
    p.add_argument("--topology", default=None, help="拓扑文件（YAML/JSON）；缺省用内置 demo")
    p.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS))
    p.add_argument("--show", action="store_true", help="即使无分歧也打印两侧观测")
    p.set_defaults(func=_cmd_probe)

    i = sub.add_parser("impls", help="列出参照实现与定向对照（默认所有领域）")
    i.add_argument("--domain", default=None, choices=sorted(ADAPTERS),
                   help="只看某个领域")
    i.set_defaults(func=_cmd_impls)

    st = sub.add_parser("stats", help="生成仓库规模数字（README 指标表的单一真源）")
    st.set_defaults(func=_cmd_stats)

    vf = sub.add_parser(
        "verify", help="验证外部发现：把 nuclei/Burp/清单的命中当假设，用同一条 oracle 链证实或证伪")
    vf.add_argument("input", help="清单文件；用 - 从 stdin 读")
    vf.add_argument("--format", default="auto",
                    choices=["auto", "nuclei", "burp", "har", "curl", "list"],
                    help="输入格式（默认按内容与文件名自动识别）")
    vf.add_argument("--domain", action="append", default=None,
                    choices=sorted(ADAPTERS), help="只用这些领域验证（可重复）")
    vf.add_argument("--out", default=None, help="把验证报告写成 Markdown")
    vf.add_argument("--json", default=None, help="把验证结果写成 JSON")
    vf.set_defaults(func=_cmd_verify)


    pc = sub.add_parser("poc", help="摊开一条 security 级发现的端到端 PoC（场景 + 字节归属 + 复现脚本）")
    pc.add_argument("case_id", help="用例 id，见 python -m ced scan 的输出")
    pc.add_argument("--out", default="results/pocs", help="PoC 脚本输出目录")
    pc.add_argument("--stdout", action="store_true", help="把脚本打到标准输出，不落盘")
    pc.add_argument("--topology", default=None, help="拓扑文件；缺省用内置 demo")
    pc.add_argument("--domain", default="http1-framing", choices=sorted(ADAPTERS))
    pc.add_argument("--mode", choices=["axis", "cross"], default="axis")
    pc.add_argument("--limit", type=int, default=None,
                    help="用例数上限（需与生成该发现时一致）")
    pc.add_argument("--seed", type=int, default=42)
    pc.add_argument("--no-minimize", action="store_true")
    pc.set_defaults(func=_cmd_poc)

    return ap


def _silence_stdout() -> None:
    """下游关闭了管道时，把 stdout 接到空设备，别再写。

    POSIX 上这类情况是 ``BrokenPipeError``；Windows 上是 ``OSError: Errno 22``。
    两种都不是程序出错（`python -m ced ... | head` 就是正常用法），
    安静退出即可 —— 但要先静音 stdout，否则解释器退出时会再报一次。
    """
    try:
        sys.stdout.flush()
    except OSError:
        pass
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        _silence_stdout()
        return 0
    except OSError as exc:
        if getattr(exc, "errno", None) in (22, 32):      # EINVAL / EPIPE
            _silence_stdout()
            return 0
        raise


if __name__ == "__main__":
    raise SystemExit(main())
