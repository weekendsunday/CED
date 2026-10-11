"""本地网页界面：零依赖，只用 Python 标准库。

    python main.py                    # 启动并自动打开浏览器
    python -m ced web --port 8777     # 指定端口
    python -m ced web --no-open       # 不自动开浏览器

控制台由三部分组成：
  * 扫描任务   —— POST /api/scan/start + SSE /api/scan/events 实时进度
  * 结果 triage —— /api/scan/result，形状来自 ``report.renderer.result_payload``
  * 提案台账   —— /api/assist/*，展示"模型只提案、内核只裁决"的命中率

SSE 与页面都不用任何第三方库：事件流是手写的 ``text/event-stream``。
"""
from __future__ import annotations

import argparse
import base64
import json
import posixpath
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .. import regression, store
from .. import detect as detect_entry
from .. import settings as app_settings
from ..adapters import ADAPTERS
from ..adapters import get as get_adapter
from ..analysis import all_pairs, analyze, analyze_pairs
from ..capture.web import CaptureRunner
from ..contracts import ImplSpec
from ..impls import reference
from ..metrics import matrix_heatmap, scan_metrics
from ..orchestrate.topology import demo, load
from ..probe import Evaluator
from ..report.renderer import result_payload
from ..scan import JobRegistry
from ..scan import runner as scan_runner

STATIC = Path(__file__).resolve().parent
DEFAULT_PORT = 8777
#: 单条请求的字节上限 —— 本工具面向单条请求，不是整个流量包
MAX_PAYLOAD = 1 << 20
#: 扫描用例上限：语料是"轴 × 定向变异"，上千条已足够，再多只是重复
MAX_CASES = 5000
#: SSE 空闲心跳间隔（秒）—— 没有新事件时也往连接上写一个注释行，防空闲超时
SSE_WAIT = 20.0

#: 任务表在进程内存里 —— 服务重启后历史仍在库里，但结果对象不再可读（前端标 live=false）
REGISTRY = JobRegistry()

#: 自动捕获：进程内只有一个代理在跑（网页上的「开始 / 停止」就是它）
CAPTURE = CaptureRunner()

#: 可测试样本目录（网页「载入示例」用；只读、不许穿越）
SAMPLE_DIR = Path(__file__).resolve().parents[2] / "samples"


def _samples_list() -> list[dict]:
    if not SAMPLE_DIR.is_dir():
        return []
    items = []
    for path in sorted(SAMPLE_DIR.rglob("*")):
        if path.is_file() and path.name != "README.md":
            items.append({"name": str(path.relative_to(SAMPLE_DIR)).replace("\\", "/"),
                          "size": path.stat().st_size})
    return items

#: 检测任务的事件流。单独一张表 —— 别把"检测"混进「历史扫描任务」列表里
DETECT_REGISTRY = JobRegistry()


def _spec_for(impl_id: str, domain: str = "http1-framing") -> ImplSpec:
    return ImplSpec(impl_id=impl_id, name=impl_id, runner="local",
                    policy=impl_id, domain=domain)


def _impls_info() -> dict:
    base = reference.REFERENCES["ref-cl-first"]
    items = []
    for name, policy in reference.REFERENCES.items():
        delta = {k: v for k, v in policy.__dict__.items()
                 if k != "name" and base.__dict__[k] != v}
        items.append({"id": name,
                      "deviation": "、".join(f"{k}={v}" for k, v in delta.items())
                                   or "基线本身"})
    return {"impls": items}


def _domains_info() -> dict:
    """已注册领域一览 —— 控制台的领域选择器靠它填充。

    每个领域报出参照实现数与定向对照数，让使用者一眼看出"这个领域有多厚"。
    """
    from ..impls import axis_pairs, local_specs

    items = []
    for name in ADAPTERS:
        try:
            items.append({"name": name, "impls": len(local_specs(name)),
                          "pairs": len(axis_pairs(name))})
        except KeyError:
            items.append({"name": name, "impls": 0, "pairs": 0})
    return {"domains": sorted(items, key=lambda d: d["name"])}


def _case_brief(spec: dict) -> dict:
    return {"id": spec["id"], "axis": spec.get("axis", ""),
            "left": spec.get("left", ""), "right": spec.get("right", ""),
            "expect_kind": spec.get("expect_kind", ""),
            "payload_len": len(base64.b64decode(spec["payload_b64"]))}


# ------------------------------------------------------------------ 扫描与提案

def _jobs_view() -> dict:
    """任务列表 = 库里的历史 + 内存里更"新"的实时状态。

    跑着的任务在库里只有启动那一刻的快照，所以要被内存状态覆盖，
    否则前端看到的进度会永远停在 0。
    """
    conn = store.connect(scan_runner.db_path())
    try:
        rows = {r["job_id"]: r for r in store.list_jobs(conn, limit=40)}
    finally:
        conn.close()

    for job in REGISTRY.all():
        rows[job.job_id] = job.brief()

    jobs = []
    for job_id, row in rows.items():
        live = REGISTRY.get(job_id)
        item = dict(row)
        item["use_llm"] = bool(item.get("use_llm"))
        item["live"] = live is not None
        if live is not None:
            item.update({"state": live.state, "done_jobs": live.done_jobs,
                         "elapsed": live.brief()["elapsed"]})
        jobs.append(item)
    jobs.sort(key=lambda r: r.get("created") or 0, reverse=True)
    return {"jobs": jobs[:40]}


def _assist_status() -> dict:
    try:
        from ..assist.client import LlmClient, config_from_env
    except ImportError:                     # 旁路被整个删掉时，控制台也不该报错
        return {"available": False, "model": "", "base_url": "",
                "reason": "提案层不可用（ced/assist/ 不存在）—— 扫描仍然照跑"}

    cfg = config_from_env()
    client = LlmClient(cfg)
    reason = "" if client.available else (
        "未配置模型：设置 CED_LLM_BASE_URL 与 CED_LLM_MODEL"
        "（OpenAI 兼容端点）后可用；未配置时扫描仍然照跑，只是不带模型提案")
    return {"available": client.available, "model": cfg.model,
            "base_url": cfg.base_url, "reason": reason}


def _ledger_view(limit: int = 60) -> dict:
    conn = store.connect(scan_runner.db_path())
    try:
        return {"stats": store.proposal_stats(conn),
                "recent": store.recent_proposals(conn, limit=limit)}
    finally:
        conn.close()


def _attach_model_clues(payload: dict, result) -> None:
    """给每条发现挂上"这条是模型猜过的吗"：猜的是什么、过了准入没有。

    挂不上就留 ``None``，绝不编 —— 前端据此如实说"这条没有模型参与"。台账是旁路，
    读不到（库被删/路径不对）时整栏留空，不能让结果页打不开。
    """
    case_ids = [f.case_id for f in result.findings]
    clues: dict[str, dict] = {}
    if case_ids:
        conn = None
        try:
            conn = store.connect(scan_runner.db_path())
            clues = store.proposal_clues(conn, case_ids)
        except Exception:                  # noqa: BLE001 —— 线索是可选装饰，不是结果
            clues = {}
        finally:
            if conn is not None:
                conn.close()
    for item in payload.get("findings", ()):
        item["clue"] = clues.get(item.get("case_id"))


class _Server(ThreadingHTTPServer):
    #: Windows 上 SO_REUSEADDR 允许两个进程绑同一端口，
    #: 那会让"端口被占就自动换"形同虚设 —— 关掉它，让第二次绑定如实失败。
    allow_reuse_address = False


class Handler(BaseHTTPRequestHandler):
    server_version = "CED-Web/0.2"
    #: 事件流需要长连接；HTTP/1.1 下每个响应都带 Content-Length（或显式 close），
    #: 所以普通请求的 keep-alive 仍然正确。
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ 工具
    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", code)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def log_message(self, *args) -> None:      # 安静模式
        pass

    # ------------------------------------------------------------------ GET
    def do_GET(self):                                   # noqa: N802
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path in ("/", "/index.html"):
            return self._send((STATIC / "index.html").read_bytes(),
                              "text/html; charset=utf-8")
        if url.path == "/api/health":
            return self._json({"ok": True})
        if url.path == "/api/impls":
            return self._json(_impls_info())
        if url.path == "/api/domains":
            return self._json(_domains_info())
        if url.path == "/api/cases":
            return self._json({"cases": [_case_brief(c)
                                         for c in regression.load_cases()]})
        if url.path == "/api/case":
            return self._case_detail((query.get("id") or [""])[0])
        if url.path == "/api/scan/jobs":
            return self._json(_jobs_view())
        if url.path == "/api/scan/events":
            return self._sse((query.get("job_id") or [""])[0])
        if url.path == "/api/scan/result":
            return self._scan_result((query.get("job_id") or [""])[0])
        if url.path == "/api/scan/metrics":
            return self._scan_metrics((query.get("job_id") or [""])[0])
        if url.path == "/api/scan/heatmap":
            return self._scan_heatmap((query.get("job_id") or [""])[0])
        if url.path == "/api/assist/status":
            return self._json(_assist_status())
        if url.path == "/api/assist/ledger":
            return self._json(_ledger_view())
        if url.path == "/api/capture/state":
            return self._json(CAPTURE.state())
        if url.path == "/api/capture/records":
            try:
                since = int((query.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            return self._json(CAPTURE.records(since))
        if url.path == "/api/capture/record":
            return self._json(CAPTURE.record((query.get("case_id") or [""])[0]))
        if url.path == "/api/detect/stages":
            return self._json({"stages": list(detect_entry.STAGES)})
        if url.path == "/api/detect/events":
            return self._sse((query.get("job_id") or [""])[0], DETECT_REGISTRY)
        if url.path == "/api/settings":
            return self._json(app_settings.public_view())
        if url.path == "/api/samples":
            return self._json({"samples": _samples_list()})
        if url.path.startswith("/samples/"):
            return self._sample(url.path)
        return self._json({"error": "not found"}, 404)

    def _sample(self, path: str) -> None:
        """把 samples/ 下的样本**按字节**发给前端。

        为什么单独一条静态路由：原始请求必须字节保真（前端靠它填进"exact"缓冲，
        而不是走会被规范化的文本框）。只允许该目录内部，不许路径穿越。
        """
        base = SAMPLE_DIR.resolve()
        name = posixpath.normpath(unquote(path[len("/samples/"):]))
        try:
            target = (base / name).resolve()
        except OSError:
            return self._json({"error": "非法路径"}, 400)
        if not str(target).startswith(str(base)) or not target.is_file():
            return self._json({"error": "没有这个样本"}, 404)
        self._send(target.read_bytes(), "application/octet-stream")

    # ----------------------------------------------------------------- POST
    def do_POST(self):                                  # noqa: N802
        url = urlparse(self.path)
        try:
            body = self._read_body()
        except Exception as exc:
            return self._json({"error": f"请求体不是合法 JSON：{exc}"}, 400)

        if url.path == "/api/probe":
            return self._probe(body)
        if url.path == "/api/regression":
            return self._regression()
        if url.path == "/api/scan/start":
            return self._scan_start(body)
        if url.path == "/api/scan/abort":
            return self._scan_abort(body)
        if url.path == "/api/assist/propose":
            return self._assist_propose(body)
        if url.path == "/api/verify":
            return self._verify(body)
        if url.path == "/api/capture/start":
            return self._capture_start(body)
        if url.path == "/api/capture/stop":
            return self._json(CAPTURE.stop())
        if url.path == "/api/capture/poc":
            result = CAPTURE.poc(str(body.get("case_id") or ""))
            return self._json(result, 200 if result.get("ok") else 400)
        if url.path == "/api/detect":
            return self._detect_start(body)
        if url.path == "/api/settings":
            return self._settings_save(body)
        return self._json({"error": "not found"}, 404)

    def _detect_start(self, body: dict) -> None:
        """单一入口：把输入交给 detect，前端随后用 SSE 看 DAG 与实时报告。

        识别不出来的输入**当场**报人事话（400），不留到事件流里再报。
        """
        text = body.get("text") or ""
        if not isinstance(text, str) or not text.strip():
            return self._json({"error": "输入是空的 —— 粘一条 HTTP 请求，"
                                        "或一份 nuclei / Burp / HAR / curl / URL 清单"}, 400)
        domains = body.get("domains") or None
        if isinstance(domains, str):
            domains = [item.strip() for item in domains.split(",") if item.strip()]
        unknown = [item for item in (domains or []) if item not in ADAPTERS]
        if unknown:
            return self._json({"error": f"未知领域：{', '.join(unknown)}"}, 400)
        try:
            kind, why, _ = detect_entry.identify(text)
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)

        job = DETECT_REGISTRY.create(domain="detect", mode="detect", limit=1)
        job.emit({"type": "queued", "kind": kind, "why": why})

        def worker() -> None:
            try:
                result = detect_entry.run(text, domains=domains, emit=job.emit)
                job.emit({"type": "done", "result": result,
                          "summary": result.get("summary", {})})
                job.finish(DONE)
            except Exception as exc:      # noqa: BLE001 —— 失败要写给前端，不许静默
                job.emit({"type": "error", "error": f"{type(exc).__name__}: {exc}"})
                job.finish(FAILED, error=str(exc))

        threading.Thread(target=worker, daemon=True).start()
        return self._json({"job_id": job.job_id, "kind": kind, "why": why})

    def _settings_save(self, body: dict) -> None:
        try:
            saved = app_settings.save(body or {})
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"ok": True, "settings": app_settings.public_view(saved)})

    def _capture_start(self, body: dict) -> None:
        """起自动捕获。端口被占 / 领域写错都要**当场**说清楚，不留给后台线程。

        **请求里没给的字段一律回落到「设置」里保存的默认值** —— 否则设置页就是个摆设
        （改了端口、写了记录文件，起捕获时却不用它）。
        """
        saved = app_settings.load()["capture"]
        try:
            port = int(body.get("port") or saved.get("port") or 18081)
        except (TypeError, ValueError):
            return self._json({"error": "端口必须是数字"}, 400)
        domains = body.get("domains")
        if domains in (None, [], ""):
            domains = list(saved.get("domains") or [])
        if isinstance(domains, str):
            domains = [item.strip() for item in domains.split(",") if item.strip()]
        unknown = [item for item in domains if item not in ADAPTERS]
        if unknown:
            return self._json({"error": f"未知领域：{', '.join(unknown)}"}, 400)
        analyze_all = body.get("analyze_all")
        if analyze_all is None:
            analyze_all = bool(saved.get("analyze_all"))
        jsonl = body.get("jsonl") or saved.get("jsonl") or None
        upstream = (str(body.get("upstream") or saved.get("upstream") or "").strip()
                    or None)
        if upstream and upstream.count(":") != 1:
            return self._json({"error": "上游代理要写成 HOST:PORT（例 127.0.0.1:10090）"}, 400)
        result = CAPTURE.start(port=port, domains=domains or None,
                               analyze_all=bool(analyze_all), jsonl=jsonl,
                               upstream=upstream)
        return self._json(result, 200 if result.get("ok") else 400)

    # ----------------------------------------------------------------- 业务
    def _evaluator(self, topology_path: str, domain: str = "http1-framing"):
        if topology_path:
            topo = load(topology_path)
        else:
            topo = demo(domain)
        return topo, Evaluator(topo.impls)

    def _probe(self, body: dict) -> None:
        try:
            payload = base64.b64decode(body.get("data_b64") or "", validate=True)
        except Exception as exc:
            return self._json({"error": f"data_b64 不是合法 base64：{exc}"}, 400)
        if not payload:
            return self._json({"error": "没有收到字节 —— 先选一个文件"}, 400)
        if len(payload) > MAX_PAYLOAD:
            return self._json(
                {"error": f"文件太大（{len(payload)} 字节 > {MAX_PAYLOAD}）——"
                          f"本工具面向单条请求，不是整个流量包"}, 400)

        domain = (body.get("domain") or "http1-framing").strip()
        if domain not in ADAPTERS:
            return self._json(
                {"error": f"未知领域：{domain}（可选：{', '.join(sorted(ADAPTERS))}）"}, 400)
        try:
            topo, evaluator = self._evaluator((body.get("topology") or "").strip(), domain)
        except Exception as exc:
            return self._json({"error": f"拓扑文件读不了：{exc}"}, 400)

        adapter = get_adapter(domain)

        if body.get("mode") == "pair":
            left, right = body.get("left"), body.get("right")
            missing = [i for i in (left, right) if i not in evaluator.specs]
            if missing:
                return self._json({"error": f"拓扑里没有这些实现：{missing}"}, 400)
            pairs = [(left, right)]
        else:
            pairs = all_pairs(evaluator.specs)

        try:
            results = analyze_pairs(payload, pairs, evaluator, adapter,
                                    minimize=True)
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

        return self._json({
            "payload_len": len(payload),
            "payload_repr": repr(payload),
            "topology": topo.describe(),
            "pairs_tested": len(pairs),
            "diverged": sum(1 for r in results if r["diverged"]),
            "results": results,
        })

    def _verify(self, body: dict) -> None:
        """验证外部发现：把别人的命中当假设，用同一条 oracle 链证实/证伪。

        判定由内核给出，不看报告方自述 —— 因此这里绝不接受调用方传进来的"结论"。
        """
        from ..intake import load
        from ..intake import verify as verify_hypotheses

        text = body.get("text") or ""
        if not text.strip():
            return self._json({"error": "没有内容可验证 —— 先贴一份清单"}, 400)
        fmt = (body.get("fmt") or "auto").strip()
        domains = [d for d in (body.get("domains") or []) if d in ADAPTERS]
        try:
            hypotheses = load(text, fmt=fmt)
        except Exception as exc:
            return self._json({"error": f"读不了这份清单：{exc}"}, 400)
        if not hypotheses:
            return self._json({"error": "识别到了格式，但里面没有可验证的条目"}, 400)
        try:
            results = verify_hypotheses(hypotheses, domains=domains or None)
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

        counts = {k: sum(1 for v in results if v.verdict == k)
                  for k in ("confirmed", "refuted", "unverifiable")}
        return self._json({
            "counts": counts,
            "items": [{
                "verdict": v.verdict, "target": v.hypothesis.target,
                "source": v.hypothesis.source, "domain": v.domain,
                "left": v.left, "right": v.right, "level": v.level,
                "kind": v.kind, "reason": v.reason, "evidence": v.evidence,
                "detail": v.detail,
            } for v in results],
        })

    def _case_detail(self, case_id: str) -> None:
        cases = {c["id"]: c for c in regression.load_cases()}
        if case_id not in cases:
            return self._json({"error": f"没有这个案例：{case_id}"}, 404)
        spec = cases[case_id]
        payload = base64.b64decode(spec["payload_b64"])
        domain = spec.get("domain", "http1-framing")
        adapter = get_adapter(domain)
        evaluator = Evaluator([_spec_for(spec["left"], domain),
                               _spec_for(spec["right"], domain)])
        result = analyze(payload, spec["left"], spec["right"], evaluator,
                         adapter, minimize=True)
        outcome = regression.run(cases=[spec])[0]
        return self._json({
            "case": {k: spec[k] for k in
                     ("id", "axis", "left", "right", "expect_kind",
                      "expect_fields", "reference", "note") if k in spec},
            "payload_repr": repr(payload),
            "result": result,
            "regression": {"passed": outcome.passed, "detail": outcome.detail},
        })

    def _regression(self) -> None:
        outcomes = regression.run()
        return self._json({
            "total": len(outcomes),
            "passed": sum(1 for o in outcomes if o.passed),
            "items": [{"name": o.name, "passed": o.passed, "detail": o.detail}
                      for o in outcomes],
        })

    # ------------------------------------------------------------------ 扫描任务
    def _scan_start(self, body: dict) -> None:
        domain = (body.get("domain") or "http1-framing").strip()
        if domain not in ADAPTERS:
            return self._json(
                {"error": f"未知领域：{domain}（可选：{', '.join(sorted(ADAPTERS))}）"}, 400)

        mode = (body.get("mode") or "axis").strip()
        if mode not in ("axis", "cross"):
            return self._json({"error": f"未知模式：{mode}（可选：axis / cross）"}, 400)

        limit = None
        raw_limit = body.get("limit")
        if raw_limit not in (None, "", 0, "0"):
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                return self._json({"error": "用例上限必须是整数"}, 400)
            if not 1 <= limit <= MAX_CASES:
                return self._json(
                    {"error": f"用例上限必须在 1..{MAX_CASES} 之间"}, 400)

        try:
            seed = int(body.get("seed") or 42)
        except (TypeError, ValueError):
            return self._json({"error": "随机种子必须是整数"}, 400)

        topology = (body.get("topology") or "").strip()
        if topology:
            try:                    # 起任务前先把拓扑读通，别等进了线程才炸
                load(topology)
            except Exception as exc:
                return self._json({"error": f"拓扑文件读不了：{exc}"}, 400)

        job = scan_runner.start(
            REGISTRY, domain=domain, mode=mode, limit=limit, seed=seed,
            use_llm=bool(body.get("use_llm")), topology=topology)
        return self._json({"job_id": job.job_id})

    def _scan_abort(self, body: dict) -> None:
        job_id = (body.get("job_id") or "").strip()
        if not REGISTRY.abort(job_id):
            return self._json({"error": f"没有这个任务：{job_id}"}, 404)
        return self._json({"ok": True})

    def _scan_result(self, job_id: str) -> None:
        job = REGISTRY.get(job_id)
        if job is None:
            return self._json(
                {"error": "结果已不在内存（服务重启过，或任务号不对）"}, 404)
        if job.result is None:
            return self._json(
                {"error": f"任务 {job_id} 还没有产出结果（状态 {job.state}）"}, 409)
        payload = result_payload(job.result)
        _attach_model_clues(payload, job.result)
        return self._json({"job": job.brief(), "result": payload})

    def _scan_metrics(self, job_id: str) -> None:
        job = REGISTRY.get(job_id)
        if job is None:
            return self._json(
                {"error": "结果已不在内存（服务重启过，或任务号不对）"}, 404)
        if job.result is None:
            return self._json(
                {"error": f"任务 {job_id} 还没有产出结果（状态 {job.state}）"}, 409)
        return self._json(
            {"metrics": scan_metrics(job.result, elapsed=job.brief()["elapsed"])})

    def _scan_heatmap(self, job_id: str) -> None:
        job = REGISTRY.get(job_id)
        if job is None:
            return self._json(
                {"error": "结果已不在内存（服务重启过，或任务号不对）"}, 404)
        if job.result is None:
            return self._json(
                {"error": f"任务 {job_id} 还没有产出结果（状态 {job.state}）"}, 409)
        return self._json(matrix_heatmap(job.result, job.result.impl_ids))

    def _sse(self, job_id: str, registry: JobRegistry = REGISTRY) -> None:
        """手写事件流：一条连接到底，事件自己序列化。

        用 ``Connection: close`` + 不给 Content-Length 来表达"消息以连接关闭结束"，
        这样不必自己实现 chunked 编码。
        """
        job = registry.get(job_id)
        if job is None:
            return self._json({"error": f"没有这个任务：{job_id}"}, 404)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        cursor = 0
        try:
            while True:
                events = job.drain(cursor, timeout=SSE_WAIT)
                if events:
                    for event in events:
                        body = json.dumps(event, ensure_ascii=False)
                        self.wfile.write(b"data: " + body.encode("utf-8") + b"\n\n")
                    cursor += len(events)
                else:                       # 注释行：什么都不表示，只为保持连接活跃
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
                if events and events[-1].get("type") in ("done", "error"):
                    return
                if job.closed and cursor >= job.stream_length:
                    return
        except (BrokenPipeError, ConnectionResetError, OSError):
            return                          # 浏览器关掉了页面而已，不是错误

    # ------------------------------------------------------------------ 提案台账
    def _assist_propose(self, body: dict) -> None:
        try:
            from ..adapters.base import axis_names
            from ..assist.client import LlmClient, config_from_env
            from ..assist.compile import admit as admit_proposals
            from ..assist.ledger import record_many, record_rejected
            from ..assist.propose import propose as propose_axes

            domain = (body.get("domain") or "http1-framing").strip()
            if domain not in ADAPTERS:
                return self._json(
                    {"error": f"未知领域：{domain}（可选：{', '.join(sorted(ADAPTERS))}）"}, 400)
        except ImportError as exc:
            return self._json(
                {"error": f"提案层不可用（{exc}）—— 扫描不受影响"}, 400)

        try:
            n = int(body.get("n") or 8)
        except (TypeError, ValueError):
            return self._json({"error": "n 必须是整数"}, 400)
        n = max(1, min(n, 20))

        client = LlmClient(config_from_env())
        if not client.available:
            return self._json({"error": _assist_status()["reason"]}, 400)

        adapter = get_adapter(domain)
        evaluator = Evaluator(demo(domain).impls)
        conn = store.connect(scan_runner.db_path())
        try:
            proposals, rejected, raw = propose_axes(
                client, adapter_name=adapter.name, n=n,
                existing_axes=axis_names(adapter),
                history=store.proposal_history_brief(conn))
            for item in rejected:
                record_rejected(conn, item)
            admissions = admit_proposals(proposals, adapter, evaluator)
            record_many(conn, admissions)

            items = [{"proposal_id": a.proposal.proposal_id, "axis": a.proposal.axis,
                      "compiled": True, "admitted": a.admitted,
                      "fields": list(a.fields), "rationale": a.proposal.rationale,
                      "note": a.detail,
                      "payload_repr": repr(a.proposal.payload)[:600]}
                     for a in admissions]
            items += [{"proposal_id": "", "axis": r.axis, "compiled": False,
                       "admitted": False, "fields": [], "rationale": "",
                       "note": f"{r.reason}：{r.detail}"[:300], "payload_repr": ""}
                      for r in rejected]
            return self._json({"items": items, "stats": store.proposal_stats(conn),
                               "raw": raw[:4000]})
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        finally:
            conn.close()


# ---------------------------------------------------------------------- 启动

def _bind(host: str, port: int) -> ThreadingHTTPServer:
    """绑定端口。请求的端口被占用时自动往后找，最后交给系统随便给一个。

    双击/连点两次启动是常态，因为"端口被占"直接崩掉是不可接受的。
    """
    tried: list[int] = []
    for candidate in [port] + [port + i for i in range(1, 10)]:
        try:
            return _Server((host, candidate), Handler)
        except OSError:
            tried.append(candidate)
    httpd = _Server((host, 0), Handler)          # 让系统分配
    print(f"[i] 端口 {'、'.join(map(str, tried))} 都被占用了，改用系统分配的端口。")
    return httpd


def serve(port: int = DEFAULT_PORT, host: str = "127.0.0.1",
          open_browser: bool = False) -> None:
    try:
        httpd = _bind(host, port)
    except OSError as exc:
        raise SystemExit(f"[!] 起不来：{exc}") from exc

    actual = httpd.server_address[1]
    url = f"http://{host}:{actual}/"
    # 把上次保存的设置（尤其模型 API 接入）在启动时生效 —— 复用 CED_LLM_* 读取路径
    app_settings.apply_llm_env()
    print(f"CED 网页界面已启动：{url}", flush=True)
    print("在这个窗口按 Ctrl+C 停止。", flush=True)

    if open_browser:
        # 用**实际**绑定的端口，而不是请求的端口 —— 端口被占时两者不同
        threading.Thread(target=lambda: (time.sleep(0.5), webbrowser.open(url)),
                         daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ced web", description="CED 本地网页界面")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-open", action="store_true", help="不要自动打开浏览器")
    args = ap.parse_args(argv)

    serve(args.port, args.host, open_browser=not args.no_open)
    return 0
