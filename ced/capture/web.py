"""网页控制台用的自动捕获外壳。

代理本体在 :mod:`ced.capture.proxy`；这里只做网页要的四件事：
**起**、**停**、给**增量记录**、按 case_id 出**一条 PoC**。

为什么不用 SSE：捕获是「一直在收」的流水，不是一次有终点的任务；网页每 ~1 秒拉一次
增量（带 ``since=`` 序号）比维护一条长连接简单得多，也少一种出错方式。

内存边界：代理只保留最近 ``MAX_RECORDS`` 条给网页看，**完整记录在 JSONL 里** ——
被裁掉的老记录仍然可查（翻 JSONL），只是不能在网页上点开。
"""
from __future__ import annotations

import threading
from pathlib import Path

from .. import artifacts
from ..scenario.poc import build_poc
from .proxy import CaptureProxy, Config

#: PoC 脚本落到仓库的 results/pocs（与扫描产出的 PoC 同一个目录，口径统一）
POC_DIR = Path(__file__).resolve().parents[2] / "results" / "pocs"

#: 记录里对外暴露的字段（下划线开头的私有字段一律不给出去）
_PUBLIC_KEYS = ("ts", "seq", "case_id", "method", "host", "path", "target", "count",
                "skip", "tunnel", "elapsed_ms", "analysis")


def _brief(record: dict) -> dict:
    return {key: record.get(key) for key in _PUBLIC_KEYS}


def _preview(record: dict) -> str:
    """把留证的原始字节渲染成人能读的形式（\\r\\n 显式写出来，便于对照报告）。"""
    import base64

    raw = base64.b64decode(record.get("raw_b64") or b"") or b""
    if not raw:
        return ""
    text = raw.decode("latin-1").replace("\r\n", "\\r\\n").replace("\n", "\\n")
    return text[:800] + ("…（已截断）" if len(text) > 800 else "")


class CaptureRunner:
    """进程内只有一个代理在跑 —— 网页上的「开始 / 停止」就是它。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.proxy: CaptureProxy | None = None
        self.thread: threading.Thread | None = None

    # ------------------------------------------------------------------ 控制

    def start(self, *, port: int = 18081, domains=None, analyze_all: bool = False,
              jsonl: str | None = None) -> dict:
        with self._lock:
            if self.proxy is not None:
                return {"error": f"已经在跑（端口 {self.proxy.cfg.port}）；先停止再改参数"}
            config = Config(port=port, domains=domains or None,
                            analyze_all=bool(analyze_all),
                            jsonl=Path(jsonl) if jsonl else None)
            proxy = CaptureProxy(config)
            try:
                proxy.bind()
            except OSError as exc:
                return {"error": f"端口 {port} 起不来：{exc}"}
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            self.proxy, self.thread = proxy, thread
        return {"ok": True, **self.state()}

    def stop(self) -> dict:
        with self._lock:
            proxy = self.proxy
            if proxy is None:
                return {"ok": True, "running": False}
            proxy.cfg.stop.set()
            if self.thread is not None:
                self.thread.join(timeout=5)
            summary = proxy.summary()
            self.proxy, self.thread = None, None
        return {"ok": True, "running": False, "summary": summary}

    # ------------------------------------------------------------------ 读

    def state(self) -> dict:
        proxy = self.proxy
        if proxy is None:
            return {"running": False}
        return {"running": True, "port": proxy.cfg.port,
                "domains": list(proxy.cfg.domains) if proxy.cfg.domains else [],
                "analyze_all": proxy.cfg.analyze_all,
                "jsonl": str(proxy.cfg.jsonl) if proxy.cfg.jsonl else "",
                "seq": proxy.seq, "summary": proxy.summary()}

    def records(self, since: int = 0, limit: int = 300) -> dict:
        proxy = self.proxy
        if proxy is None:
            return {"running": False, "seq": 0, "records": [], "counts": {},
                    "summary": {"requests": 0, "analyzed": 0, "skipped": 0,
                                "tunnels": 0, "security_requests": 0, "divergences": 0}}
        with proxy.lock:
            items = list(proxy.records)
            seq = proxy.seq
            counts = dict(proxy.duplicate_counts)
        out: list[dict] = []
        for record in items:
            if int(record.get("seq") or 0) <= since:
                continue
            out.append(_brief(record))
            if len(out) >= limit:
                break
        return {"running": True, "seq": seq, "records": out,
                "counts": counts, "summary": proxy.summary()}

    def record(self, case_id: str) -> dict:
        proxy = self.proxy
        record = proxy.seen.get(case_id) if proxy else None
        if record is None:
            return {"error": "找不到这条记录（可能已被内存裁剪；完整记录在 JSONL 里）"}
        detail = _brief(record)
        detail.update({"raw_len": record.get("raw_len", 0),
                       "normalized": bool(record.get("normalized")),
                       "raw_b64": record.get("raw_b64", ""),
                       "raw_preview": _preview(record)})
        return detail

    # ------------------------------------------------------------------ PoC

    def poc(self, case_id: str, *, out_dir: Path | None = None) -> dict:
        proxy = self.proxy
        if proxy is None:
            return {"error": "捕获没有在跑，无法生成 PoC"}
        record = proxy.seen.get(case_id) or {}
        finding = record.get("_finding")
        if finding is None:
            return {"error": "这条记录没有可生成 PoC 的材料"
                             "（不是 security 级，或已被内存裁剪）"}
        domain = record.get("_top_domain") or "http1-framing"
        built = build_poc(finding, domain=domain)
        if built is None:
            return {"error": "该发现不是 security 级 —— 按口径不生成 PoC（宁可不升级）"}

        directory = Path(out_dir) if out_dir else POC_DIR
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / built.file_name
        artifacts.write_text(path, built.script)
        return {"ok": True, "path": str(path), "case_id": built.case_id,
                "domain": built.domain, "scenario": built.scenario, "title": built.title,
                "level": built.level, "cwe": built.cwe or "",
                "impact": built.impact, "fix": built.fix, "evidence": built.evidence,
                "chain_desc": built.chain_desc, "sample_len": built.sample_len,
                "steps": list(built.steps)}


__all__ = ["CaptureRunner", "POC_DIR"]
