"""网页控制台用的自动捕获外壳。

代理本体在 :mod:`ced.capture.proxy`；这里只做网页要的五件事：
**起**、**停**、给**增量记录**、按 case_id 出**一条 PoC**、**删记录**。

为什么不用 SSE：捕获是「一直在收」的流水，不是一次有终点的任务；网页每 ~1 秒拉一次
增量（带 ``since=`` 序号）比维护一条长连接简单得多，也少一种出错方式。

内存边界：代理只保留最近 ``MAX_RECORDS`` 条给网页看，**完整记录在 JSONL 里** ——
被裁掉的老记录仍然可查（翻 JSONL），只是不能在网页上点开。

会话：一次「开始接入 → 停止」算**一次会话**。除了正在跑的那次，内存里还留最近
``ARCHIVE_SESSIONS`` 次已结束的快照，好让侧栏按"一次接入一条"回看 —— 点开就是当时的
记录与证据。同样只是"网页上还点得开几次"，完整记录始终在 JSONL 台账里。
"""
from __future__ import annotations

import base64

import threading
import time
from collections import deque
from pathlib import Path

from .. import artifacts
from ..scenario.poc import build_poc
from ..report.fixview import fix_view
from .proxy import CaptureProxy, Config

#: PoC 脚本落到仓库的 results/pocs（与扫描产出的 PoC 同一个目录，口径统一）
POC_DIR = Path(__file__).resolve().parents[2] / "results" / "pocs"

#: 内存里最多留几次**已结束**的会话给网页回看；更老的只能翻 JSONL 台账
ARCHIVE_SESSIONS = 3

#: 没有会话 / 一条都没过时的空统计（键与 ``CaptureProxy.summary()`` 对齐）
_ZERO_SUMMARY = {"requests": 0, "analyzed": 0, "skipped": 0, "tunnels": 0,
                 "security_requests": 0, "divergences": 0,
                 "divergent_requests": 0, "by_severity": {}}

#: 记录里对外暴露的字段（下划线开头的私有字段一律不给出去）
_PUBLIC_KEYS = ("ts", "seq", "case_id", "method", "host", "path", "target", "count",
                "skip", "tunnel", "mitm", "elapsed_ms", "analysis", "interpret")


class _EndedSession:
    """一次**已经结束**的捕获会话（内存快照）。

    字段名刻意与 :class:`CaptureProxy` 对齐（``records`` / ``seen`` /
    ``duplicate_counts`` / ``interpretations`` / ``interpret_stats`` / ``seq`` /
    ``lock`` / ``summary()``），这样下面几个读接口读"正在跑的"和"已经结束的"是
    同一段代码 —— 两套写法迟早各自跑偏（比如删记录只在一头生效）。

    ``seen`` 也留着：看证据、出 PoC 都要原始字节与 ``_finding``，
    只有 records 里的那份概要不够用。
    """

    def __init__(self, sid: str, t0: float, t1: float, *, port: int, domains,
                 jsonl: str, mitm: bool, interpret: bool, records, seen, counts,
                 interpretations, interpret_stats, summary: dict, seq: int) -> None:
        self.id, self.t0, self.t1 = sid, t0, t1
        self.port, self.domains, self.jsonl = port, list(domains), jsonl
        self.mitm, self.interpret = bool(mitm), bool(interpret)
        self.records, self.seen = records, seen
        self.duplicate_counts = counts
        self.interpretations, self.interpret_stats = interpretations, interpret_stats
        self.seq = seq
        self.lock = threading.Lock()      # 只读快照；保持与代理同一套用法，免得读写两副面孔
        self._summary = dict(summary)

    def summary(self) -> dict:
        return dict(self._summary)

    def brief(self) -> dict:
        """侧栏要的那一行：什么时候接的、多少条、有多严重。"""
        return {"id": self.id, "t0": self.t0, "t1": self.t1, "running": False,
                "port": self.port, "interpret": self.interpret,
                "domains": list(self.domains), "summary": self.summary()}


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
        self._ended: deque = deque(maxlen=ARCHIVE_SESSIONS)   # 已结束会话的快照（新在前）
        self._live: dict = {}                # 正在跑那次的身份：{"id": ..., "t0": ...}
        self._next_id = 1

    # ------------------------------------------------------------------ 控制

    def start(self, *, port: int = 18081, domains=None, analyze_all: bool = False,
              jsonl: str | None = None, upstream: str | None = None,
              interpreter=None) -> dict:
        with self._lock:
            if self.proxy is not None:
                return {"error": f"已经在跑（端口 {self.proxy.cfg.port}）；先停止再改参数"}
            config = Config(port=port, domains=domains or None,
                            analyze_all=bool(analyze_all),
                            jsonl=Path(jsonl) if jsonl else None,
                            upstream=upstream or None,
                            interpreter=interpreter)
            proxy = CaptureProxy(config)
            try:
                proxy.bind()
            except OSError as exc:
                return {"error": f"端口 {port} 起不来：{exc}"}
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            self.proxy, self.thread = proxy, thread
            # 会话身份在**起的那一刻**定下来：侧栏那一行要用它标"哪一次"
            self._live = {"id": "cap%d" % self._next_id, "t0": time.time()}
            self._next_id += 1
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
            self._archive(proxy, summary)
            self.proxy, self.thread = None, None
            self._live = {}
        return {"ok": True, "running": False, "summary": summary}

    def _archive(self, proxy: CaptureProxy, summary: dict) -> None:
        """把刚停下的这次会话留一份快照给网页回看（调用方已持 ``self._lock``）。

        只留**有记录**的：起了就停、一条都没过，回看它没有任何意义，摆在侧栏里
        只是噪声。留不下的由 deque 的 maxlen 淘汰最老那次。
        """
        with proxy.lock:
            if not proxy.records:
                return
            entry = _EndedSession(
                self._live.get("id") or "cap?", self._live.get("t0") or 0.0, time.time(),
                port=proxy.cfg.port, domains=proxy.cfg.domains or (),
                jsonl=str(proxy.cfg.jsonl) if proxy.cfg.jsonl else "",
                mitm=bool(proxy.cfg.mitm), interpret=proxy.cfg.interpreter is not None,
                records=list(proxy.records), seen=dict(proxy.seen),
                counts=dict(proxy.duplicate_counts),
                interpretations=list(proxy.interpretations),
                interpret_stats=dict(proxy.interpret_stats),
                summary=summary, seq=proxy.seq)
        self._ended.append(entry)

    # ------------------------------------------------------------------ 读

    def _source(self, session: str | None):
        """按会话 id 取数据源；不给 id 就是**正在跑的那一次**。

        返回 ``(数据源, 是否在跑)``；数据源为 None 表示没有这次会话。
        归档条目与 :class:`CaptureProxy` 字段名一致，所以下面几个读接口不用分两套写法。
        """
        if session:
            for entry in list(self._ended):
                if entry.id == session:
                    return entry, False
            return None, False
        return self.proxy, True

    def sessions(self) -> dict:
        """侧栏要的会话清单：正在跑的那次 + 最近几次已结束的（新的在前）。"""
        out: list[dict] = []
        proxy = self.proxy
        if proxy is not None:
            out.append({"id": self._live.get("id", ""), "t0": self._live.get("t0", 0.0),
                        "t1": None, "running": True, "port": proxy.cfg.port,
                        "interpret": proxy.cfg.interpreter is not None,
                        "domains": list(proxy.cfg.domains) if proxy.cfg.domains else [],
                        "summary": proxy.summary()})
        # 先拷一份再遍历：停止会话可能正把新条目 append 进这个 deque，
        # 直接遍历会赶上"迭代中改动"（deque 会当场抛错）
        out.extend(entry.brief() for entry in reversed(list(self._ended)))
        return {"running": proxy is not None, "sessions": out}

    def state(self) -> dict:
        proxy = self.proxy
        from . import mitm as _mitm_mod
        base = {"running": proxy is not None}
        if proxy is None:
            return {**base, "mitm": _mitm_mod.mitm_available(),
                    "seq": 0, "summary": dict(_ZERO_SUMMARY)}
        return {"running": True, "port": proxy.cfg.port,
                "mitm": proxy.cfg.mitm and _mitm_mod.mitm_available(),
                "interpret": proxy.cfg.interpreter is not None,
                "domains": list(proxy.cfg.domains) if proxy.cfg.domains else [],
                "analyze_all": proxy.cfg.analyze_all,
                "jsonl": str(proxy.cfg.jsonl) if proxy.cfg.jsonl else "",
                "seq": proxy.seq, "summary": proxy.summary()}

    def interpretations(self, session: str | None = None) -> dict:
        """给网页的解读列表（只保最近 INTERPRET_KEEP 条）。

        前端每秒拉一次**全量**、不做增量游标：解读天生是**后到**的（模型比内核慢，
        一条请求可能先出现在列表里、几秒后才有解读），用序号做增量反而更难对齐；
        这个列表很小（最多 INTERPRET_KEEP 条、每条一段文字），全量拉不心疼。
        """
        source, running = self._source(session)
        if source is None:
            return {"running": False, "items": [],
                    "stats": {"done": 0, "failed": 0, "dropped": 0, "capped": 0}}
        with source.lock:
            items = list(source.interpretations)
            stats = dict(source.interpret_stats)
        return {"running": running, "items": items, "stats": stats}

    def records(self, since: int = 0, limit: int = 300,
                session: str | None = None) -> dict:
        source, running = self._source(session)
        if source is None:
            return {"running": False, "seq": 0, "records": [], "counts": {},
                    "summary": dict(_ZERO_SUMMARY)}
        with source.lock:
            items = list(source.records)
            seq = source.seq
            counts = dict(source.duplicate_counts)
        out: list[dict] = []
        for record in items:
            if int(record.get("seq") or 0) <= since:
                continue
            out.append(_brief(record))
            if len(out) >= limit:
                break
        return {"running": running, "seq": seq, "records": out,
                "counts": counts, "summary": source.summary()}

    def record(self, case_id: str, session: str | None = None) -> dict:
        source, _ = self._source(session)
        record = source.seen.get(case_id) if source is not None else None
        if record is None:
            return {"error": "找不到这条记录（可能已被内存裁剪；完整记录在 JSONL 里）"}
        detail = _brief(record)
        detail.update({"raw_len": record.get("raw_len", 0),
                       "normalized": bool(record.get("normalized")),
                       "raw_b64": record.get("raw_b64", ""),
                       "raw_preview": _preview(record)})
        # 修复形态：与**客户原样发来的字节**逐行对照。
        # 只在点开某一条时算（列表不走这条路），所以不心疼这一点计算。
        analysis = record.get("analysis") or {}
        top = analysis.get("top") or {}
        raw = base64.b64decode(record.get("raw_b64") or b"")
        if top.get("domain") and raw:
            detail["fix_view"] = fix_view(top["domain"], raw)
        return detail

    # ------------------------------------------------------------------ 删

    def forget(self, seq: int) -> dict:
        """删掉列表里的一条（按 seq 定位）。捕获没在跑也返回成功：那份列表本来就是空的。"""
        proxy = self.proxy
        if proxy is None:
            return {"ok": True, "removed": 0}
        removed = proxy.forget(seq)
        return {"ok": True, "removed": removed, "summary": proxy.summary()}

    def forget_all(self) -> dict:
        proxy = self.proxy
        if proxy is None:
            return {"ok": True, "removed": 0}
        removed = proxy.forget_all()
        return {"ok": True, "removed": removed, "summary": proxy.summary()}

    def forget_session(self, session: str) -> dict:
        """把一次**已结束**的会话从侧栏里移除（连带它的快照）。

        正在跑的那次不在这里删：它的记录用「清空记录」清，会话本体要停了才谈得上移除。
        """
        with self._lock:
            for entry in list(self._ended):
                if entry.id == session:
                    self._ended.remove(entry)
                    return {"ok": True, "removed": 1}
        return {"ok": True, "removed": 0}

    # ------------------------------------------------------------------ PoC

    def poc(self, case_id: str, *, out_dir: Path | None = None,
            session: str | None = None) -> dict:
        source, _ = self._source(session)
        if source is None:
            return {"error": "没有这次会话，无法生成 PoC"}
        record = source.seen.get(case_id) or {}
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
