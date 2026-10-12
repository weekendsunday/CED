"""结果落库（SQLite）。

刻意做了两件在同类工具里常被忽略的事：
  * ``connect()`` 自动创建父目录 —— 目标目录不存在时不再直接崩；
  * 库文件是**产物**，不应随源码分发（见 .gitignore）。
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS case_t (
    case_id   TEXT PRIMARY KEY,
    adapter   TEXT NOT NULL,
    axis      TEXT NOT NULL,
    payload   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS divergence (
    divergence_id INTEGER PRIMARY KEY,
    case_id       TEXT NOT NULL,
    axis          TEXT NOT NULL,
    left_impl     TEXT NOT NULL,
    right_impl    TEXT NOT NULL,
    diffs         TEXT NOT NULL          -- JSON
);
CREATE TABLE IF NOT EXISTS verdict (
    verdict_id    INTEGER PRIMARY KEY,
    divergence_id INTEGER NOT NULL,
    level         TEXT NOT NULL,
    kind          TEXT NOT NULL,
    reason        TEXT,
    cwe           TEXT,
    scenario      TEXT,
    controllable  INTEGER DEFAULT 0,
    ablation      TEXT
);
CREATE TABLE IF NOT EXISTS finding (
    finding_id    INTEGER PRIMARY KEY,
    divergence_id INTEGER NOT NULL,
    original_len  INTEGER,
    minimized_len INTEGER,
    minimized     BLOB,
    chain_evidence TEXT
);
-- 攻击场景 PoC：只对 security 级发现生成（判定器没升级的，这里不许替它升级）
CREATE TABLE IF NOT EXISTS poc (
    poc_id        INTEGER PRIMARY KEY,
    case_id       TEXT NOT NULL,
    divergence_id INTEGER,
    domain        TEXT,
    scenario      TEXT NOT NULL,          -- desync | bypass | authz | generic
    title         TEXT,
    level         TEXT,
    cwe           TEXT,
    left_impl     TEXT,
    right_impl    TEXT,
    quant_label   TEXT,                   -- 量化指标名（分帧=被夹带字节数；路径=资源错位）
    quant_json    TEXT,                   -- JSON: {label, describe, values, numbers, verified}
    verified      INTEGER NOT NULL DEFAULT 0,   -- 量化是否真的算出来了
    script_path   TEXT,
    script        TEXT,
    steps         TEXT,                   -- JSON: 复现步骤
    request_b64   TEXT,                   -- 最小复现样本
    ts            REAL
);
-- 扫描任务：前端控制台的历史与状态
CREATE TABLE IF NOT EXISTS scan_job (
    job_id       TEXT PRIMARY KEY,
    domain       TEXT NOT NULL,
    mode         TEXT NOT NULL,
    limit_n      INTEGER,
    seed         INTEGER,
    state        TEXT NOT NULL,               -- pending|running|done|failed|aborted
    created      REAL, started REAL, finished REAL,
    total_cases  INTEGER NOT NULL DEFAULT 0,
    total_jobs   INTEGER NOT NULL DEFAULT 0,
    n_divergence INTEGER NOT NULL DEFAULT 0,
    n_security   INTEGER NOT NULL DEFAULT 0,
    error        TEXT
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)     # ← 不因父目录缺失而崩
    conn = sqlite3.connect(p)
    conn.executescript(SCHEMA)
    _ensure_poc_shape(conn)
    return conn


def _ensure_poc_shape(conn: sqlite3.Connection) -> None:
    """``poc`` 表的列在开发中变过形（从分帧专用字段改成通用的量化字段）。

    它是**产物表**：随时可由 ``scan`` 重建。所以形状不对就重建，
    而不是留着旧结构让 INSERT 报错。
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(poc)")}
    if cols and cols != set(_POC_COLS):
        conn.execute("DROP TABLE poc")
        conn.executescript(SCHEMA)


def open_fresh(path: str | Path) -> sqlite3.Connection:
    """每次扫描用一个干净的库 —— 否则重复运行会在同一库里累积重复记录。"""
    p = Path(path)
    if p.exists():
        p.unlink()
    return connect(p)


def save_scan(conn: sqlite3.Connection, result, adapter_name: str) -> None:
    """把一次扫描全量落库。"""
    seen_cases: set[str] = set()
    for div in result.divergences:
        if div.case_id not in seen_cases:
            seen_cases.add(div.case_id)
            conn.execute(
                "INSERT OR REPLACE INTO case_t (case_id, adapter, axis, payload) "
                "VALUES (?,?,?,?)",
                (div.case_id, adapter_name, div.axis, sqlite3.Binary(div.payload)))
        cur = conn.execute(
            "INSERT INTO divergence (case_id, axis, left_impl, right_impl, diffs) "
            "VALUES (?,?,?,?,?)",
            (div.case_id, div.axis, div.left.impl_id, div.right.impl_id,
             json.dumps({d.key: [d.left, d.right] for d in div.diffs},
                        ensure_ascii=False)))
        div_id = cur.lastrowid
        for f in result.findings:
            if f.divergence is div:
                conn.execute(
                    "INSERT INTO verdict (divergence_id, level, kind, reason, cwe, "
                    "scenario, controllable, ablation) VALUES (?,?,?,?,?,?,?,?)",
                    (div_id, f.verdict.level, f.verdict.kind, f.verdict.reason,
                     f.verdict.cwe, f.verdict.scenario,
                     int(f.verdict.controllable), f.verdict.ablation))
                conn.execute(
                    "INSERT INTO finding (divergence_id, original_len, minimized_len, "
                    "minimized, chain_evidence) VALUES (?,?,?,?,?)",
                    (div_id, f.original_len, f.minimized_len,
                     sqlite3.Binary(f.minimized) if f.minimized is not None else None,
                     f.chain_evidence))
                break
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict:
    cases = conn.execute("SELECT COUNT(*) FROM case_t").fetchone()[0]
    levels = dict(conn.execute(
        "SELECT level, COUNT(*) FROM verdict GROUP BY level").fetchall())
    kinds = dict(conn.execute(
        "SELECT kind, COUNT(*) FROM verdict GROUP BY kind").fetchall())
    return {"cases": cases, "by_level": levels, "by_kind": kinds}


# --------------------------------------------------------------------- 攻击场景 PoC

_POC_COLS = ("case_id", "divergence_id", "domain", "scenario", "title", "level",
             "cwe", "left_impl", "right_impl", "quant_label", "quant_json",
             "verified", "script_path", "script", "steps", "request_b64", "ts")


def save_pocs(conn: sqlite3.Connection, pocs, *, script_dir: str | None = None
              ) -> int:
    """落库一批 PoC。按 case_id 幂等（重跑同一次扫描不会累积重复行）。"""
    written = 0
    for poc in pocs:
        row = conn.execute(
            "SELECT divergence_id FROM divergence WHERE case_id = ? LIMIT 1",
            (poc.case_id,)).fetchone()
        script_path = (str(Path(script_dir) / poc.file_name)
                       if script_dir else None)
        data = poc.to_dict()
        quant = data.get("quant") or {}
        conn.execute("DELETE FROM poc WHERE case_id = ?", (poc.case_id,))
        conn.execute(
            f"INSERT INTO poc ({', '.join(_POC_COLS)})"
            f" VALUES ({', '.join('?' * len(_POC_COLS))})",
            (poc.case_id, row[0] if row else None, poc.domain, poc.scenario,
             poc.title, poc.level, poc.cwe, poc.left, poc.right,
             quant.get("label"), json.dumps(quant, ensure_ascii=False),
             int(poc.verified), script_path, poc.script,
             json.dumps(list(poc.steps), ensure_ascii=False),
             poc.request_b64, time.time()))
        written += 1
    conn.commit()
    return written


def list_pocs(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        f"SELECT {', '.join(_POC_COLS)} FROM poc ORDER BY ts DESC LIMIT ?",
        (limit,)).fetchall()
    return [_poc_row(dict(zip(_POC_COLS, r))) for r in rows]


def load_poc(conn: sqlite3.Connection, case_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {', '.join(_POC_COLS)} FROM poc WHERE case_id = ? LIMIT 1",
        (case_id,)).fetchone()
    return _poc_row(dict(zip(_POC_COLS, row))) if row else None


def _poc_row(row: dict) -> dict:
    row["verified"] = bool(row.get("verified"))
    try:
        row["steps"] = json.loads(row.get("steps") or "[]")
    except (TypeError, ValueError):
        row["steps"] = []
    try:
        row["quant"] = json.loads(row.get("quant_json") or "null")
    except (TypeError, ValueError):
        row["quant"] = None
    return row


# --------------------------------------------------------------------- 扫描任务

_JOB_COLS = ("job_id", "domain", "mode", "limit_n", "seed", "state",
             "created", "started", "finished", "total_cases", "total_jobs",
             "n_divergence", "n_security", "error")


def save_job(conn: sqlite3.Connection, job: dict) -> None:
    values = tuple(job.get(col) for col in _JOB_COLS)
    conn.execute(
        f"INSERT OR REPLACE INTO scan_job ({', '.join(_JOB_COLS)})"
        f" VALUES ({', '.join('?' * len(_JOB_COLS))})", values)
    conn.commit()


def list_jobs(conn: sqlite3.Connection, limit: int = 30) -> list[dict]:
    rows = conn.execute(
        f"SELECT {', '.join(_JOB_COLS)} FROM scan_job ORDER BY created DESC LIMIT ?",
        (limit,)).fetchall()
    return [dict(zip(_JOB_COLS, r)) for r in rows]


def load_job(conn: sqlite3.Connection, job_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {', '.join(_JOB_COLS)} FROM scan_job WHERE job_id = ?",
        (job_id,)).fetchone()
    return dict(zip(_JOB_COLS, row)) if row else None
