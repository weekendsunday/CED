"""把一次扫描跑成任务：装配 → 差分扫描 → 落库。

**这一层不做判定。** 判定仍然只发生在 ``classify.upgradability.judge``；
语料只来自领域适配器自带的轴，模型不参与"往哪里搜"。
"""
from __future__ import annotations

import os
import threading
import time

from .. import store
from ..adapters import get as get_adapter
from ..orchestrate.topology import demo, load
from ..pipeline import plan_jobs, scan
from ..probe import Evaluator
from ..report.renderer import summary_of
from .job import (ABORTED, DONE, FAILED, RUNNING, JobAborted, JobRegistry,
                  ScanJob)

DEFAULT_DB = "ced.db"


def db_path() -> str:
    """任务库位置。用 ``CED_DB`` 覆盖；缺省落在当前工作目录（与 CLI 一致）。"""
    return os.environ.get("CED_DB") or DEFAULT_DB


def _counts(result) -> dict:
    """SSE 完成事件与控制台用的汇总 —— 与 ``/api/scan/result`` 的 summary 同口径。"""
    counts = {"total_cases": 0, "jobs": 0, "divergences": 0, "security": 0,
              "rejected_cases": 0, "by_level": {}, "by_kind": {}}
    if result is None:
        return counts
    counts["total_cases"] = result.total_cases
    counts["jobs"] = result.jobs
    counts["divergences"] = len(result.divergences)
    counts["security"] = len(result.security)
    counts["rejected_cases"] = getattr(result, "rejected_cases", 0)
    counts.update(summary_of(result))
    return counts


# --------------------------------------------------------------------- 任务执行

def run_job(job: ScanJob, *, db: str | None = None) -> None:
    """在**后台线程**里跑完一个任务。任何异常都落到 job 状态，不向外抛。"""
    db = db or db_path()
    job.state = RUNNING
    job.started = time.time()
    conn = None
    try:
        adapter = get_adapter(job.domain)
        topo = load(job.topology) if job.topology else demo(job.domain)
        evaluator = Evaluator(topo.impls)
        job.total_jobs = len(plan_jobs(adapter, list(evaluator.specs), job.mode))
        job.emit({"type": "stage", "stage": "topology", "detail": topo.describe()})

        conn = store.connect(db)
        store.save_job(conn, job.row())

        job.emit({"type": "stage", "stage": "scan",
                  "detail": "开始差分扫描"})

        def on_progress(done: int, total: int, result) -> None:
            if job.aborting:
                raise JobAborted()
            job.done_jobs, job.total_jobs = done, total
            job.total_cases = result.total_cases
            job.n_divergence = len(result.divergences)
            job.n_security = len(result.security)
            job.result = result          # 活对象：中止时这里是已完成的部分
            job.emit({"type": "progress", "done": done, "total": total,
                      "cases": result.total_cases,
                      "divergences": len(result.divergences),
                      "security": len(result.security)})

        try:
            result = scan(adapter, evaluator, mode=job.mode, limit=job.limit,
                          seed=job.seed, on_progress=on_progress)
        except JobAborted:
            result = job.result
            final_state = ABORTED
            job.emit({"type": "stage", "stage": "save",
                      "detail": "已中止 —— 保留已完成的部分结果"})
        else:
            final_state = DONE

        job.result = result
        if result is not None:
            job.total_cases = result.total_cases
            job.n_divergence = len(result.divergences)
            job.n_security = len(result.security)
            store.save_scan(conn, result, adapter.name)
        store.save_job(conn, {**job.row(), "state": final_state})
        # 顺序是有意的：**先发终态事件，再置终态**。
        # 反过来的话，事件流的读者会在 done 到达之前看到 closed 而提前收线。
        job.emit({"type": "done", "state": final_state, "summary": _counts(result)})
        job.finish(final_state)
    except Exception as exc:                       # noqa: BLE001 —— 任务线程不能崩
        text = f"{type(exc).__name__}: {exc}"
        job.emit({"type": "error", "text": text})
        job.finish(FAILED, error=text)
        if conn is not None:
            try:
                store.save_job(conn, job.row())
            except Exception:                      # 落库失败不能盖掉真实错误
                pass
    finally:
        if conn is not None:
            conn.close()


def start(registry: JobRegistry, **kwargs) -> ScanJob:
    """建任务并立刻在后台线程里跑起来，返回可立即订阅事件流的任务。"""
    job = registry.create(**kwargs)
    threading.Thread(target=run_job, args=(job,),
                     name=f"ced-scan-{job.job_id}", daemon=True).start()
    return job
