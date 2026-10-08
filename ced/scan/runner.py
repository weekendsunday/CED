"""把一次扫描跑成任务：装配 →（可选）提案与准入实验 → 差分扫描 → 落库。

**这一层不做判定。** 判定仍然只发生在 ``classify.upgradability.judge``；
提案（手写或模型产出的）只影响"往哪里搜"，且必须先通过差分 oracle 的准入实验。
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


# --------------------------------------------------------------------- 提案准备

def _calibrate_handwritten(emit, adapter, evaluator, conn) -> None:
    """用**同一把尺子**先量一遍内置轴语料。

    不这么做，"模型提案命中率"就没有可比基线 —— 评审会问"你说模型有用，
    跟手写轴比呢？"。这一步给出同口径的对照数字。
    """
    from ..assist.compile import admit as admit_proposals
    from ..assist.ledger import record_many
    from ..contracts import ORIGIN_HANDWRITTEN, Proposal

    proposals = [
        Proposal(axis=axis, payload=payload, origin=ORIGIN_HANDWRITTEN,
                 rationale="内置轴语料")
        for axis, payload in adapter.corpus()
    ]
    admissions = admit_proposals(proposals, adapter, evaluator)
    record_many(conn, admissions)
    hits = sum(1 for a in admissions if a.admitted)
    emit({"type": "stage", "stage": "propose",
          "detail": f"手写轴基线：{hits}/{len(admissions)} 条通过准入实验"})


def _llm_proposals(emit, adapter, evaluator, conn, *, want: int = 8
                   ) -> list[tuple[str, bytes]]:
    """向模型要一批提案，逐条过两道门槛，返回通过准入实验的候选语料。"""
    from ..adapters.base import axis_names
    from ..assist.client import LlmClient, config_from_env
    from ..assist.compile import admit as admit_proposals
    from ..assist.ledger import record_many, record_rejected
    from ..assist.propose import propose as propose_axes

    client = LlmClient(config_from_env())
    if not client.available:
        emit({"type": "stage", "stage": "propose",
              "detail": "未配置模型（CED_LLM_BASE_URL / CED_LLM_MODEL）"
                        "—— 本次只用内置轴"})
        return []

    proposals, rejected, _raw = propose_axes(
        client, adapter_name=adapter.name, n=want, existing_axes=axis_names(adapter),
        history=store.proposal_history_brief(conn))
    for item in rejected:
        record_rejected(conn, item)

    if not proposals:
        emit({"type": "stage", "stage": "propose",
              "detail": f"模型没有产出可用提案（被丢弃 {len(rejected)} 条）"})
        return []

    admissions = admit_proposals(proposals, adapter, evaluator)
    record_many(conn, admissions)

    hit = sum(1 for a in admissions if a.admitted)
    emit({
        "type": "proposals",
        "accepted": hit,
        "rejected": len(rejected) + (len(admissions) - hit),
        "detail": f"模型提案 {len(admissions)} 条，通过准入实验 {hit} 条",
        "items": [{"proposal_id": a.proposal.proposal_id, "axis": a.proposal.axis,
                   "admitted": a.admitted, "fields": list(a.fields),
                   "note": a.detail} for a in admissions],
    })
    # 只有通过准入实验的提案才进语料 —— 没逼出分歧的提案到此为止
    return [a.proposal.to_case() for a in admissions if a.admitted]


def prepare_adopted(emit, adapter, evaluator, conn=None) -> list[tuple[str, bytes]]:
    """固化语料：加载人工采纳过的模型提案，**照样重跑一遍准入实验**。

    固化的意义是省掉模型调用，不是省掉门槛 —— 没逼出分歧的就地丢弃，
    "只有过了准入的才进语料"这条不变式因此依然字面成立。

    与人手无关：不勾「使用模型提案」也带上，它已经是内置基线的一部分。
    ``conn`` 给了才记账 —— 那本台账是记命中率用的，CLI 不落库时可以不传。
    """
    from .. import adopted
    from ..assist.compile import admit as admit_proposals
    from ..assist.ledger import record_many

    cases = adopted.load(adapter.name)
    if not cases:
        return []
    admissions = admit_proposals([c.to_proposal() for c in cases], adapter, evaluator)
    if conn is not None:
        record_many(conn, admissions)
    hit = sum(1 for a in admissions if a.admitted)
    emit({"type": "stage", "stage": "propose",
          "detail": f"固化语料 {len(admissions)} 条（{adopted.path_of(adapter.name).name}），"
                    f"重新过准入实验 {hit} 条通过"})
    return [a.proposal.to_case() for a in admissions if a.admitted]


def prepare_proposals(emit, adapter, evaluator, conn, *, want: int = 8
                      ) -> list[tuple[str, bytes]]:
    """提案准备：先在**同一把尺子**上量手写轴，再要模型提案，两者都过准入实验。

    ``emit(event: dict)`` 只要收得下事件字典即可 —— 控制台传 ``job.emit``，
    CLI 传一个打印函数。返回可直接交给 ``pipeline.scan(extra_cases=...)`` 的语料。
    """
    _calibrate_handwritten(emit, adapter, evaluator, conn)
    return _llm_proposals(emit, adapter, evaluator, conn, want=want)


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

        extra: list[tuple[str, bytes]] = prepare_adopted(job.emit, adapter,
                                                         evaluator, conn)
        if job.use_llm:
            extra += prepare_proposals(job.emit, adapter, evaluator, conn)
        job.n_proposal = len(extra)
        job.emit({"type": "stage", "stage": "scan",
                  "detail": f"提案候选 {len(extra)} 条（与内置语料重复的会被丢弃）；"
                            f"开始差分扫描"})

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
                          seed=job.seed, extra_cases=extra,
                          on_progress=on_progress)
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
            # 记账用**真正进池**的条数，而不是提案总数 —— 两者可能因去重而不同
            job.n_proposal = result.proposed_cases
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
