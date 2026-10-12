"""扫描任务：状态机 + 内存注册表 + 事件流。

``pipeline.scan`` 是同步的、一次跑完的；控制台需要的是"能启动、能看进度、能中止、
能回看历史"的任务。这一层只做任务生命周期，**不含任何领域知识，也不做任何判定**。
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any

#: 任务状态
PENDING = "pending"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
ABORTED = "aborted"
#: 终态 —— 进入终态后 SSE 流关闭
FINAL = (DONE, FAILED, ABORTED)


class JobAborted(RuntimeError):
    """由进度回调抛出，用来中止一次扫描。

    之所以用异常而不是返回值：``pipeline.scan`` 的循环不需要为此加分支，
    而且中止时**已经跑完的部分**通过进度回调的活对象留了下来（见 ScanJob.result）。
    """


class ScanJob:
    """一个扫描任务的全部状态。

    线程模型：runner 在后台线程写，HTTP 处理线程读（SSE）。所有可变状态的读写
    都在 ``_lock`` 下，等待新事件走 ``_cond``。
    """

    def __init__(self, job_id: str, *, domain: str = "http1-framing",
                 mode: str = "axis", limit: int | None = None, seed: int = 42,
                 topology: str = "", link: dict | None = None) -> None:
        self.job_id = job_id
        self.domain = domain
        self.mode = mode
        self.limit = limit
        self.seed = seed
        self.topology = topology
        #: 界面上那份「连线设置」（接我的产品时的三条信息）。为空 = 只跑内置基准。
        self.link = link

        self.state = PENDING
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self.error: str | None = None

        # 进度
        self.stage = "pending"
        self.stage_detail = ""
        self.done_jobs = 0
        self.total_jobs = 0
        self.total_cases = 0
        self.n_divergence = 0
        self.n_security = 0

        #: 事件流（供 SSE 从任意游标重放）。上限见 _MAX_EVENTS。
        self.events: list[dict] = []
        #: 一次扫描的 ScanResult（活对象）。中止时这里是**已完成的那部分**。
        self.result: Any = None
        #: 收到中止请求后置位；进度回调据此抛出 JobAborted。
        self.aborting = False

        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

    # ------------------------------------------------------------------ 事件流

    _MAX_EVENTS = 500

    def emit(self, event: dict) -> None:
        """追加一条事件并唤醒所有 SSE 等待者。"""
        event = {**event, "ts": round(time.time() - self.created, 3)}
        with self._cond:
            self.events.append(event)
            if len(self.events) > self._MAX_EVENTS:
                # 只丢最老的日志类事件，进度/终态事件保持可重放
                keep = [e for e in self.events if e.get("type") != "stage"]
                self.events = keep[-self._MAX_EVENTS:]
            self._cond.notify_all()

    def drain(self, cursor: int, timeout: float = 20.0) -> list[dict]:
        """取 ``cursor`` 之后的事件；没有新事件时最多阻塞 ``timeout`` 秒。

        这是 SSE 的心跳：浏览器不需要我们主动 ping，只要连接上有字节流动即可。
        """
        with self._cond:
            if cursor >= len(self.events) and self.state not in FINAL:
                self._cond.wait(timeout)
            return list(self.events[cursor:])

    @property
    def stream_length(self) -> int:
        with self._lock:
            return len(self.events)

    @property
    def closed(self) -> bool:
        return self.state in FINAL

    def finish(self, state: str, *, error: str | None = None) -> None:
        with self._cond:
            self.state = state
            self.error = error or self.error
            self.finished = time.time()
            self._cond.notify_all()

    def abort_requested(self) -> bool:
        with self._lock:
            self.aborting = True
            return self.state == RUNNING

    # ------------------------------------------------------------------ 序列化

    def row(self) -> dict:
        """与 ``store.scan_job`` 表列名一致的扁平行。"""
        return {
            "job_id": self.job_id, "domain": self.domain, "mode": self.mode,
            "limit_n": self.limit, "seed": self.seed,
            "state": self.state, "created": self.created, "started": self.started,
            "finished": self.finished, "total_cases": self.total_cases,
            "total_jobs": self.total_jobs, "n_divergence": self.n_divergence,
            "n_security": self.n_security, "error": self.error,
        }

    def brief(self) -> dict:
        """给前端的任务摘要。``live`` 表示结果还在内存里、可以点开。"""
        data = self.row()
        data["live"] = True
        data["stage"] = self.stage
        data["stage_detail"] = self.stage_detail
        data["done_jobs"] = self.done_jobs
        data["elapsed"] = round((self.finished or time.time())
                                - (self.started or self.created), 3)
        data["link"] = self.link or {}
        return data


class JobRegistry:
    """内存任务表。超出容量时按"最老且已终态"淘汰，**绝不淘汰在跑的**。"""

    def __init__(self, max_jobs: int = 40) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._max = max_jobs

    def create(self, **kwargs) -> ScanJob:
        job = ScanJob(uuid.uuid4().hex[:8], **kwargs)
        with self._lock:
            self._jobs[job.job_id] = job
            self._evict_locked()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def all(self) -> list[ScanJob]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created, reverse=True)
        return jobs

    def abort(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        job.abort_requested()
        return True

    def _evict_locked(self) -> None:
        if len(self._jobs) <= self._max:
            return
        candidates = sorted((j for j in self._jobs.values() if j.closed),
                            key=lambda j: j.created)
        for job in candidates[:len(self._jobs) - self._max]:
            self._jobs.pop(job.job_id, None)
