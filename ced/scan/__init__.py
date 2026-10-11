"""扫描任务层：把同步的差分扫描包成可启动/可观测/可中止的任务。

不含领域知识，也不做判定 —— 判定只在 ``ced.classify.upgradability.judge``。
"""

from .job import (ABORTED, DONE, FAILED, FINAL, PENDING, RUNNING, JobAborted,
                  JobRegistry, ScanJob)
from .runner import db_path, run_job, start

__all__ = ["ABORTED", "DONE", "FAILED", "FINAL", "PENDING", "RUNNING",
           "JobAborted", "JobRegistry", "ScanJob", "db_path", "run_job",
           "start"]
