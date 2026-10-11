"""扫描控制台端到端测试：任务状态机 + 事件流 + HTTP 接口。

覆盖的都是"消费者可见的行为"：
  * 任务跑完状态为 done，结果能被 /api/scan/result 取回
  * SSE 事件流能读到 progress 与 done，且流在 done 之后结束
  * **中止的任务保留已完成的部分**结果（不是全丢）
  * 未配置模型时 /api/assist/status 如实报"不可用"，且扫描路径完全不受影响
  * 事件表只会淘汰日志类事件，进度与终态事件始终可重放
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import store
from ced.report.renderer import result_payload
from ced.scan import runner
from ced.scan.job import ABORTED, DONE, JobRegistry
from ced.web.server import REGISTRY, Handler, _bind


def _post(base: str, path: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(base + path, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class _TempDb(unittest.TestCase):
    """把任务库隔离到临时目录 —— 单测不许依赖仓库里的数据文件。"""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = os.environ.get("CED_DB")
        os.environ["CED_DB"] = str(Path(self._dir.name) / "console.db")

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("CED_DB", None)
        else:
            os.environ["CED_DB"] = self._old_db
        self._dir.cleanup()


class TestJobLifecycle(unittest.TestCase):

    def test_event_stream_replays_from_cursor(self):
        registry = JobRegistry()
        job = registry.create(mode="axis", limit=10)
        job.emit({"type": "stage", "stage": "start", "detail": "x"})
        job.emit({"type": "progress", "done": 1, "total": 2})
        self.assertEqual(len(job.drain(0, timeout=0.01)), 2)
        self.assertEqual([e["type"] for e in job.drain(1, timeout=0.01)],
                         ["progress"])
        self.assertEqual(job.drain(2, timeout=0.01), [])

    def test_finish_closes_stream_without_waiting(self):
        registry = JobRegistry()
        job = registry.create(mode="axis")
        job.finish(DONE)
        self.assertTrue(job.closed)
        started = time.time()
        job.drain(0, timeout=5.0)          # 终态下不该阻塞
        self.assertLess(time.time() - started, 1.0)

    def test_log_events_are_trimmed_but_final_state_survives(self):
        from ced.scan.job import ScanJob

        job = ScanJob("t", mode="axis", limit=1)
        for i in range(ScanJob._MAX_EVENTS + 50):
            job.emit({"type": "stage", "stage": "log", "detail": str(i)})
        job.emit({"type": "done", "state": DONE})
        types = [e["type"] for e in job.events]
        self.assertIn("done", types)
        self.assertLessEqual(len(job.events), ScanJob._MAX_EVENTS)

    def test_registry_never_evicts_running_jobs(self):
        registry = JobRegistry(max_jobs=2)
        first = registry.create(mode="axis")
        registry.create(mode="axis")
        registry.create(mode="axis")
        self.assertEqual(len(registry.all()), 3, "在跑的任务不允许被淘汰")

        first.finish(DONE)
        registry.create(mode="axis")
        self.assertIsNone(registry.get(first.job_id), "已终态的最老任务应被淘汰")
        self.assertEqual(len(registry.all()), 3)


class TestRunner(_TempDb):

    def test_job_runs_to_done_and_persists(self):
        job = REGISTRY.create(mode="axis", limit=20, seed=42)
        runner.run_job(job)
        self.assertEqual(job.state, DONE)
        self.assertIsNotNone(job.result)
        self.assertGreater(len(job.result.divergences), 0)
        self.assertEqual(job.n_divergence, len(job.result.divergences))

        payload = result_payload(job.result)
        self.assertTrue(payload["compare_keys"], "证据视图需要 compare_keys")
        first = payload["findings"][0]
        self.assertIn("observations", first)
        self.assertEqual(set(first["observations"]),
                         set(payload["compare_keys"]))

        conn = store.connect(runner.db_path())
        try:
            row = store.load_job(conn, job.job_id)
            self.assertEqual(row["state"], DONE)
            self.assertEqual(row["n_divergence"], job.n_divergence)
        finally:
            conn.close()

    def test_abort_keeps_partial_result(self):
        job = REGISTRY.create(mode="axis", limit=300, seed=42)
        thread = threading.Thread(target=runner.run_job, args=(job,), daemon=True)
        thread.start()

        deadline = time.time() + 30
        while time.time() < deadline and job.done_jobs < 1 and not job.closed:
            time.sleep(0.002)
        job.abort_requested()
        thread.join(timeout=60)

        self.assertEqual(job.state, ABORTED)
        self.assertIsNotNone(job.result, "中止必须保留已完成的部分结果")
        self.assertLess(job.done_jobs, job.total_jobs)

    def test_unknown_domain_fails_the_job_without_raising(self):
        job = REGISTRY.create(domain="does-not-exist", mode="axis")
        runner.run_job(job)                 # 不得抛出
        self.assertEqual(job.state, "failed")
        self.assertIn("does-not-exist", job.error or "")


class TestConsoleApi(_TempDb):

    @classmethod
    def setUpClass(cls) -> None:
        cls._httpd = _bind("127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls._httpd.server_address[1]}"
        cls._thread = threading.Thread(target=cls._httpd.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def _events(self, job_id: str, limit: float = 60.0) -> list[dict]:
        request = urllib.request.Request(
            f"{self.base}/api/scan/events?job_id={job_id}")
        events: list[dict] = []
        deadline = time.time() + limit
        with urllib.request.urlopen(request, timeout=limit) as stream:
            while time.time() < deadline:
                line = stream.readline()
                if not line:
                    break
                if not line.startswith(b"data:"):
                    continue                # ": ping" 心跳
                event = json.loads(line[5:].decode("utf-8"))
                events.append(event)
                if event.get("type") in ("done", "error"):
                    break
        return events

    def test_scan_start_stream_result_and_jobs(self):
        status, started = _post(self.base, "/api/scan/start",
                                {"mode": "axis", "limit": 20, "seed": 42})
        self.assertEqual(status, 200, started)
        job_id = started["job_id"]

        events = self._events(job_id)
        kinds = [e["type"] for e in events]
        self.assertIn("stage", kinds)
        self.assertIn("progress", kinds)
        self.assertEqual(kinds[-1], "done", f"事件流必须以 done 收尾：{kinds}")
        self.assertEqual(events[-1]["state"], DONE)
        self.assertGreater(events[-1]["summary"]["security"], 0)

        status, payload = _get(self.base, f"/api/scan/result?job_id={job_id}")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["job"]["job_id"], job_id)
        findings = payload["result"]["findings"]
        self.assertTrue(findings, "结果里必须有发现")
        self.assertTrue(any(f["level"] == "security" for f in findings))

        status, jobs = _get(self.base, "/api/scan/jobs")
        self.assertEqual(status, 200)
        self.assertIn(job_id, [j["job_id"] for j in jobs["jobs"]])
        row = next(j for j in jobs["jobs"] if j["job_id"] == job_id)
        self.assertTrue(row["live"], "刚跑完的任务结果还在内存里，live 应为真")

    def test_result_of_unknown_job_is_a_readable_error(self):
        status, payload = _get(self.base, "/api/scan/result?job_id=nope")
        self.assertEqual(status, 404)
        self.assertIn("error", payload)

    def test_bad_scan_params_are_rejected_before_starting(self):
        for body in ({"domain": "nope"}, {"mode": "nope"}, {"limit": -3},
                     {"limit": 99999}):
            status, payload = _post(self.base, "/api/scan/start", body)
            self.assertEqual(status, 400, f"{body} 应被拒绝")
            self.assertIn("error", payload)

    def test_assist_status_reports_unavailable_without_model(self):
        os.environ.pop("CED_LLM_BASE_URL", None)
        os.environ.pop("CED_LLM_MODEL", None)
        status, payload = _get(self.base, "/api/assist/status")
        self.assertEqual(status, 200)
        self.assertFalse(payload["available"])
        self.assertIn("CED_LLM_BASE_URL", payload["reason"])

    def test_abort_unknown_job_is_404(self):
        status, payload = _post(self.base, "/api/scan/abort", {"job_id": "nope"})
        self.assertEqual(status, 404)
        self.assertIn("error", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
