"""指标卡片与交叉矩阵热力图：纯计算 + 控制台新端点。

覆盖的都是"消费者可见的行为"：
  * ``scan_metrics`` 的每个比率在手工构造的结果上逐个对得上
  * 空结果不除零，且各比率的"空"约定各不相同（0 / 1 / None）
  * 热力图对称、对角线为空、同格多条发现取最严重级别
  * 真跑一次扫描后矩阵覆盖全部 9 个实现（9×9）
  * 两个新端点在真 HTTP 上返回 200，未知任务号 404
  * 结果自证：``result_payload`` 带上 impls / 实测标记 / 缓存账，
    顶部三行要用的"最严重档位"与指标口径一致
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

from ced.adapters import get as get_adapter
from ced.contracts import (LEVEL_COMPAT, LEVEL_SECURITY, LEVEL_UNKNOWN,
                           Divergence, Finding, Observation, Verdict)
from ced.metrics import matrix_heatmap, scan_metrics
from ced.orchestrate.topology import demo
from ced.pipeline import ScanResult, scan
from ced.probe import Evaluator
from ced.web.server import _bind


def _finding(case_id: str, level: str, kind: str, left: str, right: str, *,
             controllable: bool = False, original_len: int = 100,
             minimized_len: int = 0) -> Finding:
    """手工造一条发现 —— 只填指标用得到的字段。"""
    div = Divergence(case_id=case_id, axis="test",
                     payload=b"A" * 8,
                     left=Observation(impl_id=left),
                     right=Observation(impl_id=right))
    verdict = Verdict(level=level, kind=kind, controllable=controllable)
    return Finding(divergence=div, verdict=verdict,
                   minimized=(b"B" * minimized_len if minimized_len else None),
                   original_len=original_len, minimized_len=minimized_len)


def _result(findings: list[Finding], *, total_cases: int = 12,
            jobs: int = 3, impl_ids: list[str] | None = None) -> ScanResult:
    return ScanResult(total_cases=total_cases, jobs=jobs,
                      divergences=[f.divergence for f in findings],
                      findings=findings,
                      impl_ids=impl_ids or [])


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


class TestScanMetrics(unittest.TestCase):

    def test_every_ratio_on_a_handmade_result(self):
        findings = [
            # 安全级 + 可控 + 被最小化
            _finding("c1", LEVEL_SECURITY, "framing_boundary", "a", "b",
                     controllable=True, original_len=100, minimized_len=40),
            # 安全级 + 不可控；case_id 与上一条重复（唯一化压缩比因此 < 1）
            _finding("c1", LEVEL_SECURITY, "chunk", "a", "c",
                     controllable=False, original_len=100, minimized_len=0),
            # 未知级别，不参与安全/可控统计，也不参与最小化压缩比
            _finding("c3", LEVEL_UNKNOWN, "syntax", "b", "c",
                     controllable=False, original_len=100, minimized_len=0),
        ]
        m = scan_metrics(_result(findings, total_cases=12, jobs=4), elapsed=6.0)

        self.assertEqual(set(m), {
            "total_cases", "jobs", "divergences", "by_level", "by_severity",
            "security", "severity", "security_share", "controllable_rate",
            "unique_case_ratio", "minimize_ratio", "minimized_count", "elapsed",
            "avg_seconds_per_case"})
        self.assertEqual(m["total_cases"], 12)
        self.assertEqual(m["jobs"], 4)
        self.assertEqual(m["divergences"], 3)
        self.assertEqual(m["by_level"],
                         {"security": 2, "unknown": 1, "compatibility": 0})
        self.assertEqual(m["security"], 2)
        self.assertEqual(m["security_share"], round(2 / 3, 4))
        self.assertEqual(m["controllable_rate"], 0.5)
        self.assertEqual(m["unique_case_ratio"], round(2 / 3, 4),
                         "3 条分歧只有 2 个不同 case_id")
        self.assertEqual(m["minimize_ratio"], 0.4,
                         "只统计 minimized_len>0 的那条：40/100")
        self.assertEqual(m["minimized_count"], 1)
        self.assertEqual(m["elapsed"], 6.0, "elapsed 原样透传")
        self.assertEqual(m["avg_seconds_per_case"], 0.5)

    def test_empty_result_never_divides_by_zero(self):
        m = scan_metrics(ScanResult(), elapsed=None)
        self.assertEqual(m["divergences"], 0)
        self.assertEqual(m["by_level"],
                         {"security": 0, "unknown": 0, "compatibility": 0})
        self.assertEqual(m["security"], 0)
        self.assertEqual(m["security_share"], 0.0)
        self.assertEqual(m["controllable_rate"], 0.0)
        self.assertEqual(m["unique_case_ratio"], 1.0)
        self.assertEqual(m["minimize_ratio"], 1.0)
        self.assertEqual(m["minimized_count"], 0)
        self.assertIsNone(m["elapsed"])
        self.assertIsNone(m["avg_seconds_per_case"])

        # 有耗时但没有用例：仍然不能除零
        m2 = scan_metrics(ScanResult(total_cases=0), elapsed=1.5)
        self.assertIsNone(m2["avg_seconds_per_case"])
        self.assertEqual(m2["elapsed"], 1.5)

    def test_all_floats_are_rounded_to_four_places(self):
        findings = [_finding("c1", LEVEL_SECURITY, "chunk", "a", "b",
                             controllable=True, original_len=3, minimized_len=1)]
        m = scan_metrics(_result(findings, total_cases=7), elapsed=1.0)
        self.assertEqual(m["security_share"], 1.0)
        self.assertEqual(m["controllable_rate"], 1.0)
        self.assertEqual(m["minimize_ratio"], round(1 / 3, 4))
        self.assertEqual(m["avg_seconds_per_case"], round(1 / 7, 4))
        self.assertEqual(m["minimize_ratio"], 0.3333)
        self.assertEqual(m["avg_seconds_per_case"], 0.1429)


class TestMatrixHeatmap(unittest.TestCase):

    def setUp(self):
        self.impls = ["a", "b", "c"]
        self.result = _result([
            _finding("k1", LEVEL_UNKNOWN, "syntax", "a", "b"),
            _finding("k2", LEVEL_SECURITY, "framing_boundary", "a", "b"),
            _finding("k3", LEVEL_COMPAT, "status_only", "b", "c"),
        ])

    def test_symmetric_diagonal_empty_and_worst_level_wins(self):
        d = matrix_heatmap(self.result, self.impls)
        self.assertEqual(d["impls"], self.impls)
        cells = d["cells"]

        for i in range(len(self.impls)):
            for j in range(len(self.impls)):
                self.assertEqual(cells[i][j]["count"], cells[j][i]["count"],
                                 f"({i},{j}) 与 ({j},{i}) 必须对称")
                if i == j:
                    self.assertEqual(cells[i][j]["count"], 0)
                    self.assertIsNone(cells[i][j]["level"])
                    self.assertEqual(cells[i][j]["kind"], "")

        ab = cells[0][1]
        self.assertEqual(ab["count"], 2)
        self.assertEqual(ab["security"], 1)
        self.assertEqual(ab["level"], LEVEL_SECURITY, "同格取最严重级别")
        self.assertEqual(ab["kind"], "syntax", "保留第一个非空 kind")
        self.assertEqual(ab["case_ids"], ["k1", "k2"])

        self.assertEqual(cells[1][2]["level"], LEVEL_COMPAT)
        self.assertEqual(cells[1][2]["case_ids"], ["k3"])
        self.assertEqual(cells[0][2]["count"], 0)
        self.assertEqual(d["max"], 2)
        self.assertGreaterEqual(d["max"], 1)

    def test_max_is_at_least_one_even_without_findings(self):
        d = matrix_heatmap(_result([]), self.impls)
        self.assertEqual(d["max"], 1)
        self.assertEqual(len(d["cells"]), 3)
        self.assertTrue(all(c["count"] == 0 and c["level"] is None
                            for row in d["cells"] for c in row))

    def test_case_ids_capped_at_five(self):
        findings = [_finding(f"k{i}", LEVEL_SECURITY, "chunk", "a", "b")
                    for i in range(7)]
        d = matrix_heatmap(_result(findings), self.impls)
        self.assertEqual(d["cells"][0][1]["count"], 7)
        self.assertEqual(len(d["cells"][0][1]["case_ids"]), 5)

    def test_unknown_impls_are_ignored(self):
        d = matrix_heatmap(_result([_finding("k1", LEVEL_SECURITY, "chunk",
                                             "a", "zzz")]), self.impls)
        self.assertTrue(all(c["count"] == 0 for row in d["cells"] for c in row))


class TestRealScanMatrix(unittest.TestCase):

    def test_axis_scan_covers_all_nine_impls(self):
        adapter = get_adapter("http1-framing")
        evaluator = Evaluator(demo().impls)
        result = scan(adapter, evaluator, mode="axis", limit=20,
                      do_minimize=False)
        d = matrix_heatmap(result, result.impl_ids)
        self.assertEqual(len(d["impls"]), 9)
        self.assertEqual(len(d["cells"]), 9)
        self.assertTrue(all(len(row) == 9 for row in d["cells"]))
        self.assertGreaterEqual(d["max"], 1)
        metrics = scan_metrics(result, elapsed=1.0)
        self.assertEqual(metrics["divergences"], len(result.divergences))


class TestResultSelfEvidence(unittest.TestCase):
    """「产品实测」结果页顶部三行与每条发现的实测 / 推演标记，字段得齐。"""

    def _scan(self, limit: int = 20):
        adapter = get_adapter("http1-framing")
        evaluator = Evaluator(demo().impls)
        return scan(adapter, evaluator, mode="axis", limit=limit,
                    do_minimize=False)

    def test_payload_has_self_evidence_fields(self):
        from ced.report.renderer import result_payload

        result = self._scan()
        payload = result_payload(result)
        self.assertIn("impls", payload)
        self.assertIn("measured_impls", payload)
        self.assertIn("has_product", payload)
        self.assertIn("cache", payload)
        self.assertEqual(sorted(payload["cache"]), ["hits", "trips"])
        # 只有内置参照实现：没有实测、没有真实产品参与
        self.assertTrue(payload["impls"])
        self.assertFalse(payload["has_product"])
        self.assertEqual(payload["measured_impls"], [])
        for item in payload["findings"]:
            self.assertFalse(item["measured"])
        # 缓存确实被用上了（同一对「实现 + 字节」在一次运行里会重复求值）
        self.assertGreater(payload["cache"]["hits"], 0)

    def test_worst_severity_matches_the_metrics_caliber(self):
        """结果页第三行报的"最严重档位"与指标口径同源。"""
        metrics = scan_metrics(self._scan(), elapsed=1.0)
        self.assertIn(metrics["severity"],
                      ("critical", "high", "medium", "low", "info", ""))


class TestMetricsApi(unittest.TestCase):
    """真 HTTP：起服务 → 起扫描 → 等 done → 打两个新端点。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._httpd = _bind("127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls._httpd.server_address[1]}"
        cls._thread = threading.Thread(target=cls._httpd.serve_forever,
                                       daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._old_db = os.environ.get("CED_DB")
        os.environ["CED_DB"] = str(Path(self._dir.name) / "metrics.db")

    def tearDown(self) -> None:
        if self._old_db is None:
            os.environ.pop("CED_DB", None)
        else:
            os.environ["CED_DB"] = self._old_db
        self._dir.cleanup()

    def _run_scan(self) -> str:
        status, started = _post(self.base, "/api/scan/start",
                                {"mode": "axis", "limit": 20, "seed": 42})
        self.assertEqual(status, 200, started)
        job_id = started["job_id"]

        request = urllib.request.Request(
            f"{self.base}/api/scan/events?job_id={job_id}")
        deadline = time.time() + 60
        with urllib.request.urlopen(request, timeout=60) as stream:
            while time.time() < deadline:
                line = stream.readline()
                if not line:
                    break
                if not line.startswith(b"data:"):
                    continue
                event = json.loads(line[5:].decode("utf-8"))
                if event.get("type") in ("done", "error"):
                    self.assertEqual(event["type"], "done", event)
                    break
        return job_id

    def test_metrics_endpoint_shape(self):
        job_id = self._run_scan()
        status, payload = _get(
            self.base, f"/api/scan/metrics?job_id={job_id}")
        self.assertEqual(status, 200, payload)
        m = payload["metrics"]
        self.assertEqual(set(m), {
            "total_cases", "jobs", "divergences", "by_level", "security",
            "security_share", "controllable_rate", "unique_case_ratio",
            "minimize_ratio", "minimized_count", "elapsed",
            "avg_seconds_per_case"})
        self.assertEqual(m["security"], m["by_level"]["security"])
        self.assertGreater(m["security"], 0, "axis 扫描应至少有一条安全级")
        self.assertLessEqual(m["minimize_ratio"], 1.0)
        self.assertIsNotNone(m["avg_seconds_per_case"])

    def test_heatmap_endpoint_shape(self):
        job_id = self._run_scan()
        status, payload = _get(
            self.base, f"/api/scan/heatmap?job_id={job_id}")
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["impls"]), 9)
        self.assertEqual(len(payload["cells"]), 9)
        self.assertEqual(len(payload["cells"][0]), 9)
        self.assertGreaterEqual(payload["max"], 1)
        for i in range(9):
            self.assertEqual(payload["cells"][i][i]["count"], 0)
            self.assertIsNone(payload["cells"][i][i]["level"])

    def test_unknown_job_id_is_404_on_both_endpoints(self):
        for path in ("/api/scan/metrics", "/api/scan/heatmap"):
            status, payload = _get(self.base, f"{path}?job_id=nope")
            self.assertEqual(status, 404, f"{path} 对未知任务应 404")
            self.assertIn("error", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
