"""攻击场景 / PoC / 链路拓扑的端到端测试。

覆盖的都是"消费者可见的行为"：
  * **不夸大**：`unknown` / `compatibility` 级发现不许生成 PoC
  * 生成的脚本必须**语法合法**且**真的能跑通**（写盘 → 子进程执行 → 断言 PASS）
  * 字节归属必须与链式模型一致（转发 / 消费 / 夹带三个数字对得上）
  * PoC 落库幂等（重跑不累积重复行）
  * 无 Docker 的替身链路拓扑能被加载，且链路方向声明正确
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.adapters import get as get_adapter
from ced.adapters.http1_framing import Http1FramingAdapter
from ced.contracts import (LEVEL_COMPAT, LEVEL_UNKNOWN, Divergence, Finding,
                           Observation, Verdict)
from ced.orchestrate.topology import demo, load
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.scenario import build_poc, build_pocs, templates, write_pocs
from ced import store

ADAPTER = Http1FramingAdapter()
TOPO = demo()
EVAL = Evaluator(TOPO.impls)

#: 在仓库里跑测试脚本 —— 生成的 PoC 靠"往上找 ced/__init__.py"定位仓库根，
#: 所以必须放在仓库内才能验证这条路径真的成立。
SCRATCH = ROOT / "results" / "_scenario_test"


def _synthetic_finding(level: str) -> Finding:
    payload = b"POST / HTTP/1.1\r\nContent-Length: 03\r\n\r\nabc"
    left = Observation(impl_id="ref-cl-first", ok=True, fields={"consumed": 0})
    right = Observation(impl_id="ref-lenient-cl", ok=True, fields={"consumed": 3})
    divergence = Divergence(case_id="deadbeef", axis="cl_value", payload=payload,
                            left=left, right=right, diffs=[])
    return Finding(divergence=divergence,
                   verdict=Verdict(level=level, kind="framing_boundary"),
                   original_len=len(payload))


class TestNoOverstatement(unittest.TestCase):

    def test_non_security_findings_get_no_poc(self):
        """判定器没升级的分歧，这里不许替它升级 —— 这是不夸大的第一道闸。"""
        for level in (LEVEL_UNKNOWN, LEVEL_COMPAT):
            self.assertIsNone(build_poc(_synthetic_finding(level)), level)

    def test_scan_pocs_are_all_security(self):
        result = scan(ADAPTER, EVAL, mode="axis", limit=20, do_minimize=False)
        pocs = build_pocs(result)
        self.assertTrue(pocs, "内置语料应当产出 security 级发现")
        security_ids = {f.case_id for f in result.security}
        for poc in pocs:
            self.assertEqual(poc.level, "security")
            self.assertIn(poc.case_id, security_ids)


class TestPocContent(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = scan(ADAPTER, EVAL, mode="axis", limit=60, do_minimize=True)
        cls.pocs = build_pocs(cls.result)
        cls.poc = cls.pocs[0]

    def test_quantification_matches_the_domain_model(self):
        """PoC 里的量化必须与该领域的量化口径算出来的一致，不能是估的。"""
        adapter = get_adapter("http1-framing")
        quant = adapter.quantify(self.poc.request, self.poc.left, self.poc.right)
        self.assertIsNotNone(quant)
        self.assertEqual(self.poc.quant.label, quant.label)
        self.assertEqual(self.poc.quant.numbers, quant.numbers)
        self.assertTrue(self.poc.verified)

    def test_scenario_is_classified_and_steps_carry_numbers(self):
        self.assertIn(self.poc.scenario, templates.SCENARIOS)
        self.assertTrue(self.poc.steps)
        joined = " ".join(self.poc.steps)
        for key, value in self.poc.quant.values.items():
            if key in ("front", "back"):
                continue
            self.assertIn(str(value), joined, f"步骤里缺 {key}={value}")
        self.assertIn(self.poc.fix, joined)

    def test_script_is_valid_python_and_embeds_the_sample(self):
        compile(self.poc.script, self.poc.file_name, "exec")
        self.assertIn(self.poc.case_id, self.poc.script)
        self.assertIn(self.poc.request_b64, self.poc.script)
        self.assertIn("--i-am-authorized", self.poc.script,
                      "脚本必须带授权门禁")

    def test_generated_script_actually_runs_and_asserts(self):
        """最强的一条：把脚本写到仓库里，用子进程真跑，必须退出 0 且断言 PASS。"""
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, True)
        paths = write_pocs(self.result, SCRATCH)
        self.assertTrue(paths)

        target = SCRATCH / self.poc.file_name
        self.assertTrue(target.is_file())
        proc = subprocess.run([sys.executable, str(target)], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)
        self.assertIn("被夹带", proc.stdout)

    def test_generated_script_refuses_unauthorized_send(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, True)
        write_pocs(self.result, SCRATCH)
        target = SCRATCH / self.poc.file_name
        proc = subprocess.run([sys.executable, str(target), "--send", "127.0.0.1:9"],
                              cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("拒绝发送", proc.stdout)

    def test_write_pocs_is_idempotent(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, True)
        first = write_pocs(self.result, SCRATCH)
        second = write_pocs(self.result, SCRATCH)
        self.assertEqual(len(first), len(second))
        self.assertEqual(sorted(p.name for p in first), sorted(p.name for p in second))


class TestPocPersistence(unittest.TestCase):

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self._dir.name) / "poc.db"

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_round_trip_and_idempotence(self):
        result = scan(ADAPTER, EVAL, mode="axis", limit=20, do_minimize=False)
        pocs = build_pocs(result)
        conn = store.connect(self.path)
        try:
            store.save_scan(conn, result, ADAPTER.name)
            self.assertEqual(store.save_pocs(conn, pocs), len(pocs))
            self.assertEqual(store.save_pocs(conn, pocs), len(pocs))  # 重跑不累积

            rows = store.list_pocs(conn)
            self.assertEqual(len(rows), len(pocs))
            one = store.load_poc(conn, pocs[0].case_id)
            self.assertIsNotNone(one)
            self.assertEqual(one["scenario"], pocs[0].scenario)
            self.assertTrue(one["verified"])
            self.assertTrue(one["steps"], "步骤必须落库，报告才能复现")
            self.assertIsNone(store.load_poc(conn, "nope"))
        finally:
            conn.close()


class TestTopologies(unittest.TestCase):

    def test_standin_front_topology_is_a_real_chain(self):
        """无 Docker 的替身链路：必须先把自己声明成 chain，且指向探针控制口。"""
        topology = load(ROOT / "ced" / "topologies" / "standin-front.json")
        self.assertEqual(topology.domain, "http1-framing")
        self.assertEqual(topology.chain, ("standin-front", "ref-cl-first"))
        front = next(s for s in topology.impls if s.impl_id == "standin-front")
        self.assertEqual(front.runner, "chain")
        self.assertTrue(front.endpoint and front.probe_api)
        self.assertTrue(any(s.runner == "local" for s in topology.impls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
