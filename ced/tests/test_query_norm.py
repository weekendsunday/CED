"""查询串解析（query-norm）领域的单元测试。

覆盖的都是**消费者可见的行为**：
  * 每个解析策略开关在它自己的语料上确实产生预期差异
  * 良性轴零分歧（假阳性防线，最重要的一条）
  * 消融实验能机械地定位"分歧由哪类承载者 / 哪处解释差异"承载
  * 量化口径：同一段查询串被两侧读成不同的参数取值
  * 参数级最小化：长度不增、分歧仍在
  * 端到端 PoC：扫描该领域产出的脚本真能跑通并断言 PASS
  * CLI：`python -m ced scan --domain query-norm` 能跑出安全级发现并落 PoC
  * 已知案例反验证：`query-*` 案例全部 PASS
"""
from __future__ import annotations

import itertools
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# import 即 @register —— 让 Evaluator / scan / regression 都能找到本领域
from ced.adapters import query_norm  # noqa: F401,E402
from ced.adapters.query_norm import QueryNormAdapter
from ced import regression
from ced.contracts import ImplSpec
from ced.differ.comparator import compare, diff_keys, diverges
from ced.impls import query_reference
from ced.impls.query_norm import parse_query
from ced.mutate import query_axes
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.scenario import build_pocs, write_pocs

ADAPTER = QueryNormAdapter()


def _evaluator(*impl_ids: str) -> Evaluator:
    """把若干参照实现包成本地观测源。"""
    return Evaluator([
        ImplSpec(impl_id=i, name=i, runner="local", policy=i, domain="query-norm")
        for i in impl_ids
    ])


def _fields(payload: bytes, impl_id: str) -> dict:
    return parse_query(payload, query_reference.policy_of(impl_id)).to_fields()


#: (查询串, left, right, 期望差异字段集, 左 norm_query, 右 norm_query)
#: 每一条都对应"某个解析策略开关"这一处真实差异。
CASES: tuple[tuple[bytes, str, str, frozenset, str, str], ...] = (
    (b"a=1&a=2", "query-gateway", "query-last-wins",
     frozenset({"norm_query", "dup_kept"}), "a=1", "a=2"),
    (b"a=1&a=2", "query-gateway", "query-all-wins",
     frozenset({"norm_query", "keys", "param_count", "dup_kept"}),
     "a=1", "a=1&a=2"),
    (b"a=1;b=2", "query-gateway", "query-semicolon-sep",
     frozenset({"norm_query", "keys", "param_count"}), "a=1;b=2", "a=1&b=2"),
    (b"a=%26b%3D1", "query-gateway", "query-no-decode",
     frozenset({"norm_query"}), "a=&b=1", "a=%26b%3D1"),
    (b"a=%2526", "query-gateway", "query-double-decode",
     frozenset({"norm_query"}), "a=%26", "a=&"),
    (b"a=1+2", "query-gateway", "query-plus-literal",
     frozenset({"norm_query"}), "a=1 2", "a=1+2"),
    (b"a=&b=1", "query-gateway", "query-drop-empty",
     frozenset({"norm_query", "keys", "param_count"}), "a=&b=1", "b=1"),
    (b"a[]=1", "query-gateway", "query-bracket-strip",
     frozenset({"norm_query", "keys"}), "a[]=1", "a=1"),
    (b"Name=x", "query-gateway", "query-case-insensitive",
     frozenset({"norm_query", "keys"}), "Name=x", "name=x"),
    (b"b=2&a=1", "query-gateway", "query-sorted",
     frozenset({"norm_query", "keys"}), "b=2&a=1", "a=1&b=2"),
)


class TestStrategyKnobs(unittest.TestCase):
    """1. 每个策略开关在它自己的语料上都产生预期差异。"""

    def test_each_knob_produces_expected_divergence(self):
        for payload, left, right, expected, lq, rq in CASES:
            with self.subTest(payload=payload, left=left, right=right):
                lf, rf = _fields(payload, left), _fields(payload, right)
                self.assertEqual(lf["norm_query"], lq)
                self.assertEqual(rf["norm_query"], rq)
                diffs = {k for k in ADAPTER.compare_keys if lf[k] != rf[k]}
                self.assertEqual(diffs, set(expected))


class TestBenignAxis(unittest.TestCase):
    """2. 良性轴零分歧：这是假阳性的第一道防线。"""

    def test_no_pair_diverges_on_benign_payloads(self):
        ids = list(query_reference.QUERY_REFERENCES)
        for left, right in itertools.combinations(ids, 2):
            for payload in query_axes.case_benign():
                with self.subTest(payload=payload, pair=(left, right)):
                    lf, rf = _fields(payload, left), _fields(payload, right)
                    diffs = [k for k in ADAPTER.compare_keys if lf[k] != rf[k]]
                    self.assertEqual(diffs, [], f"{payload!r} 在 {left}/{right} 上分歧")


class TestAblation(unittest.TestCase):
    """3. 消融实验真的能定位承载者。"""

    def test_drop_duplicates_ablates_the_carrier(self):
        payload = b"a=1&a=2"
        left, right = "query-gateway", "query-last-wins"
        evaluator = _evaluator(left, right)

        div = compare("x", "query_duplicate", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)

        labels = ADAPTER.ablate(div, evaluator)
        target_label = next(label for label, _ in query_axes.ABLATIONS
                            if "重复参数" in label)
        self.assertIn(target_label, labels)

        # 把重复参数抹掉后，两侧就都没有可分歧的东西了 —— 分歧必须消失
        transform = dict(query_axes.ABLATIONS)[target_label]
        candidate = transform(payload)
        self.assertNotEqual(candidate, payload)
        self.assertFalse(diverges(evaluator(left, candidate),
                                  evaluator(right, candidate),
                                  ADAPTER.compare_keys))

    def test_semicolon_to_amp_ablates_separator_axis(self):
        payload = b"a=1;b=2"
        left, right = "query-gateway", "query-semicolon-sep"
        evaluator = _evaluator(left, right)
        div = compare("y", "query_separators", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)
        labels = ADAPTER.ablate(div, evaluator)
        self.assertIn("把 `;` 换成正 `&`", labels)


class TestQuantify(unittest.TestCase):
    """4. 量化：同一段查询串被两侧读成不同取值。"""

    def test_duplicate_values_differ(self):
        quant = ADAPTER.quantify(b"a=1&a=2", "query-gateway", "query-last-wins")
        self.assertIsNotNone(quant)
        front, back = quant.numbers
        self.assertNotEqual(front, back)
        self.assertEqual((front, back), ("a=1", "a=2"))
        self.assertIn("a", quant.describe)

    def test_unknown_impl_quantifies_none(self):
        self.assertIsNone(
            ADAPTER.quantify(b"a=1&a=2", "query-gateway", "not-a-real-impl"))


class TestMinimize(unittest.TestCase):
    """5. 参数级最小化：长度不增、分歧仍在。"""

    def test_minimize_keeps_divergence_and_does_not_grow(self):
        payload = b"a=1&b=2&c=3&a=9"
        left, right = "query-gateway", "query-last-wins"
        evaluator = _evaluator(left, right)

        def keeps_divergence(candidate: bytes) -> bool:
            return bool(diff_keys(evaluator(left, candidate),
                                  evaluator(right, candidate),
                                  ADAPTER.compare_keys))

        self.assertTrue(keeps_divergence(payload))
        minimized = ADAPTER.minimize(payload, keeps_divergence)
        self.assertLessEqual(len(minimized), len(payload))
        self.assertTrue(keeps_divergence(minimized),
                        f"最小化后分歧丢失：{minimized!r}")


class TestPoc(unittest.TestCase):
    """6. 端到端 PoC：该领域的脚本必须真能跑通并断言 PASS。"""

    @classmethod
    def setUpClass(cls) -> None:
        impls = list(query_reference.QUERY_REFERENCES)
        cls.evaluator = _evaluator(*impls)
        cls.result = scan(ADAPTER, cls.evaluator, mode="axis", limit=40)
        cls.pocs = build_pocs(cls.result)

    def test_pocs_are_all_security(self):
        self.assertTrue(self.pocs, "query-norm 领域应当产出 security 级发现")
        self.assertTrue(all(p.level == "security" for p in self.pocs))
        security_ids = {f.case_id for f in self.result.security}
        for poc in self.pocs:
            self.assertIn(poc.case_id, security_ids)

    def test_generated_script_runs_and_asserts(self):
        results_dir = ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(dir=results_dir,
                                              ignore_cleanup_errors=True)
        self.addCleanup(scratch.cleanup)
        paths = write_pocs(self.result, scratch.name)
        self.assertTrue(paths)

        target = paths[0]
        self.assertTrue(target.is_file())
        proc = subprocess.run([sys.executable, str(target)], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)


class TestCli(unittest.TestCase):
    """7. CLI：干净进程里 `python -m ced scan --domain query-norm` 能跑出安全级发现 + PoC。

    注册由 main 在 ``ced/adapters/__init__.py`` 集成时统一加；本测试先 bootstrap
    导入本领域模块（等价于集成后的状态），从而验证领域端到端可用。
    """

    def test_cli_scan_produces_security_and_poc(self):
        results_dir = ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(dir=results_dir,
                                              ignore_cleanup_errors=True)
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name) / "report.md"
        poc_dir = Path(scratch.name) / "pocs"

        bootstrap = (
            "import sys;"
            "import ced.adapters.query_norm;"          # 等价于集成后的注册
            "from ced.cli import main;"
            "sys.exit(main(['scan','--domain','query-norm','--mode','axis',"
            "'--limit','40','--out'," + repr(str(out)) + ","
            "'--poc-dir'," + repr(str(poc_dir)) + "]))"
        )
        # 子进程是 ced.cli.main —— 它会把 stdout 固定成 UTF-8（见 cli.main 的 reconfigure），
        # 所以父进程必须按 UTF-8 解码。用平台默认编码（Windows 上是 GBK）去读会在读线程里
        # UnicodeDecodeError，proc.stdout 直接变 None，真实错误被 "None + str" 的 TypeError 盖掉。
        # stdout/stderr 兜底成空串也是这个道理：让失败信息看得见，别再被 TypeError 吃掉。
        proc = subprocess.run([sys.executable, "-c", bootstrap], cwd=str(ROOT),
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0,
                         (proc.stdout or "") + (proc.stderr or ""))
        self.assertRegex(proc.stdout, r"安全级 [1-9]")
        self.assertTrue(out.is_file())
        self.assertIn("query-norm", out.read_text(encoding="utf-8"))
        scripts = list(poc_dir.glob("poc_*.py"))
        self.assertTrue(scripts, "CLI 未产出任何 PoC 脚本")

        run = subprocess.run([sys.executable, str(scripts[0])], cwd=str(ROOT),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("PASS", run.stdout)


class TestRegression(unittest.TestCase):
    """8. 反验证：`query-*` 已知案例全部 PASS。"""

    def test_query_cases_all_pass(self):
        outcomes = regression.run()
        query_cases = [o for o in outcomes if o.name.startswith("query-")]
        self.assertGreaterEqual(len(query_cases), 8)
        for outcome in query_cases:
            self.assertTrue(outcome.passed, f"{outcome.name}: {outcome.detail}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
