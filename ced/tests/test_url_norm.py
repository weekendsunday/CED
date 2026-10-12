"""URL / 路径归一化领域的单元测试。

覆盖的都是**消费者可见的行为**：
  * 每个归一化策略开关在它自己的语料上确实产生预期差异
  * 良性轴零分歧（假阳性防线，最重要的一条）
  * 消融实验能机械地定位"分歧由哪类字节承载"
  * 量化口径：同一段 target 被两侧解成不同资源
  * 段级最小化：长度不增、分歧仍在
  * 端到端 PoC：扫描 URL 领域产出的脚本真能跑通并断言 PASS
  * 已知案例反验证：`url-*` 案例全部 PASS
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

from ced import regression
from ced.adapters.url_norm import UrlNormAdapter
from ced.contracts import ImplSpec
from ced.differ.comparator import compare, diff_keys
from ced.impls import url_reference
from ced.impls.path_norm import normalize_target
from ced.mutate import url_axes
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.scenario import build_pocs, write_pocs

ADAPTER = UrlNormAdapter()


def _evaluator(*impl_ids: str) -> Evaluator:
    """把若干参照实现包成本地观测源。"""
    return Evaluator([
        ImplSpec(impl_id=i, name=i, runner="local", policy=i, domain="url-norm")
        for i in impl_ids
    ])


def _fields(target: bytes, impl_id: str) -> dict:
    return normalize_target(target, url_reference.policy_of(impl_id)).to_fields()


#: (target, left, right, 期望差异字段集, 左 norm_path, 右 norm_path)
#: 每一条都对应"某个归一化策略开关"这一处真实差异。
CASES: tuple[tuple[bytes, str, str, frozenset, str, str], ...] = (
    (b"/admin/../pub", "url-gateway", "url-keep-dots",
     frozenset({"norm_path", "traversal", "segments"}), "/pub", "/admin/../pub"),
    (b"/pub/%2e%2e/admin", "url-gateway", "url-percent-strict",
     frozenset({"norm_path", "traversal", "segments", "decoded"}),
     "/admin", "/pub/%2e%2e/admin"),
    (b"/pub/%252E%252E/admin", "url-gateway", "url-decode-twice",
     frozenset({"norm_path", "traversal", "segments", "decoded"}),
     "/pub/%2E%2E/admin", "/admin"),
    (b"/admin\\..\\pub", "url-gateway", "url-backslash-sep",
     frozenset({"norm_path", "traversal"}), "/admin\\..\\pub", "/pub"),
    (b"//admin", "url-gateway", "url-collapse-slash",
     frozenset({"norm_path"}), "//admin", "/admin"),
    (b"/admin.", "url-gateway", "url-strip-trailing",
     frozenset({"norm_path"}), "/admin.", "/admin"),
    (b"/admin;x=/pub", "url-gateway", "url-strip-semicolon",
     frozenset({"norm_path"}), "/admin;x=/pub", "/admin/pub"),
    (b"/ADMIN", "url-gateway", "url-case-insensitive",
     frozenset({"norm_path"}), "/ADMIN", "/admin"),
    (b"/pub%2Fadmin", "url-gateway", "url-decode-never",
     frozenset({"norm_path", "segments", "decoded"}),
     "/pub/admin", "/pub%2Fadmin"),
    (b"/pub/%c0%ae%c0%ae%2fadmin", "url-gateway", "url-overlong-accept",
     frozenset({"accepted", "status", "norm_path", "traversal", "segments", "decoded"}),
     "/pub/%c0%ae%c0%ae%2fadmin", "/admin"),
    (b"/admin%00.jpg", "url-gateway", "url-null-truncate",
     frozenset({"norm_path"}), "/admin\x00.jpg", "/admin"),
)


class TestStrategyKnobs(unittest.TestCase):
    """1. 每个策略开关在它自己的语料上都产生预期差异。"""

    def test_each_knob_produces_expected_divergence(self):
        for target, left, right, expected, lpath, rpath in CASES:
            with self.subTest(target=target, left=left, right=right):
                lf, rf = _fields(target, left), _fields(target, right)
                self.assertEqual(lf["norm_path"], lpath)
                self.assertEqual(rf["norm_path"], rpath)
                diffs = {k for k in ADAPTER.compare_keys if lf[k] != rf[k]}
                self.assertEqual(diffs, set(expected))


class TestBenignAxis(unittest.TestCase):
    """2. 良性轴零分歧：这是假阳性的第一道防线。"""

    def test_no_pair_diverges_on_benign_targets(self):
        ids = list(url_reference.NORM_REFERENCES)
        for left, right in itertools.combinations(ids, 2):
            for target in url_axes.case_benign():
                with self.subTest(target=target, pair=(left, right)):
                    lf, rf = _fields(target, left), _fields(target, right)
                    diffs = [k for k in ADAPTER.compare_keys if lf[k] != rf[k]]
                    self.assertEqual(diffs, [], f"{target!r} 在 {left}/{right} 上分歧")


class TestAblation(unittest.TestCase):
    """3. 消融实验真的能定位承载者。"""

    def test_drop_dot_segments_ablates_the_carrier(self):
        payload = b"/admin/../pub"
        left, right = "url-gateway", "url-keep-dots"
        evaluator = _evaluator(left, right)

        div = compare("x", "path_dot_segments", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)

        labels = ADAPTER.ablate(div, evaluator)
        target_label = next(label for label, _ in url_axes.ABLATIONS
                            if "点段" in label)
        self.assertIn(target_label, labels)

        # 把点段整个删掉后，两侧就都没有可解算的东西了 —— 分歧必须消失
        transform = dict(url_axes.ABLATIONS)[target_label]
        candidate = transform(payload)
        self.assertNotEqual(candidate, payload)
        self.assertFalse(diff_keys(evaluator(left, candidate),
                                   evaluator(right, candidate),
                                   ADAPTER.compare_keys))


class TestQuantify(unittest.TestCase):
    """4. 量化：同一段 target 被两侧解成不同资源。"""

    def test_two_paths_differ(self):
        quant = ADAPTER.quantify(b"/pub%2Fadmin", "url-gateway", "url-decode-never")
        self.assertIsNotNone(quant)
        front, back = quant.numbers
        self.assertNotEqual(front, back)
        self.assertEqual((front, back), ("/pub/admin", "/pub%2Fadmin"))

    def test_unknown_impl_quantifies_none(self):
        self.assertIsNone(
            ADAPTER.quantify(b"/pub%2Fadmin", "url-gateway", "not-a-real-impl"))


class TestMinimize(unittest.TestCase):
    """5. 段级最小化：长度不增、分歧仍在。"""

    def test_minimize_keeps_divergence_and_does_not_grow(self):
        payload = b"/a/b/../../admin/../pub"
        left, right = "url-gateway", "url-keep-dots"
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
    """6. 端到端 PoC：URL 领域的脚本必须真能跑通并断言 PASS。"""

    @classmethod
    def setUpClass(cls) -> None:
        impls = list(url_reference.NORM_REFERENCES)
        cls.evaluator = _evaluator(*impls)
        cls.result = scan(ADAPTER, cls.evaluator, mode="axis", limit=20)
        cls.pocs = build_pocs(cls.result)

    def test_pocs_are_all_security(self):
        self.assertTrue(self.pocs, "URL 领域应当产出 security 级发现")
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


class TestRegression(unittest.TestCase):
    """7. 反验证：`url-*` 已知案例全部 PASS。"""

    def test_url_cases_all_pass(self):
        outcomes = regression.run()
        url_cases = [o for o in outcomes if o.name.startswith("url-")]
        self.assertGreaterEqual(len(url_cases), 9)
        for outcome in url_cases:
            self.assertTrue(outcome.passed, f"{outcome.name}: {outcome.detail}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
