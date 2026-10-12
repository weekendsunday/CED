"""编码 / Unicode 归一化领域的单元测试。

覆盖的都是**消费者可见的行为**：
  * 每个解释策略开关在它自己的语料上确实产生预期差异
  * 良性轴零分歧（假阳性防线，最重要的一条）
  * 消融实验能机械地定位"分歧由哪类字节承载"
  * 量化口径：同一段字节被检查侧与执行侧读成不同文本
  * 转义片段 / 字节级最小化：长度不增、分歧仍在
  * 端到端 PoC：扫描本领域产出的脚本真能跑通并断言 PASS
  * 已知案例反验证：`enc-*` 案例全部 PASS
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
# import 即 @register —— 新领域不必改中央注册表
from ced.adapters import enc_norm as enc_adapter_module  # noqa: F401
from ced.adapters.enc_norm import EncNormAdapter
from ced.contracts import ImplSpec
from ced.differ.comparator import compare, diff_keys
from ced.impls import enc_reference
from ced.impls.enc_norm import interpret
from ced.mutate import enc_axes
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.scenario import build_pocs, write_pocs

ADAPTER = EncNormAdapter()


def _evaluator(*impl_ids: str) -> Evaluator:
    """把若干参照实现包成本地观测源。"""
    return Evaluator([
        ImplSpec(impl_id=i, name=i, runner="local", policy=i, domain="enc-norm")
        for i in impl_ids
    ])


def _fields(payload: bytes, impl_id: str) -> dict:
    return interpret(payload, enc_reference.policy_of(impl_id)).to_fields()


#: (payload, left, right, 期望差异字段集, 左 norm_text, 右 norm_text)
#: 每一条都对应"某个解释策略开关"这一处真实差异。
CASES: tuple[tuple[bytes, str, str, frozenset, str, str], ...] = (
    (b"%c0%afadmin", "enc-strict", "enc-overlong-accept",
     frozenset({"accepted", "status", "norm_text", "codepoints"}),
     "\\u00c0\\u00afadmin", "/admin"),
    (b"cafe%CC%81", "enc-strict", "enc-nfc",
     frozenset({"norm_text", "codepoints"}),
     "cafe\\u0301", "caf\\u00e9"),
    (b"caf%C3%A9", "enc-strict", "enc-nfd",
     frozenset({"norm_text", "codepoints"}),
     "caf\\u00e9", "cafe\\u0301"),
    (b"%EF%BC%8Fadmin", "enc-strict", "enc-fold-width",
     frozenset({"norm_text", "codepoints"}),
     "\\uff0fadmin", "/admin"),
    (b"%u002fadmin", "enc-strict", "enc-percent-u",
     frozenset({"norm_text", "codepoints", "decoded_layers"}),
     "%u002fadmin", "/admin"),
    (b"pa%C5%BFs", "enc-strict", "enc-fold-case",
     frozenset({"norm_text", "codepoints"}),
     "pa\\u017fs", "pass"),
    (b"%C3%A9", "enc-strict", "enc-latin1",
     frozenset({"norm_text", "codepoints"}),
     "\\u00e9", "\\u00c3\\u00a9"),
    (b"%ED%A0%80", "enc-strict", "enc-surrogate-keep",
     frozenset({"accepted", "status", "norm_text", "codepoints"}),
     "\\u00ed\\u00a0\\u0080", "\\ud800"),
    (b"admin%00.txt", "enc-strict", "enc-nul-truncate",
     frozenset({"norm_text", "codepoints"}),
     "admin\\u0000.txt", "admin"),
)


class TestStrategyKnobs(unittest.TestCase):
    """1. 每个解释策略开关在它自己的语料上都产生预期差异。"""

    def test_each_knob_produces_expected_divergence(self):
        for payload, left, right, expected, ltext, rtext in CASES:
            with self.subTest(payload=payload, left=left, right=right):
                lf, rf = _fields(payload, left), _fields(payload, right)
                self.assertEqual(lf["norm_text"], ltext)
                self.assertEqual(rf["norm_text"], rtext)
                diffs = {k for k in ADAPTER.compare_keys if lf[k] != rf[k]}
                self.assertEqual(diffs, set(expected))


class TestBenignAxis(unittest.TestCase):
    """2. 良性轴零分歧：这是假阳性的第一道防线。"""

    def test_no_pair_diverges_on_benign_payloads(self):
        ids = list(enc_reference.ENC_REFERENCES)
        for left, right in itertools.combinations(ids, 2):
            for payload in enc_axes.case_benign():
                with self.subTest(payload=payload, pair=(left, right)):
                    lf, rf = _fields(payload, left), _fields(payload, right)
                    diffs = [k for k in ADAPTER.compare_keys if lf[k] != rf[k]]
                    self.assertEqual(diffs, [], f"{payload!r} 在 {left}/{right} 上分歧")


class TestAblation(unittest.TestCase):
    """3. 消融实验真的能定位承载者。"""

    def _divergence(self, payload, left, right):
        evaluator = _evaluator(left, right)
        div = compare("x", "probe", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)
        return evaluator, div

    def test_overlong_utf8_is_located(self):
        evaluator, div = self._divergence(b"%c0%afadmin",
                                          "enc-strict", "enc-overlong-accept")
        labels = ADAPTER.ablate(div, evaluator)
        target = next(label for label, _ in enc_axes.ABLATIONS if "非 ASCII" in label)
        self.assertIn(target, labels)

        transform = dict(enc_axes.ABLATIONS)[target]
        candidate = transform(b"%c0%afadmin")
        self.assertNotEqual(candidate, b"%c0%afadmin")
        self.assertFalse(diff_keys(evaluator("enc-strict", candidate),
                                   evaluator("enc-overlong-accept", candidate),
                                   ADAPTER.compare_keys))

    def test_combining_mark_is_located_for_nfc(self):
        evaluator, div = self._divergence(b"cafe%CC%81",
                                          "enc-strict", "enc-nfc")
        labels = ADAPTER.ablate(div, evaluator)
        target = next(label for label, _ in enc_axes.ABLATIONS if "组合附加符号" in label)
        self.assertIn(target, labels)


class TestQuantify(unittest.TestCase):
    """4. 量化：同一段字节被两侧读成不同文本。"""

    def test_two_texts_differ(self):
        quant = ADAPTER.quantify(b"%c0%afadmin", "enc-strict",
                                 "enc-overlong-accept")
        self.assertIsNotNone(quant)
        front, back = quant.numbers
        self.assertNotEqual(front, back)
        self.assertEqual((front, back), ("\\u00c0\\u00afadmin", "/admin"))
        self.assertEqual(quant.values["norm_front"], "\\u00c0\\u00afadmin")
        self.assertEqual(quant.values["norm_back"], "/admin")

    def test_unknown_impl_quantifies_none(self):
        self.assertIsNone(
            ADAPTER.quantify(b"%c0%afadmin", "enc-strict", "not-a-real-impl"))


class TestMinimize(unittest.TestCase):
    """5. 转义 / 字节级最小化：长度不增、分歧仍在。"""

    def test_minimize_keeps_divergence_and_does_not_grow(self):
        payload = b"..%c0%af..%c0%afetc%c0%afpasswd"
        left, right = "enc-strict", "enc-overlong-accept"
        evaluator = _evaluator(left, right)

        def keeps_divergence(candidate: bytes) -> bool:
            return bool(diff_keys(evaluator(left, candidate),
                                  evaluator(right, candidate),
                                  ADAPTER.compare_keys))

        self.assertTrue(keeps_divergence(payload))
        minimized = ADAPTER.minimize(payload, keeps_divergence)
        self.assertLess(len(minimized), len(payload))
        self.assertTrue(keeps_divergence(minimized),
                        f"最小化后分歧丢失：{minimized!r}")


class TestPoc(unittest.TestCase):
    """6. 端到端 PoC：本领域的脚本必须真能跑通并断言 PASS。"""

    @classmethod
    def setUpClass(cls) -> None:
        impls = list(enc_reference.ENC_REFERENCES)
        cls.evaluator = _evaluator(*impls)
        cls.result = scan(ADAPTER, cls.evaluator, mode="axis", limit=40)
        cls.pocs = build_pocs(cls.result)

    def test_pocs_are_all_security(self):
        self.assertTrue(self.pocs, "编码领域应当产出 security 级发现")
        self.assertTrue(all(p.level == "security" for p in self.pocs))
        security_ids = {f.case_id for f in self.result.security}
        for poc in self.pocs:
            self.assertIn(poc.case_id, security_ids)

    def test_poc_uses_filter_scenario(self):
        self.assertTrue(any(p.scenario == "filter" for p in self.pocs))

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
    """7. 反验证：`enc-*` 已知案例全部 PASS。"""

    def test_enc_cases_all_pass(self):
        outcomes = regression.run()
        enc_cases = [o for o in outcomes if o.name.startswith("enc-")]
        self.assertGreaterEqual(len(enc_cases), 8)
        for outcome in enc_cases:
            self.assertTrue(outcome.passed, f"{outcome.name}: {outcome.detail}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
