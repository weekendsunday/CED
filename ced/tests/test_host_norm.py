"""Host / 路由归一化领域的单元测试。

覆盖的都是**消费者可见的行为**：
  * 每个归一化策略开关在它自己的语料上确实产生预期差异
  * 良性轴零分歧（假阳性防线，最重要的一条）
  * 消融实验能机械地定位"分歧由哪类字节承载"
  * 量化口径：同一段 Host 被两侧认成不同虚拟主机
  * 字节级最小化：长度不增、分歧仍在
  * 端到端 PoC：扫描 Host 领域产出的脚本真能跑通并断言 PASS
  * 已知案例反验证：`host-*` 案例全部 PASS
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

# import 即 @register —— 让引擎在干净进程里也知道 host-norm 领域
from ced.adapters import host_norm  # noqa: F401
from ced.adapters.host_norm import HostNormAdapter
from ced import regression
from ced.contracts import ImplSpec
from ced.differ.comparator import compare, diff_keys
from ced.impls import host_reference
from ced.impls.host_norm import normalize_host
from ced.mutate import host_axes
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.scenario import build_pocs, write_pocs

ADAPTER = HostNormAdapter()


def _evaluator(*impl_ids: str) -> Evaluator:
    """把若干参照实现包成本地观测源。"""
    return Evaluator([
        ImplSpec(impl_id=i, name=i, runner="local", policy=i, domain="host-norm")
        for i in impl_ids
    ])


def _fields(host: bytes, impl_id: str) -> dict:
    return normalize_host(host, host_reference.policy_of(impl_id)).to_fields()


#: (Host 字节, left, right, 期望差异字段集, 左 norm_host, 右 norm_host)
#: 每一条都对应"某个 Host 归一化策略开关"这一处真实差异。
CASES: tuple[tuple[bytes, str, str, frozenset, str, str], ...] = (
    (b"example.com.", "host-literal", "host-strip-dot",
     frozenset({"norm_host"}), "example.com.", "example.com"),
    (b"EXAMPLE.com", "host-literal", "host-lowercase",
     frozenset({"norm_host"}), "EXAMPLE.com", "example.com"),
    (b"example.com:80", "host-literal", "host-strip-default-port",
     frozenset({"port"}), "example.com", "example.com"),
    (b"user@example.com", "host-literal", "host-strip-userinfo",
     frozenset({"norm_host", "has_userinfo"}),
     "user@example.com", "example.com"),
    (b"example..com", "host-literal", "host-collapse-dots",
     frozenset({"norm_host"}), "example..com", "example.com"),
    ("münich.example".encode("utf-8"), "host-literal", "host-idna",
     frozenset({"norm_host"}), "münich.example".encode("utf-8").decode("latin-1"),
     "xn--mnich-kva.example"),
    (b"[0:0:0:0:0:0:0:1]", "host-literal", "host-ipv6-canonical",
     frozenset({"norm_host"}), "[0:0:0:0:0:0:0:1]", "[::1]"),
    (b"exa%6Dple.com", "host-literal", "host-percent-decode",
     frozenset({"norm_host"}), "exa%6Dple.com", "example.com"),
)


class TestStrategyKnobs(unittest.TestCase):
    """1. 每个策略开关在它自己的语料上都产生预期差异。"""

    def test_each_knob_produces_expected_divergence(self):
        for host, left, right, expected, lhost, rhost in CASES:
            with self.subTest(host=host, left=left, right=right):
                lf, rf = _fields(host, left), _fields(host, right)
                self.assertEqual(lf["norm_host"], lhost)
                self.assertEqual(rf["norm_host"], rhost)
                diffs = {k for k in ADAPTER.compare_keys if lf[k] != rf[k]}
                self.assertEqual(diffs, set(expected))

    def test_default_port_knob_moves_only_port(self):
        lf = _fields(b"example.com:80", "host-literal")
        rf = _fields(b"example.com:80", "host-strip-default-port")
        self.assertEqual(lf["port"], 80)
        self.assertIsNone(rf["port"])
        self.assertEqual(lf["norm_host"], rf["norm_host"])

    def test_classify_by_exact_field_name(self):
        self.assertEqual(ADAPTER.classify(["norm_host"]), "host_interpretation")
        self.assertEqual(ADAPTER.classify(["port"]), "host_interpretation")
        self.assertEqual(ADAPTER.classify(["accepted", "status"]), "acceptance")
        self.assertEqual(ADAPTER.classify(["is_ip"]), "syntax_detail")


class TestBenignAxis(unittest.TestCase):
    """2. 良性轴零分歧：这是假阳性的第一道防线。"""

    def test_no_pair_diverges_on_benign_hosts(self):
        ids = list(host_reference.NORM_REFERENCES)
        for left, right in itertools.combinations(ids, 2):
            for host in host_axes.case_benign():
                with self.subTest(host=host, pair=(left, right)):
                    lf, rf = _fields(host, left), _fields(host, right)
                    diffs = [k for k in ADAPTER.compare_keys if lf[k] != rf[k]]
                    self.assertEqual(diffs, [], f"{host!r} 在 {left}/{right} 上分歧")


class TestAblation(unittest.TestCase):
    """3. 消融实验真的能定位承载者。"""

    def test_drop_trailing_dot_ablates_the_carrier(self):
        payload = b"example.com."
        left, right = "host-literal", "host-strip-dot"
        evaluator = _evaluator(left, right)

        div = compare("x", "host_trailing_dot", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)

        labels = ADAPTER.ablate(div, evaluator)
        target_label = next(label for label, _ in host_axes.ABLATIONS
                            if "尾随点" in label)
        self.assertIn(target_label, labels)

        transform = dict(host_axes.ABLATIONS)[target_label]
        candidate = transform(payload)
        self.assertNotEqual(candidate, payload)
        self.assertFalse(diff_keys(evaluator(left, candidate),
                                   evaluator(right, candidate),
                                   ADAPTER.compare_keys))

    def test_userinfo_ablation(self):
        payload = b"evil.com@victim.example"
        left, right = "host-literal", "host-strip-userinfo"
        evaluator = _evaluator(left, right)
        div = compare("x", "host_userinfo", payload,
                      evaluator(left, payload), evaluator(right, payload),
                      ADAPTER.compare_keys)
        self.assertIsNotNone(div)
        self.assertIn("抹掉 userinfo（@ 之前）", ADAPTER.ablate(div, evaluator))


class TestQuantify(unittest.TestCase):
    """4. 量化：同一段 Host 被两侧认成不同虚拟主机。"""

    def test_two_vhosts_differ(self):
        quant = ADAPTER.quantify(b"user@example.com",
                                 "host-literal", "host-strip-userinfo")
        self.assertIsNotNone(quant)
        front, back = quant.numbers
        self.assertNotEqual(front, back)
        self.assertEqual((front, back), ("user@example.com", "example.com"))
        self.assertEqual(quant.values["norm_front"], "user@example.com")
        self.assertEqual(quant.values["norm_back"], "example.com")

    def test_unknown_impl_quantifies_none(self):
        self.assertIsNone(
            ADAPTER.quantify(b"example.com.", "host-literal", "not-a-real-impl"))


class TestMinimize(unittest.TestCase):
    """5. 字节级最小化：长度不增、分歧仍在。"""

    def test_minimize_keeps_divergence_and_does_not_grow(self):
        payload = b"sub.example.com."
        left, right = "host-literal", "host-strip-dot"
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
    """6. 端到端 PoC：Host 领域的脚本必须真能跑通并断言 PASS。"""

    @classmethod
    def setUpClass(cls) -> None:
        impls = list(host_reference.NORM_REFERENCES)
        cls.evaluator = _evaluator(*impls)
        cls.result = scan(ADAPTER, cls.evaluator, mode="axis", limit=40)
        cls.pocs = build_pocs(cls.result)

    def test_pocs_are_all_security(self):
        self.assertTrue(self.pocs, "Host 领域应当产出 security 级发现")
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
    """7. 反验证：`host-*` 已知案例全部 PASS。"""

    def test_host_cases_all_pass(self):
        outcomes = regression.run()
        host_cases = [o for o in outcomes if o.name.startswith("host-")]
        self.assertGreaterEqual(len(host_cases), 8)
        for outcome in host_cases:
            self.assertTrue(outcome.passed, f"{outcome.name}: {outcome.detail}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
