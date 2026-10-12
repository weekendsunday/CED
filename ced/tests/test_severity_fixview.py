"""危险等级（五档）与"修复形态"的回归测试。

守两条对外承诺：

  * **等级一定是五档之一，而且与证据强度单调相关** —— "结构性前提成立"只到"高"，
    只有实机测量才能顶到"严重"；量化不出来要降档，不能照样报满。
  * **修复形态一定与原始输入同口径** —— 规范化后的字节再规范化一次不该再变，
    而且它必须真的把歧义消掉（拿两侧观测复核），否则就是编了一个假的修复方案。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import detect
from ced.adapters import get as get_adapter, names as domain_names
from ced.classify.upgradability import grade
from ced.contracts import (LEVEL_COMPAT, LEVEL_SECURITY, LEVEL_UNKNOWN,
                           SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFO,
                           SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_ORDER,
                           Verdict)
from ced.differ.comparator import diff_keys
from ced.probe import Evaluator
from ced.report.fixview import fix_view, line_diff

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


class _Q:
    """量化结果的替身 —— 只带 grade 关心的三个事实。"""

    def __init__(self, *, verified=True, mismatch=True, measured=False,
                 blocked=False):
        self.verified, self.mismatch = verified, mismatch
        self.measured, self.blocked = measured, blocked


class TestGrade(unittest.TestCase):
    """等级规则的**真值表**：每一档的进入条件都钉死在这里。"""

    def test_category_to_tier(self):
        self.assertEqual(grade(level=LEVEL_COMPAT, ceiling="high",
                               controllable=True), SEVERITY_INFO)
        self.assertEqual(grade(level=LEVEL_UNKNOWN, ceiling="high",
                               controllable=True), SEVERITY_LOW)

    def test_security_needs_controllable(self):
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=False), SEVERITY_LOW)

    def test_ceiling_is_reached_only_with_confirmed_mismatch(self):
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=True, quantified=_Q()),
                         SEVERITY_HIGH)
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="medium",
                               controllable=True, quantified=_Q()),
                         SEVERITY_MEDIUM)

    def test_unquantified_drops_one_tier(self):
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=True, quantified=None),
                         SEVERITY_MEDIUM)
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=True, quantified=_Q(verified=False)),
                         SEVERITY_MEDIUM)

    def test_no_actual_mismatch_drops_two_tiers(self):
        """量化出来了两侧其实一致 —— 那比"没量化"更弱，降两档。"""
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=True, quantified=_Q(mismatch=False)),
                         SEVERITY_LOW)

    def test_blocked_chain_does_not_downgrade(self):
        """前置直接拒绝（一个字节都没转发）说的是"没有链路"，不是"两侧一致" —— 不降档。

        否则"前置实现越严格，等级越低"，整类分歧会被压到最低档。
        """
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="high",
                               controllable=True,
                               quantified=_Q(mismatch=False, blocked=True)),
                         SEVERITY_HIGH)

    def test_only_measured_evidence_reaches_critical(self):
        self.assertEqual(grade(level=LEVEL_SECURITY, ceiling="medium",
                               controllable=True, quantified=_Q(measured=True)),
                         SEVERITY_CRITICAL)

    def test_verdict_without_severity_falls_back_to_level(self):
        """外部构造的老 Verdict 没带 severity 时，也要有一个保守的等级，不能是空。"""
        self.assertEqual(Verdict(level=LEVEL_SECURITY).severity, SEVERITY_MEDIUM)
        self.assertEqual(Verdict(level=LEVEL_UNKNOWN).severity, SEVERITY_LOW)
        self.assertEqual(Verdict(level=LEVEL_COMPAT).severity, SEVERITY_INFO)
        self.assertIn(Verdict(level=LEVEL_SECURITY).severity, SEVERITY_ORDER)


class TestEveryAdapterGradesAndHardens(unittest.TestCase):

    def test_每个领域都声明了基准实现与修复形态(self):
        for name in domain_names():
            adapter = get_adapter(name)
            with self.subTest(domain=name):
                self.assertTrue(callable(getattr(adapter, "harden", None)),
                                "适配器必须给出修复形态")
                baseline = getattr(adapter, "baseline_id", None)
                self.assertTrue(baseline, "必须声明修复形态以哪个基准实现为准")
                ids = [s.impl_id for s in adapter.specs()]
                self.assertIn(baseline, ids, "基准实现必须是本领域里的一个实现")

    def test_每个分歧类型都有等级上限(self):
        ceilings = {"critical", "high", "medium", "low", "info"}
        for name in domain_names():
            adapter = get_adapter(name)
            for kind in adapter.boundary_kinds + (adapter.kind_acceptance,):
                with self.subTest(domain=name, kind=kind):
                    self.assertIn(adapter.meta(kind).get("severity"), ceilings)


class TestFixView(unittest.TestCase):

    def _raw(self, name: str) -> bytes:
        return (SAMPLES / name).read_bytes()

    def test_cl_te_conflict_is_rejected_not_just_rewritten(self):
        """CL 与 TE 并存：修复口径是**直接拒绝** —— 但仍要给出规范形态供对照。"""
        view = fix_view("http1-framing", self._raw("02-cl-te-smuggling.bin"))
        self.assertTrue(view["reject"])
        self.assertTrue(view["changed"])
        self.assertTrue(any("Transfer-Encoding" in c for c in view["changes"]))
        self.assertNotIn("Transfer-Encoding", view["fixed_text"])

    def test_leading_zero_content_length_is_canonicalised(self):
        view = fix_view("http1-framing", self._raw("03-cl-leading-zero.bin"))
        self.assertIn("Content-Length: 3", view["fixed_text"])
        self.assertNotIn("Content-Length: 03", view["fixed_text"])

    def test_path_dot_segments_are_resolved(self):
        view = fix_view("url-norm", self._raw("07-path-traversal.bin"))
        self.assertIn("/admin", view["fixed_text"])
        self.assertNotIn("..", view["fixed_text"])

    def test_duplicate_params_are_dropped(self):
        view = fix_view("query-norm", self._raw("08-query-pollution.bin"))
        self.assertTrue(view["changed"])
        self.assertIn("a=1&b=%253C", view["fixed_text"])

    def test_diff_rows_are_ordered_and_tagged(self):
        rows = line_diff(b"a\nb\n", b"a\nc\n")
        self.assertEqual([r["tag"] for r in rows], ["same", "del", "add"])
        self.assertEqual(rows[1]["orig"], "b")
        self.assertEqual(rows[2]["fixed"], "c")

    def test_修复形态必须把歧义真的消掉(self):
        """规范化后的字节再规范化一次不该再变（幂等），否则"修复"没修干净。"""
        for name in ("02-cl-te-smuggling.bin", "03-cl-leading-zero.bin",
                     "04-conflicting-cl.bin", "07-path-traversal.bin",
                     "08-query-pollution.bin", "09-enc-uXXXX.bin",
                     "10-absolute-form.bin"):
            raw = self._raw(name)
            for domain in domain_names():
                adapter = get_adapter(domain)
                first = adapter.harden(raw)
                if first is None:
                    continue
                second = adapter.harden(first.fixed)
                with self.subTest(sample=name, domain=domain):
                    self.assertIsNotNone(second)
                    self.assertEqual(second.fixed, first.fixed,
                                     "修复形态必须自洽：再改写一次不该继续变")

    def test_规范化后的字节在各实现间不再分叉(self):
        """修复的判据是"两侧读成同一个东西" —— 用领域自己的观测复核。"""
        adapter = get_adapter("url-norm")
        raw = self._raw("07-path-traversal.bin")
        fixed = adapter.harden(raw).fixed
        evaluator = Evaluator(adapter.specs())
        ids = [s.impl_id for s in adapter.specs()]
        for other in ids[1:]:
            with self.subTest(other=other):
                self.assertFalse(
                    diff_keys(evaluator(ids[0], fixed), evaluator(other, fixed),
                              adapter.compare_keys),
                    "规范化之后不该再有分歧")

    def test_未知领域返回没有方案而不是抛错(self):
        """领域名不认识时只能是"取不到方案"，不能把整份报告 / 整个页面带崩。

        这不是假想场景：手工构造的 ScanResult 默认 ``domain=""``，
        而结果包会对**每条发现**取修复形态。
        """
        self.assertIsNone(fix_view("", b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
        self.assertIsNone(fix_view("no-such-domain", b"GET / HTTP/1.1\r\n\r\n"))

    def test_已经是规范形态时没有一个字节要改(self):
        """TE 只有一条且是 chunked、请求体是规范分块 —— 没有可改的字节。

        这种分歧是**实现策略**不同（同一份合法写法，双方接受度不一样），
        ``changed`` 为假就是判据：界面/报告据此不再画一张左右相同的对照表。
        """
        raw = (b"POST /a HTTP/1.1\r\nHost: example.com\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        view = fix_view("http1-framing", raw)
        self.assertFalse(view["changed"])
        self.assertFalse(view["reject"])
        self.assertEqual(view["changes"], [])
        self.assertTrue(view["rows"], "对照表仍然要给出来，只是不该被当成改动")
        self.assertTrue(all(r["tag"] == "same" for r in view["rows"]))
        self.assertTrue(view["note"], "必须说清为什么没有改动")

    def test_改没改字节看字节而不是看对照表(self):
        """超长输入不做逐行比对（对照表退化成空表），此时仍要判对有没有改动。

        否则一条**真的改了字节**的发现会被当成"无需改写"——
        那正是"对比里前后毫无区别"的另一面。
        """
        lines = [b"GET / HTTP/1.1", b"Host: example.com"]
        lines += [b"X-Pad-%d: v" % i for i in range(320)]      # 超过逐行比对的阈值
        lines.append(b"Content-Length: 03")                    # 这条确实要改写
        raw = b"\r\n".join(lines) + b"\r\n\r\nabc"
        view = fix_view("http1-framing", raw)
        self.assertEqual(view["rows"], [], "这么长就不该逐行比了")
        self.assertTrue(view["changed"], "字节真的变了，不能说成无需改写")

    def test_fix_view_is_json_safe_and_has_no_diff_when_nothing_changes(self):
        import json
        view = fix_view("host-norm", self._raw("01-benign-request.bin"))
        json.dumps(view, ensure_ascii=False)
        self.assertFalse(view["changed"])
        self.assertTrue(view["note"])


class TestDetectSeverity(unittest.TestCase):

    def test_摘要带上五档分档且总数吻合(self):
        raw = (SAMPLES / "07-path-traversal.bin").read_bytes()
        result = detect.run(raw.decode("latin-1"))
        summary = result["summary"]
        self.assertIn(summary["severity"], SEVERITY_ORDER)
        self.assertEqual(sum(summary["by_severity"].values()),
                         summary["divergences"],
                         "分档必须覆盖每一条分歧，不能漏计")
        ceiling = {"high": 1, "medium": 2, "low": 3, "info": 4, "critical": 0}
        worst = min(summary["by_severity"],
                    key=lambda key: ceiling.get(key, 9))
        self.assertEqual(summary["severity"], worst)
        for finding in result["findings"]:
            self.assertIn(finding["severity"], SEVERITY_ORDER)

    def test_每条发现都带修复形态或明确说明给不出(self):
        raw = (SAMPLES / "02-cl-te-smuggling.bin").read_bytes()
        result = detect.run(raw.decode("latin-1"))
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertIn("fix_view", finding)

    def test_修复方案写进了报告(self):
        raw = (SAMPLES / "07-path-traversal.bin").read_bytes()
        result = detect.run(raw.decode("latin-1"))
        report = result["report"]
        report = report if isinstance(report, str) else "\n".join(report)
        self.assertIn("修复形态", report)
        self.assertIn("```diff", report)


class TestExternalInputsGetTheSameTreatment(unittest.TestCase):
    """外部扫描器结果（nuclei/Burp/HAR/curl/清单）走的是另一条链。

    它曾经只给三态、不给危险等级、也不给修复形态 —— 于是"照别处一样看一条发现"
    到这里就断了。这两条测试把它钉在同一口径上。
    """

    EXTERNAL = ("nuclei-results.json", "burp-sitemap.xml", "devtools.har",
                "curl-commands.sh", "urls.txt")

    def test_已证实条目必须带危险等级与修复形态(self):
        for name in self.EXTERNAL:
            with self.subTest(sample=name):
                text = (SAMPLES / "external" / name).read_text(encoding="utf-8")
                result = detect.run(text)
                summary = result["summary"]
                self.assertLessEqual(sum(summary["by_severity"].values()),
                                     summary["confirmed"])
                confirmed = [f for f in result["findings"]
                             if f["verdict"] == "confirmed"]
                self.assertTrue(confirmed, f"{name} 应当至少证实一条")
                for finding in confirmed:
                    self.assertIn(finding["severity"], SEVERITY_ORDER)
                    self.assertIsNotNone(finding["fix_view"],
                                         "已证实的条目必须给出修复形态")

    def test_修复形态写进了外部结果报告(self):
        text = (SAMPLES / "external" / "urls.txt").read_text(encoding="utf-8")
        result = detect.run(text)
        self.assertIn("修复形态", result["report"])
        self.assertIn("```diff", result["report"])


class TestDoubtsAlsoGetAFix(unittest.TestCase):
    """疑点（没升级的那些）也要给改动清单 —— 报告里只有一张汇总表等于什么都没说。"""

    def test_疑点也有修复形态(self):
        raw = (SAMPLES / "08-query-pollution.bin").read_bytes()
        result = detect.run(raw.decode("latin-1"))
        doubts = [f for f in result["findings"] if f["level"] != "security"]
        self.assertTrue(doubts, "这份样本本就该产出疑点，否则这条测试没在测东西")
        report = result["report"]
        self.assertIn("## 疑点", report)
        self.assertIn("修复形态", report[doubts and report.find("## 疑点"):])


if __name__ == "__main__":
    unittest.main(verbosity=2)
