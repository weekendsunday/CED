"""发现归并的测试。

守的是两条**消费者可见的不变量**：
  * **条数守恒** —— 归并只是展示层的事，绝不允许把发现弄丢（汇总的 count 必须等于发现总数）
  * **代表选择确定性** —— 同一份输入任何时候都选出同一条代表（级别优先 → 最小化后最短 → case_id）

再加一条报告侧不变量：明细小节的数量必须等于类的数量（否则报告又会淹没在重复条目里）。
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced.adapters import get as get_adapter
from ced.pipeline import scan
from ced.probe import Evaluator
from ced.report.cluster import cluster, cluster_payload, redundancy
from ced.report.renderer import render_markdown, result_payload

ADAPTER = get_adapter("host-norm")


def _result(limit: int = 30):
    return scan(ADAPTER, Evaluator(ADAPTER.specs()), mode="axis",
                limit=limit, do_minimize=False)


class TestClusterInvariants(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _result()
        cls.clusters = cluster(cls.result.findings)

    def test_counts_are_conserved(self):
        """归并不丢发现：各组条数之和 == 发现总数，且分组键与条数完全对应。

        注意：同一个 case_id（同一份字节）对不同实现对会分叉，因此它可能成为
        **多个类别**的代表 —— 那是正确行为，不是重复计数。
        """
        from collections import Counter

        self.assertTrue(self.clusters, "内置语料应当产出发现")
        self.assertEqual(sum(c.count for c in self.clusters),
                         len(self.result.findings))
        expected = Counter(
            (f.divergence.left.impl_id, f.divergence.right.impl_id, f.verdict.kind)
            for f in self.result.findings)
        actual = {(c.left, c.right, c.kind): c.count for c in self.clusters}
        self.assertEqual(len(actual), len(self.clusters), "分组键必须唯一")
        self.assertEqual(actual, expected, "归并的键与条数必须与发现完全对应")

    def test_grouping_key_is_pair_plus_kind(self):
        """同一组里的所有发现必须是同一对实现 + 同一分歧类型。"""
        for item in self.clusters:
            self.assertEqual(item.left, item.representative.divergence.left.impl_id)
            self.assertEqual(item.right, item.representative.divergence.right.impl_id)
            self.assertEqual(item.kind, item.representative.verdict.kind)

    def test_representative_selection_is_deterministic_and_level_first(self):
        again = cluster(self.result.findings)
        self.assertEqual([c.case_id for c in self.clusters],
                         [c.case_id for c in again], "同一输入必须选出同一批代表")
        for item in self.clusters:
            levels = {f.verdict.level for f in self.result.findings
                      if f.divergence.left.impl_id == item.left
                      and f.divergence.right.impl_id == item.right
                      and f.verdict.kind == item.kind}
            self.assertEqual(item.level, item.representative.verdict.level)
            if "security" in levels:
                self.assertEqual(item.level, "security",
                                 "组内只要有安全级，代表就该是安全级")

    def test_ordering_is_stable(self):
        order = {"security": 0, "unknown": 1, "compatibility": 2}
        keys = [(order.get(c.level, 9), -c.count, c.left, c.right, c.kind)
                for c in self.clusters]
        self.assertEqual(keys, sorted(keys))

    def test_redundancy_matches_ratio(self):
        self.assertAlmostEqual(redundancy(self.result.findings),
                               len(self.result.findings) / len(self.clusters), places=2)

    def test_representative_prefers_measured_chain_evidence(self):
        """组内有一条拿到过真实链路实测 → 代表必须是它（最强的证据不能被更短的顶掉）。"""
        from types import SimpleNamespace as NS

        def fake(case_id, *, length, chain=None, level="security"):
            return NS(case_id=case_id, minimized_len=length, original_len=length,
                      chain_evidence=chain,
                      verdict=NS(level=level, kind="cl"),
                      divergence=NS(left=NS(impl_id="ref-a"), right=NS(impl_id="ref-b"),
                                    axis="cl-leading-zero"))

        cluster_ = cluster([fake("short", length=5), fake("measured", length=40,
                                                          chain="前置转发 39 / 后端 0 / 夹带 39")])
        self.assertEqual(len(cluster_), 1)
        self.assertEqual(cluster_[0].case_id, "measured")
        self.assertEqual(cluster_[0].count, 2)
        # 没有链路证据时，才回到"最短优先"
        cluster_ = cluster([fake("short", length=5), fake("long", length=40)])
        self.assertEqual(cluster_[0].case_id, "short")


class TestClusterSurfaces(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = _result()
        cls.clusters = cluster(cls.result.findings)

    def test_report_detail_lists_one_section_per_class(self):
        """报告明细的小节数必须等于类数 —— 否则又会被重复条目淹没。"""
        report = render_markdown(self.result, domain="host-norm")
        self.assertEqual(len(re.findall(r"^### \[", report, flags=re.M)),
                         len(self.clusters))
        self.assertIn("## 同类归并", report)
        self.assertIn(f"冗余", report)

    def test_payload_carries_clusters_and_keeps_every_finding(self):
        payload = result_payload(self.result)
        self.assertEqual(sum(c["count"] for c in payload["clusters"]),
                         len(payload["findings"]))
        self.assertEqual(len(payload["findings"]), len(self.result.findings),
                         "JSON 必须保留完整清单，归并只影响展示")

    def test_没改字节的修复形态不画对照表(self):
        """字节没变的发现只给说明、不给对照表 —— 两栏一模一样不是对照，是噪声。

        判据是修复形态自己的 ``changed``：拿"这一节里有没有 diff 围栏"来验。
        """
        payload = result_payload(self.result)
        by_id = {f["case_id"]: f for f in payload["findings"]}
        reps = [by_id[c["case_id"]] for c in payload["clusters"]]
        noop = [f for f in reps if f["fix_view"]
                and not f["fix_view"]["changed"] and not f["fix_view"]["reject"]]
        self.assertTrue(noop, "这组语料里应当有'字节没得改'的分歧可测")
        report = render_markdown(self.result, domain="host-norm")
        for item in noop:
            with self.subTest(case=item["case_id"]):
                head = "`%s`" % item["case_id"]
                chunk = next(c for c in report.split("\n### ") if head in c.split("\n", 1)[0])
                self.assertIn("无需改写字节", chunk, "为什么没改动必须写出来")
                self.assertNotIn("```diff", chunk, "没改动就不该画对照表")
        for item in payload["clusters"]:
            self.assertEqual({"left", "right", "kind", "level", "severity",
                              "count", "case_id", "axis", "case_ids"}, set(item))
        self.assertAlmostEqual(payload["redundancy"], redundancy(self.result.findings),
                               places=2)

    def test_payload_cluster_payload_is_json_safe(self):
        import json
        json.dumps(cluster_payload(self.result.findings), ensure_ascii=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
