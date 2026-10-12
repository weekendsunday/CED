"""验证层（intake）的单元测试。

覆盖消费者可见的行为：
  * 5 种外部格式各能解析出假设（外加 manual）
  * 三态口径：confirmed / refuted / unverifiable
  * 格式识别失败报人话错误，不静默返回空
  * domains=[] 不报错
  * 一条假设的失败不拖垮整批
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# import 即触发领域注册（@register）
from ced.adapters import url_norm  # noqa: F401
from ced.intake import (CONFIRMED, REFUTED, UNVERIFIABLE, Hypothesis,
                        load, verify)

#: 一条真会被检出的输入：`..` 段在"解算 / 保留"两侧造成不同资源
DIVERGENT_URL = "http://example.com/admin/../pub"
#: 一条完全规范、两侧理解一致的输入
BENIGN_URL = "http://example.com/pub/index.html"

NUCLEI_JSONL = (
    '{"template-id":"path-trav","matched-at":'
    '"http://example.com/admin/../pub","host":"example.com"}\n'
)
BURP_XML = (
    '<?xml version="1.0"?>\n'
    '<items><item><url>http://example.com/pub/index.html</url>'
    '<host>example.com</host></item></items>'
)
HAR_JSON = (
    '{"log":{"entries":[{"request":{"method":"GET",'
    '"url":"http://example.com/admin/../pub",'
    '"postData":{"text":"a=1"}}}]}}'
)
CURL_LINE = ("curl -X GET -H 'Host: example.com' --data 'a=1' "
             "http://example.com/admin/../pub")
LIST_TEXT = "http://example.com/admin/../pub\n# comment\n"


class TestFormats(unittest.TestCase):
    """5 种格式各解析出至少一条，且字段正确。"""

    def test_nuclei_jsonl(self):
        hyps = load(NUCLEI_JSONL)
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "nuclei")
        self.assertEqual(hyps[0].target, DIVERGENT_URL)
        self.assertEqual(hyps[0].note, "path-trav")
        self.assertIn("matched-at", hyps[0].raw)

    def test_burp_xml(self):
        hyps = load(BURP_XML)
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "burp")
        self.assertEqual(hyps[0].target, BENIGN_URL)
        self.assertEqual(hyps[0].note, "example.com")

    def test_har_json(self):
        hyps = load(HAR_JSON)
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "har")
        self.assertEqual(hyps[0].target, DIVERGENT_URL)
        self.assertEqual(hyps[0].note, "GET")
        self.assertIn("a=1", hyps[0].raw)          # postData 进了 raw

    def test_curl_command(self):
        hyps = load(CURL_LINE)
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "curl")
        self.assertEqual(hyps[0].target, DIVERGENT_URL)
        self.assertEqual(hyps[0].raw, CURL_LINE)

    def test_plain_list(self):
        hyps = load(LIST_TEXT)
        self.assertEqual(len(hyps), 1)             # 注释行被跳过
        self.assertEqual(hyps[0].source, "list")
        self.assertEqual(hyps[0].target, DIVERGENT_URL)

    def test_manual(self):
        hyps = load(DIVERGENT_URL, fmt="manual")
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "manual")
        self.assertEqual(hyps[0].target, DIVERGENT_URL)

    def test_path_with_extension_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.jsonl"
            path.write_text(NUCLEI_JSONL, encoding="utf-8")
            hyps = load(str(path))
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].source, "nuclei")


class TestSniffFailure(unittest.TestCase):
    """格式识别失败要报人话错误，不许静默返回空。"""

    def test_empty_input(self):
        with self.assertRaises(ValueError) as ctx:
            load("")
        self.assertIn("空", str(ctx.exception))

    def test_unrecognized_json(self):
        with self.assertRaises(ValueError):
            load('{"a": 1}')

    def test_unknown_format_name(self):
        with self.assertRaises(ValueError) as ctx:
            load("whatever", fmt="bogus")
        self.assertIn("bogus", str(ctx.exception))

    def test_explicit_wrong_format(self):
        with self.assertRaises(ValueError):
            load("not a nuclei result", fmt="nuclei")

    def test_curl_command_without_url(self):
        with self.assertRaises(ValueError):
            load("curl -k -s\n")


class TestVerdicts(unittest.TestCase):
    """三态口径。"""

    def test_confirmed_uses_divergent_pair(self):
        hyps = load(LIST_TEXT)
        results = verify(hyps, domains=["url-norm"])
        self.assertEqual(len(results), 1)
        v = results[0]
        self.assertEqual(v.verdict, CONFIRMED)
        self.assertEqual(v.domain, "url-norm")
        self.assertTrue(v.left and v.right)
        self.assertIn(v.level, ("security", "unknown", "compatibility"))
        self.assertTrue(v.evidence)                # 消融证据非空
        self.assertIsNotNone(v.minimized_b64)

    def test_refuted_on_benign_input(self):
        """口径：`refuted` 只表示"试过的这些领域里看不出分歧"，**不等于发现是假的**。"""
        hyps = load(BENIGN_URL, fmt="manual")
        results = verify(hyps, domains=["url-norm"])
        detail = results[0].detail
        self.assertEqual(results[0].verdict, REFUTED)
        self.assertIn("未证实", detail)
        self.assertIn("不等于这条发现是假的", detail)      # 不许把"没看出"说成"是假的"
        self.assertIn("url-norm", detail)                  # 要写清试过哪些领域

    def test_unverifiable_when_input_not_acceptable(self):
        # 只有 URL、没有原始请求字节 → 分帧领域无从下手
        hyps = load(LIST_TEXT)          # target 是 URL，raw 为空
        results = verify(hyps, domains=["http1-framing"])
        self.assertEqual(results[0].verdict, UNVERIFIABLE)
        self.assertIn("HTTP/1.", results[0].detail)

    def test_all_domains_do_not_raise(self):
        hyps = load(LIST_TEXT)
        results = verify(hyps, domains=[])
        self.assertEqual(len(results), 1)
        self.assertIn(results[0].verdict, (CONFIRMED, REFUTED, UNVERIFIABLE))

    def test_bad_batch_member_does_not_kill_batch(self):
        good = Hypothesis(source="list", target=DIVERGENT_URL)
        broken = Hypothesis(source="manual", target="")   # 空目标
        results = verify([good, broken], domains=["url-norm"])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].verdict, CONFIRMED)
        self.assertEqual(results[1].verdict, UNVERIFIABLE)


class TestFormatToVerdict(unittest.TestCase):
    """端到端：解析 → 验证。"""

    def test_nuclei_hit_confirmed(self):
        hyps = load(NUCLEI_JSONL)
        results = verify(hyps, domains=["url-norm"])
        self.assertEqual(results[0].verdict, CONFIRMED)

    def test_burp_benign_refuted(self):
        hyps = load(BURP_XML)
        results = verify(hyps, domains=["url-norm"])
        self.assertEqual(results[0].verdict, REFUTED)

    def test_curl_hit_confirmed(self):
        hyps = load(CURL_LINE)
        results = verify(hyps, domains=["url-norm"])
        self.assertEqual(results[0].verdict, CONFIRMED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
