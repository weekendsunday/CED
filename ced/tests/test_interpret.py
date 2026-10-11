"""解读层测试：全部离线，不发起任何真实网络请求。

覆盖的都是"消费者可见的行为"，重点是那条红线 ——
**解读层改不了判定**：
  * 解析：只认三个键，模型幻觉出来的 level / cwe / verdict 一律丢弃
  * 降级：没配模型 / 连不上 / 输出不合形，都返回 ok=False，绝不抛异常
  * 接入：没传 interpreter 时发现里**根本没有** interpret 字段；
          interpreter 抛异常也不影响差分与判定结果
  * 报告：解读只以"非判定"小栏追加，原有确定性文案一行不改
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import detect
from ced.assist.client import LlmConfig, LlmUnavailable
from ced.assist.interpret import (INTERPRET_KEYS, Interpretation, build_prompt,
                                  interpret, parse_interpretation)

CL_TE = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 48\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
         b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n").decode("latin-1")

GOOD = json.dumps({"impact": "前置把 chunked 体当成正文转发，后端会把它当第二条请求。",
                   "cwe_hint": "CWE-444 HTTP 请求走私",
                   "fix": "对 CL 与 TE 并存的请求一律 400 拒绝，转发前完成定帧。"},
                  ensure_ascii=False)


class _FakeClient:
    """可控的假客户端：离线驱动 interpret 的每条分支。"""

    def __init__(self, reply: str = "", available: bool = True,
                 error: Exception | None = None) -> None:
        self.config = LlmConfig(base_url="http://x/v1", model="fake-model")
        self._reply = reply
        self._available = available
        self._error = error
        self.calls: list[list[dict]] = []

    @property
    def available(self) -> bool:
        return self._available

    def chat(self, messages: list[dict], **_: object) -> str:
        self.calls.append(messages)
        if self._error is not None:
            raise self._error
        return self._reply


class TestParse(unittest.TestCase):
    """文本形状的校验：能抠出 JSON 就认，抠不出就报错，多余字段丢掉。"""

    def test_plain_object_is_accepted(self):
        got = parse_interpretation(GOOD)
        self.assertTrue(got.ok)
        self.assertIn("请求走私", got.cwe_hint)

    def test_markdown_fence_is_tolerated(self):
        got = parse_interpretation("```json\n" + GOOD + "\n```")
        self.assertTrue(got.ok)

    def test_prose_around_json_is_tolerated(self):
        got = parse_interpretation("好的，解读如下：\n" + GOOD + "\n希望有帮助。")
        self.assertTrue(got.ok)

    def test_hallucinated_fields_are_dropped(self):
        """红线：模型自己塞的 level / cwe / verdict 不进任何结构。"""
        raw = json.dumps({"impact": "有影响", "level": "security",
                          "cwe": "CWE-999", "verdict": "confirmed",
                          "proposals": [1]}, ensure_ascii=False)
        got = parse_interpretation(raw)
        self.assertTrue(got.ok)
        self.assertEqual(set(got.to_dict()) - {"model", "ok", "error"},
                         set(INTERPRET_KEYS))
        for leaked in ("security", "CWE-999", "confirmed"):
            self.assertNotIn(leaked, json.dumps(got.to_dict(), ensure_ascii=False))

    def test_non_json_raises(self):
        with self.assertRaises(ValueError):
            parse_interpretation("我觉得这条挺严重的，建议修一下。")

    def test_all_empty_raises(self):
        with self.assertRaises(ValueError):
            parse_interpretation(json.dumps({"impact": "  ", "fix": ""}))

    def test_overlong_text_is_capped(self):
        got = parse_interpretation(json.dumps({"impact": "啊" * 5000}))
        self.assertLessEqual(len(got.impact), 400)

    def test_newlines_collapse_to_one_line(self):
        got = parse_interpretation(json.dumps({"impact": "第一行\n\n第二行"}))
        self.assertEqual(got.impact, "第一行 第二行")


class TestInterpret(unittest.TestCase):

    def test_no_client_degrades_instead_of_raising(self):
        got = interpret(None, finding={})
        self.assertFalse(got.ok)
        self.assertIn("未配置模型", got.error)

    def test_unavailable_client_degrades(self):
        got = interpret(_FakeClient(available=False), finding={})
        self.assertFalse(got.ok)

    def test_client_failure_degrades(self):
        client = _FakeClient(error=LlmUnavailable("模型不可达：超时"))
        got = interpret(client, finding={})
        self.assertFalse(got.ok)
        self.assertIn("不可达", got.error)

    def test_bad_output_degrades(self):
        got = interpret(_FakeClient(reply="这不是 JSON"), finding={})
        self.assertFalse(got.ok)
        self.assertIn("不合形", got.error)

    def test_good_output_is_marked_ok_with_model_name(self):
        got = interpret(_FakeClient(reply=GOOD), finding={"level": "security"})
        self.assertTrue(got.ok)
        self.assertEqual(got.model, "fake-model")
        self.assertTrue(got.impact)

    def test_prompt_states_level_is_final_and_hides_payload_bytes(self):
        prompt = build_prompt({"level": "security", "kind": "framing_boundary",
                               "reason": "结构字段分歧", "payload_repr": "SECRET"})
        self.assertIn("不得更改", prompt)
        self.assertNotIn("SECRET", prompt, "解读不该拿到原始字节，免得它自己去做差分")


class TestDetectIntegration(unittest.TestCase):

    def test_without_interpreter_findings_carry_no_interpretation(self):
        result = detect.run(CL_TE)
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertNotIn("interpret", finding)

    def test_interpreter_attaches_but_never_touches_verdict(self):
        levels = {}
        def fake(finding):
            levels[finding["case_id"]] = (finding["level"], finding["cwe"])
            # 恶意解读：就算模型试图改判定，也不该有地方让它落地
            return {"ok": True, "impact": "翻译", "cwe_hint": "CWE-000",
                    "fix": "修法", "level": "compatibility", "model": "fake-model"}

        result = detect.run(CL_TE, interpreter=fake)
        self.assertTrue(result["findings"])
        self.assertTrue(levels, "解读层应当被调用")
        for finding in result["findings"]:
            self.assertTrue(finding["interpret"]["ok"])
            self.assertEqual(finding["interpret"]["impact"], "翻译")
            # 判定字段与不带解读时完全一致
            self.assertEqual((finding["level"], finding["cwe"]),
                             levels[finding["case_id"]])

    def test_interpreter_exception_does_not_break_detection(self):
        def boom(_finding):
            raise RuntimeError("模拟模型层炸了")

        result = detect.run(CL_TE, interpreter=boom)
        self.assertTrue(result["findings"], "解读层挂掉不该影响差分与判定")
        self.assertTrue(result["report"])
        for finding in result["findings"]:
            self.assertFalse(finding["interpret"]["ok"])

    def test_interpretation_is_appended_as_non_verdict_lines(self):
        events = []
        result = detect.run(CL_TE, emit=events.append,
                            interpreter=lambda f: {"ok": True, "impact": "人话影响",
                                                   "cwe_hint": "CWE-444", "fix": "人话修法"})
        self.assertTrue(result["findings"])
        interpret_events = [e for e in events if e.get("type") == "interpret"]
        self.assertEqual(len(interpret_events), len(result["findings"]))
        self.assertTrue(all(e["interpret"]["ok"] for e in interpret_events))
        # 报告里那几行明确标注"非判定"，且内核原文案仍在
        self.assertIn("模型解读（**非判定**，仅供参考）：人话影响", result["report"])
        self.assertIn("- 修复建议：", result["report"])


class TestServerWiring(unittest.TestCase):

    def test_interpreter_is_none_when_model_not_configured(self):
        import os
        from unittest import mock
        from ced.web import server

        clean = {k: v for k, v in os.environ.items() if not k.startswith("CED_LLM_")}
        with mock.patch.dict(os.environ, clean, clear=True):
            self.assertIsNone(server._make_interpreter())


if __name__ == "__main__":
    unittest.main(verbosity=2)
