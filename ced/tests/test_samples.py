"""样本文件必须一直给出 samples/README.md 里写的结论。

为什么值得一个测试：`samples/` 是演示与评审要用的东西，而"说明里的数字"最容易随时间失真
（参照实现一改、判定口径一调，数字就变了）。这份测试把 README 里的表变成可执行的断言 ——
**文档自带验证**，改了实现就会被这里挡住。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import detect

SAMPLES = Path(__file__).resolve().parents[2] / "samples"

#: 文件名 → (分歧数, 安全级数)。与 samples/README.md 的表逐行对应
EXPECTED_RAW = {
    "01-benign-request.bin": (0, 0),
    "02-cl-te-smuggling.bin": (15, 15),
    "03-cl-leading-zero.bin": (8, 8),
    "04-conflicting-cl.bin": (8, 8),
    "05-chunked-bare-lf.bin": (8, 8),
    "06-host-trailing-dot.bin": (8, 8),
    "07-path-traversal.bin": (11, 11),
    "08-query-pollution.bin": (43, 22),
    "09-enc-uXXXX.bin": (9, 9),
    "10-absolute-form.bin": (29, 28),
}

#: 文件名 → 最高危险等级。与 samples/README.md 的表逐行对应。
#: 守的是"类别与等级是两回事"这条口径：`security` 只说明结构前提成立，
#: 程度要看等级（类型上限 + 证据强度）。
EXPECTED_TIER = {
    "01-benign-request.bin": "",
    "02-cl-te-smuggling.bin": "high",
    "03-cl-leading-zero.bin": "high",
    "04-conflicting-cl.bin": "high",
    "05-chunked-bare-lf.bin": "high",
    "06-host-trailing-dot.bin": "medium",
    "07-path-traversal.bin": "high",
    "08-query-pollution.bin": "medium",
    "09-enc-uXXXX.bin": "medium",
    "10-absolute-form.bin": "high",
}

#: 外部格式文件 → 识别出的格式 + 三态条数（已证实 / 未证实）
EXPECTED_EXTERNAL = {
    "nuclei-results.json": ("nuclei", 1, 1),
    "burp-sitemap.xml": ("burp", 1, 1),
    "devtools.har": ("har", 1, 1),
    "curl-commands.sh": ("curl", 1, 2),
    "urls.txt": ("list", 2, 1),
}


class TestRawSamples(unittest.TestCase):

    def test_samples_exist(self):
        for name in list(EXPECTED_RAW) + [f"external/{n}" for n in EXPECTED_EXTERNAL]:
            self.assertTrue((SAMPLES / name).is_file(), f"样本缺失：{name}")

    def test_raw_samples_match_the_documented_results(self):
        """逐份跑一遍：分歧数/安全级数必须与 README 的表一致。"""
        for name, (divergences, security) in EXPECTED_RAW.items():
            with self.subTest(sample=name):
                text = (SAMPLES / name).read_bytes().decode("latin-1")
                result = detect.run(text)
                self.assertEqual(result["kind"], "raw-request")
                summary = result["summary"]
                self.assertEqual((summary["divergences"], summary["security"]),
                                 (divergences, security),
                                 f"{name} 的结论变了，README 与实现要对齐")
                self.assertEqual(summary["severity"], EXPECTED_TIER[name],
                                 f"{name} 的最高危险等级变了，README 与实现要对齐")

    def test_benign_sample_is_the_control_group(self):
        """对照组：正常请求一个分歧都不许有（防假阳性）。"""
        result = detect.run((SAMPLES / "01-benign-request.bin").read_bytes()
                            .decode("latin-1"))
        self.assertEqual(result["summary"]["divergences"], 0)
        self.assertEqual(result["findings"], [])

    def test_security_samples_carry_a_poc(self):
        """安全级样本必须真能产出 PoC（步骤与脚本都要有）。"""
        for name in ("02-cl-te-smuggling.bin", "07-path-traversal.bin",
                     "06-host-trailing-dot.bin"):
            with self.subTest(sample=name):
                result = detect.run((SAMPLES / name).read_bytes().decode("latin-1"))
                security = [item for item in result["findings"]
                            if item["level"] == "security"]
                self.assertTrue(security, f"{name} 应当判出安全级")
                self.assertTrue(security[0]["poc"]["steps"], "PoC 要带复现步骤")
                self.assertIn("def main", security[0]["poc"]["script"])


class TestExternalSamples(unittest.TestCase):

    def test_external_samples_are_recognized_and_verified(self):
        for name, (kind, confirmed, refuted) in EXPECTED_EXTERNAL.items():
            with self.subTest(sample=name):
                text = (SAMPLES / "external" / name).read_text(encoding="utf-8")
                result = detect.run(text)
                self.assertEqual(result["kind"], kind)
                summary = result["summary"]
                self.assertEqual((summary["confirmed"], summary["refuted"]),
                                 (confirmed, refuted),
                                 f"{name} 的三态结论变了，README 与实现要对齐")

    def test_pcap_is_refused_with_a_way_forward(self):
        """pcap 不支持，但要说清怎么办（导 HAR 或走自动捕获）。"""
        with self.assertRaises(ValueError) as ctx:
            detect.identify("\x00\x01\x02 not really pcap but also not http ###")
        self.assertIn("接受的形态", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
