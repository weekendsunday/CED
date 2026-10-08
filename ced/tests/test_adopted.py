"""固化语料测试：全部离线，不调模型、不发起网络请求。

覆盖的都是"消费者可见的行为"：
  * 加载：没有文件 = 空（常态）；坏文件报人话而不是悄悄降级；同一条写两遍静默去重
  * 采纳：**只认命中过的**（没逼出过分歧的不许采纳）、幂等、可撤下
  * 身份不变：固化后仍是同一条模型提案 —— origin 仍是 llm、payload → 同一个 proposal_id，
    所以台账与报告不必多认一种来源
  * 不绕门槛：固化语料照样重跑差分 oracle 准入实验，没逼出分歧的就地丢弃 ——
    这条是设计的命门，专人守着
"""
from __future__ import annotations

import base64
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced import adopted, store
from ced.adapters.http1_framing import Http1FramingAdapter
from ced.contracts import ORIGIN_LLM, Proposal
from ced.impls import reference
from ced.probe import Evaluator
from ced.scan.runner import prepare_adopted

ADAPTER = Http1FramingAdapter()
EVAL = Evaluator(reference.specs())

#: 真的会逼出结构分歧（CL/TE 冲突）
_DIVERGES = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
#: 完全规范 —— 两侧必然一致。拿它冒充固化语料，就该被门槛丢掉
_BENIGN = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"


def _ledger(rows, directory: Path) -> sqlite3.Connection:
    """临时台账。``rows`` = (轴名, 字节, 命中与否)。"""
    conn = store.connect(directory / "ced.db")
    for axis, payload, admitted in rows:
        store.save_proposal(
            conn, Proposal(axis=axis, payload=payload, origin=ORIGIN_LLM,
                           model="fake-model", rationale=f"{axis} 当初的理由"),
            compiled=True, admitted=admitted, fields=("cl",) if admitted else ())
    return conn


def _write_file(domain: str, entries: list[dict]) -> Path:
    """手写一份固化文件 —— 模拟有人直接编辑仓库里的 JSON。"""
    path = adopted.path_of(domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"domain": domain, "adopted": entries},
                               ensure_ascii=False), encoding="utf-8")
    return path


def _entry(axis: str, payload: bytes, **extra) -> dict:
    out = {"axis": axis, "payload_b64": base64.b64encode(payload).decode("ascii")}
    out.update(extra)
    return out


class TestAdoptedBase(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(scratch.cleanup)
        self.tmp = Path(scratch.name)
        self._old_dir = adopted.ADOPTED_DIR
        adopted.ADOPTED_DIR = self.tmp / "adopted"
        self.addCleanup(lambda: setattr(adopted, "ADOPTED_DIR", self._old_dir))


class TestLoad(TestAdoptedBase):

    def test_no_file_is_empty(self):
        self.assertEqual(adopted.load("http1-framing"), [])

    def test_roundtrip_keeps_provenance(self):
        conn = _ledger([("llm_axis", _DIVERGES, True)], self.tmp)
        adopted.adopt(conn, "http1-framing", ["llm_axis"])
        cases = adopted.load("http1-framing")
        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual(case.axis, "llm_axis")
        self.assertEqual(case.payload, _DIVERGES)
        self.assertEqual(case.model, "fake-model")
        self.assertEqual(case.rationale, "llm_axis 当初的理由")
        self.assertEqual(case.hit_fields, ("cl",))
        self.assertTrue(case.adopted_at)

    def test_broken_json_says_so(self):
        path = adopted.path_of("http1-framing")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{ 这不是 JSON", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            adopted.load("http1-framing")
        self.assertIn("固化语料读不了", str(ctx.exception))

    def test_entry_without_payload_is_rejected(self):
        _write_file("http1-framing", [{"axis": "llm_axis"}])
        with self.assertRaises(ValueError) as ctx:
            adopted.load("http1-framing")
        self.assertIn("缺 payload_b64", str(ctx.exception))

    def test_bad_base64_is_rejected(self):
        _write_file("http1-framing", [_entry("llm_axis", b"x")])
        path = adopted.path_of("http1-framing")
        body = json.loads(path.read_text(encoding="utf-8"))
        body["adopted"][0]["payload_b64"] = "这不是 base64!!"
        path.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            adopted.load("http1-framing")
        self.assertIn("不是合法 base64", str(ctx.exception))

    def test_same_payload_twice_is_deduped(self):
        _write_file("http1-framing", [_entry("llm_a", _DIVERGES),
                                     _entry("llm_b", _DIVERGES)])
        self.assertEqual([c.axis for c in adopted.load("http1-framing")], ["llm_a"])


class TestAdopt(TestAdoptedBase):

    def test_only_admitted_rows_are_adoptable(self):
        conn = _ledger([("llm_hit", _DIVERGES, True),
                        ("llm_miss", _DIVERGES, False)], self.tmp)
        added, existing, missing = adopted.adopt(conn, "http1-framing",
                                                ["llm_hit", "llm_miss", "不存在"])
        self.assertEqual(added, ["llm_hit"])
        self.assertEqual(existing, [])
        self.assertEqual(sorted(missing), ["llm_miss", "不存在"])
        self.assertEqual([c.axis for c in adopted.load("http1-framing")], ["llm_hit"])

    def test_adopt_is_idempotent(self):
        conn = _ledger([("llm_hit", _DIVERGES, True)], self.tmp)
        adopted.adopt(conn, "http1-framing", ["llm_hit"])
        added, existing, missing = adopted.adopt(conn, "http1-framing", ["llm_hit"])
        self.assertEqual((added, missing), ([], []))
        self.assertEqual(existing, ["llm_hit"])
        self.assertEqual(len(adopted.load("http1-framing")), 1)

    def test_drop_removes_and_reports_absent(self):
        conn = _ledger([("llm_a", _DIVERGES, True),
                        ("llm_b", _DIVERGES + b"x", True)], self.tmp)
        adopted.adopt(conn, "http1-framing", ["llm_a", "llm_b"])
        gone, absent = adopted.drop("http1-framing", ["llm_a", "没有这条"])
        self.assertEqual(gone, ["llm_a"])
        self.assertEqual(absent, ["没有这条"])
        self.assertEqual([c.axis for c in adopted.load("http1-framing")], ["llm_b"])

    def test_identity_is_unchanged(self):
        """固化只改变"怎么拿到它"，不改变"它是谁"。"""
        conn = _ledger([("llm_hit", _DIVERGES, True)], self.tmp)
        adopted.adopt(conn, "http1-framing", ["llm_hit"])
        case = adopted.load("http1-framing")[0]
        proposal = case.to_proposal()
        self.assertEqual(proposal.origin, ORIGIN_LLM)
        self.assertEqual(proposal.proposal_id,
                         Proposal(axis="llm_hit", payload=_DIVERGES).proposal_id)
        self.assertEqual(proposal.rationale, "llm_hit 当初的理由")


class TestPrepareAdopted(TestAdoptedBase):

    def _emit(self):
        events: list[dict] = []
        return events, events.append

    def test_returns_cases_that_still_diverge(self):
        _write_file("http1-framing", [_entry("llm_hit", _DIVERGES,
                                             adopted_from="fake-model")])
        events, emit = self._emit()
        cases = prepare_adopted(emit, ADAPTER, EVAL)      # 不给 conn 也能跑
        self.assertEqual(cases, [("llm_hit", _DIVERGES)])
        self.assertEqual([e["stage"] for e in events], ["propose"])
        self.assertIn("1 条通过", events[0]["detail"])

    def test_benign_entry_is_dropped_by_the_gate(self):
        """手改文件塞一条不会分歧的进来 —— 门槛照样拦得住。"""
        _write_file("http1-framing", [_entry("llm_benign", _BENIGN)])
        events, emit = self._emit()
        self.assertEqual(prepare_adopted(emit, ADAPTER, EVAL), [])
        self.assertIn("0 条通过", events[0]["detail"])

    def test_no_file_means_no_event(self):
        events, emit = self._emit()
        self.assertEqual(prepare_adopted(emit, ADAPTER, EVAL), [])
        self.assertEqual(events, [])

    def test_records_into_ledger_when_conn_given(self):
        _write_file("http1-framing", [_entry("llm_hit", _DIVERGES,
                                             adopted_from="fake-model")])
        conn = store.connect(self.tmp / "ledger.db")
        _, emit = self._emit()
        prepare_adopted(emit, ADAPTER, EVAL, conn)
        stats = store.proposal_stats(conn)
        self.assertEqual(stats["proposed"], 1)
        self.assertEqual(stats["admitted"], 1)
        self.assertEqual(stats["by_origin"]["llm"]["admitted"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
