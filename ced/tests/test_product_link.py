"""「产品实测」（原矩阵扫描）这一版的验收测试。

覆盖的都是**这一版新加、且容易静默出错**的东西：

  * 探针自报身份：``/health`` 要带领域与读法（旧版只回 ``{"status":"ok"}``）
  * 领域对不上 → 起任务前**拦住**（不是跑完给一份看着正常的报告）
  * 观测缓存：同一对「实现 + 字节」只做一次真实动作，且**故障不缓存**
  * 探针「收全即处理」：有 Content-Length 就不必等 5 秒空闲超时
  * 连线设置加载器：一批坏输入都要给**人话**，旧别名要能用
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.contracts import ImplSpec, Observation, ProbeRejected, ProbeUnreachable
from ced.orchestrate.topology import (SettingsError, Topology, check_probes,
                                      from_text, parse_settings, to_settings)
from ced.probe.cache import CachedObservations
from ced.probe.chain import ChainEvaluator
from ced.probe.server import message_length

DEVNULL = subprocess.DEVNULL
FRONT = Path(__file__).resolve().parent / "fixtures" / "standin_front.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise unittest.SkipTest(f"端口 {port} 未在 {timeout}s 内就绪")


class _WithProbe(unittest.TestCase):
    """起一个真探针 —— 身份自报、收全即处理都要对着真的进程测。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.data_port = _free_port()
        cls.api_port = _free_port()
        cls.probe = subprocess.Popen(
            [sys.executable, "-m", "ced.probe.server",
             "--policy", "ref-cl-first", "--domain", "http1-framing",
             "--data-port", str(cls.data_port), "--api-port", str(cls.api_port)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        try:
            _wait_port(cls.api_port)
        except unittest.SkipTest:
            cls.probe.terminate()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        _stop(cls.probe)

    def _start_front(self) -> int:
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(FRONT), "pass", str(port), str(self.data_port)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)
        return port


# --------------------------------------------------------------- 消息边界

class TestMessageBoundary(unittest.TestCase):
    """``message_length`` 只在**能确定**的时候给结论，其余一律 None（回落超时）。"""

    def test_complete_content_length(self):
        buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
        self.assertEqual(message_length(buf), len(buf))

    def test_incomplete_content_length(self):
        buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel"
        self.assertGreater(message_length(buf), len(buf))

    def test_no_body_is_read_the_moment_headers_end(self):
        buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        self.assertEqual(message_length(buf), len(buf))

    def test_headers_still_arriving_is_unknown(self):
        self.assertIsNone(message_length(b"GET / HTTP/1.1\r\nHost: x\r\n"))

    def test_chunked_is_unknown(self):
        buf = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        self.assertIsNone(message_length(buf))

    def test_cl_and_te_together_is_unknown(self):
        buf = (b"POST / HTTP/1.1\r\nContent-Length: 5\r\n"
               b"Transfer-Encoding: chunked\r\n\r\nhello")
        self.assertIsNone(message_length(buf))

    def test_duplicate_content_length_is_unknown(self):
        buf = (b"POST / HTTP/1.1\r\nContent-Length: 5\r\n"
               b"Content-Length: 6\r\n\r\nhello")
        self.assertIsNone(message_length(buf))

    def test_malformed_content_length_is_unknown(self):
        for value in (b"abc", b"5 5", b"-1", b"0x5"):
            buf = b"POST / HTTP/1.1\r\nContent-Length: " + value + b"\r\n\r\nhello"
            self.assertIsNone(message_length(buf), value)


class TestCollectAndProcess(_WithProbe):
    """收全即处理：有 Content-Length 就不该白等 5 秒空闲超时。"""

    def test_cl_request_is_answered_without_half_close(self):
        """直连探针数据口发一条带 CL 的请求、**不**半关闭：必须立刻回。

        量的是探针自己（前置夹具为了模拟"收不齐"会自己等 2s，量它会串味）。
        改动前这里要等满 IDLE_TIMEOUT（5s），改动后是 DRAIN_GRACE 量级。
        """
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
        started = time.time()
        with socket.create_connection(("127.0.0.1", self.data_port), timeout=10) as sock:
            sock.sendall(payload)
            out = b""
            while b"\r\n\r\n" not in out:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
        elapsed = time.time() - started
        self.assertTrue(out, "探针没有回任何东西")
        self.assertLess(elapsed, 1.5,
                        f"收全即处理没生效，耗时 {elapsed:.1f}s（空闲超时是 5s）")

    def test_chunked_request_still_recorded_verbatim(self):
        """判不出边界（分块）时如实等超时，但**记到的字节原样不动**。"""
        payload = (b"POST / HTTP/1.1\r\nHost: x\r\n"
                   b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        with socket.create_connection(("127.0.0.1", self.data_port), timeout=10) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)          # 半关闭：替身前置就是这么干的
            out = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
        self.assertIn(b"200 OK", out)
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.api_port}/views", timeout=5) as resp:
            views = json.loads(resp.read().decode("utf-8"))["views"]
        self.assertEqual(views[-1]["raw_len"], len(payload),
                         "探针把字节改了 —— 那就不是观测了")

# --------------------------------------------------------------- 探针身份

class TestProbeIdentity(_WithProbe):

    def test_health_reports_domain_and_policy(self):
        url = f"http://127.0.0.1:{self.api_port}/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("domain"), "http1-framing")
        self.assertEqual(data.get("policy"), "ref-cl-first")

    def test_chain_evaluator_reads_the_identity(self):
        ev = ChainEvaluator("127.0.0.1:1", f"127.0.0.1:{self.api_port}")
        ident = ev.identity(timeout=5)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.get("domain"), "http1-framing")

    def test_identity_of_dead_probe_is_none_not_a_guess(self):
        ev = ChainEvaluator("127.0.0.1:1", f"127.0.0.1:{_free_port()}")
        self.assertIsNone(ev.identity(timeout=1))

    def test_self_check_lights_up_all_three_steps(self):
        port = self._start_front()
        ev = ChainEvaluator(f"127.0.0.1:{port}", f"127.0.0.1:{self.api_port}")
        report = ev.self_check("http1-framing", "ref-cl-first")
        self.assertTrue(report["ok"], report["steps"])
        self.assertEqual([s["key"] for s in report["steps"]],
                         ["identity", "reset", "probe"])

    def test_self_check_red_on_domain_mismatch(self):
        port = self._start_front()
        ev = ChainEvaluator(f"127.0.0.1:{port}", f"127.0.0.1:{self.api_port}")
        report = ev.self_check("url-normalization", "")
        self.assertFalse(report["ok"])
        self.assertIn("http1-framing", report["steps"][0]["detail"])

    def test_self_check_red_on_policy_mismatch(self):
        port = self._start_front()
        ev = ChainEvaluator(f"127.0.0.1:{port}", f"127.0.0.1:{self.api_port}")
        report = ev.self_check("http1-framing", "ref-te-first")
        self.assertFalse(report["ok"])
        self.assertIn("ref-te-first", report["steps"][0]["detail"])


class TestDomainGateBlocksRun(_WithProbe):
    """领域对不上 → ``check_probes`` 当场抛（命令行也走这条路）。"""

    def _topo(self, domain: str) -> Topology:
        return Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="mine", name="我的产品", role="front", runner="chain",
                     domain=domain, endpoint=f"127.0.0.1:{_free_port()}",
                     probe_api=f"127.0.0.1:{self.api_port}"),
            ImplSpec(impl_id="ref-cl-first", name="ref-cl-first", role="solo",
                     runner="local", policy="ref-cl-first"),
        ])

    def test_mismatch_is_refused_in_plain_words(self):
        with self.assertRaises(SettingsError) as ctx:
            check_probes(self._topo("url-normalization"))
        text = str(ctx.exception)
        self.assertIn("http1-framing", text)
        self.assertIn("url-normalization", text)

    def test_match_is_a_note_not_an_error(self):
        notes = check_probes(self._topo("http1-framing"))
        self.assertTrue(notes)
        self.assertTrue(any("已核对" in n for n in notes))

    def test_dead_probe_says_it_cannot_verify(self):
        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="mine", name="我的产品", role="front", runner="chain",
                     domain="http1-framing", endpoint=f"127.0.0.1:{_free_port()}",
                     probe_api=f"127.0.0.1:{_free_port()}"),
        ])
        notes = check_probes(topo, timeout=1.0)
        self.assertTrue(any("无法校验" in n for n in notes), notes)


# --------------------------------------------------------------- 观测缓存

class TestObservationCache(unittest.TestCase):

    def test_same_impl_and_bytes_only_trips_once(self):
        seen: list[bytes] = []

        def evaluate(impl_id: str, payload: bytes) -> Observation:
            seen.append(payload)
            return Observation(impl_id=impl_id, fields={"n": len(payload)})

        cache = CachedObservations(evaluate)
        payload = b"POST / HTTP/1.1\r\n\r\n"
        for _ in range(4):
            cache("a", payload)
        cache("b", payload)
        stats = cache.stats()
        self.assertEqual(stats["trips"], 2, "不同实现就是两次动作，同实现同字节只算一次")
        self.assertEqual(stats["hits"], 3)
        self.assertEqual(len(seen), 2)

    def test_unreachable_is_never_cached(self):
        calls = {"n": 0}

        def evaluate(impl_id: str, payload: bytes) -> Observation:
            calls["n"] += 1
            raise ProbeUnreachable("链路抖了一下")

        cache = CachedObservations(evaluate)
        for _ in range(3):
            with self.assertRaises(ProbeUnreachable):
                cache("a", b"x")
        self.assertEqual(calls["n"], 3, "链路故障必须每次都如实暴露，不许被缓存")
        self.assertEqual(cache.stats()["hits"], 0)

    def test_rejected_is_cached(self):
        calls = {"n": 0}

        def evaluate(impl_id: str, payload: bytes) -> Observation:
            calls["n"] += 1
            raise ProbeRejected("前置按策略拒了")

        cache = CachedObservations(evaluate)
        for _ in range(3):
            with self.assertRaises(ProbeRejected):
                cache("a", b"x")
        self.assertEqual(calls["n"], 1, "同一次运行里「被拒绝」是确定的结论，可以复用")

    def test_cache_is_not_shared_across_runs(self):
        from ced.pipeline import scan
        from ced.adapters.http1_framing import Http1FramingAdapter
        from ced.probe import Evaluator

        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="ref-cl-first", name="a", role="solo", runner="local",
                     policy="ref-cl-first"),
            ImplSpec(impl_id="ref-lenient-cl", name="b", role="solo", runner="local",
                     policy="ref-lenient-cl"),
        ])
        adapter = Http1FramingAdapter()
        first = scan(adapter, Evaluator(topo.impls), mode="axis", limit=20,
                     do_minimize=False)
        second = scan(adapter, Evaluator(topo.impls), mode="axis", limit=20,
                      do_minimize=False)
        self.assertEqual(first.cache_hits, second.cache_hits,
                         "每次运行各建一份缓存，第二次不该复用第一次的账")
        self.assertEqual(first.cache_trips, second.cache_trips,
                         "两次运行的真实动作数必须一样（第二次没有偷懒复用）")
        self.assertGreater(first.cache_hits, 0, "同一对字节重复求值就该命中")


# --------------------------------------------------------------- 连线设置加载器

GOOD = {
    "format": 1,
    "domain": "http1-framing",
    "product": {"id": "gw", "name": "网关",
                "endpoint": "127.0.0.1:8080", "probe_api": "127.0.0.1:8801"},
    "impls": [{"id": "ref-cl-first", "role": "back", "runner": "local",
               "policy": "ref-cl-first"}],
    "chain": ["gw", "ref-cl-first"],
}


def _bad(**changes):
    data = json.loads(json.dumps(GOOD))
    data.update(changes)
    return data


class TestLinkLoader(unittest.TestCase):

    def test_good_settings_load(self):
        topo = parse_settings(GOOD)
        self.assertEqual(topo.domain, "http1-framing")
        self.assertEqual(len(topo.impls), 2)
        self.assertEqual(topo.chain, ("gw", "ref-cl-first"))

    def test_legacy_topology_alias_still_works(self):
        data = {"domain": "http1-framing",
                "topology": [{"id": "ref-cl-first", "role": "back",
                              "runner": "local", "policy": "ref-cl-first"}]}
        topo = parse_settings(data)
        self.assertEqual([s.impl_id for s in topo.impls], ["ref-cl-first"])

    def test_impl_field_aliases(self):
        data = {"format": 1, "domain": "http1-framing", "impls": [
            {"id": "gw", "runner": "chain", "address": "127.0.0.1:8080",
             "control": "127.0.0.1:8801"}]}
        topo = parse_settings(data)
        self.assertEqual(topo.impls[0].endpoint, "127.0.0.1:8080")
        self.assertEqual(topo.impls[0].probe_api, "127.0.0.1:8801")

    def test_old_doc_shape_is_refused_not_silently_empty(self):
        """按旧文档写 ``topology:`` + ``product:`` 会被解释成镜像名 —— 必须报错。"""
        data = {"domain": "http1-framing",
                "topology": [{"product": "nginx:1.25.5"}]}
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(data)
        text = str(ctx.exception)
        self.assertIn("nginx", text)
        self.assertIn("chain", text)

    def test_unknown_top_key_is_refused(self):
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(_bad(wat=1))
        self.assertIn("wat", str(ctx.exception))

    def test_empty_impls_is_refused(self):
        data = {"format": 1, "domain": "http1-framing", "impls": [],
                "product": None}
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(data)
        self.assertIn("一个产品都没有", str(ctx.exception))

    def test_missing_id_is_plain(self):
        data = {"format": 1, "domain": "http1-framing", "impls": [
            {"runner": "local", "policy": "ref-cl-first"}]}
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(data)
        self.assertIn("没写 id", str(ctx.exception))

    def test_unknown_runner_is_refused(self):
        data = {"format": 1, "domain": "http1-framing", "impls": [
            {"id": "x", "runner": "docker"}]}
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(data)
        self.assertIn("chain", str(ctx.exception))

    def test_chain_must_be_two_known_ids(self):
        with self.assertRaises(SettingsError):
            parse_settings(_bad(chain=["gw"]))
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(_bad(chain=["gw", "nope"]))
        self.assertIn("nope", str(ctx.exception))

    def test_format_from_the_future_is_refused(self):
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(_bad(format=99))
        self.assertIn("99", str(ctx.exception))

    def test_local_policy_must_exist(self):
        data = {"format": 1, "domain": "http1-framing", "impls": [
            {"id": "x", "runner": "local", "policy": "does-not-exist"}]}
        with self.assertRaises(SettingsError) as ctx:
            parse_settings(data)
        self.assertIn("chain", str(ctx.exception))

    def test_yaml_without_parser_says_what_to_do(self):
        # 本机装了 PyYAML 也要能测「没装」的分支：sys.modules 置 None 让函数内
        # import yaml 直接 ImportError（对局部导入这是唯一可靠的模拟方式）
        import sys
        with mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaises(SettingsError) as ctx:
                from_text("domain: http1-framing\n", suffix=".yaml",
                          source="a.yaml")
        text = str(ctx.exception)
        self.assertTrue("PyYAML" in text or "pyyaml" in text, text)

    def test_broken_json_points_at_line_and_column(self):
        with self.assertRaises(SettingsError) as ctx:
            from_text('{"domain": "x",}', suffix=".json", source="a.json")
        self.assertIn("第", str(ctx.exception))

    def test_round_trip_is_stable(self):
        topo = parse_settings(GOOD)
        again = to_settings(topo)
        self.assertEqual(again["product"]["endpoint"], "127.0.0.1:8080")
        self.assertEqual(parse_settings(again).domain, "http1-framing")

    def test_reference_file_loads(self):
        from ced.orchestrate.topology import load

        topo = load(ROOT / "ced" / "topologies" / "standin-front.json")
        self.assertEqual(topo.chain, ("standin-front", "ref-cl-first"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
