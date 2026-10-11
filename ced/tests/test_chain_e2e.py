"""链路端到端测试：真实前置 → 探针，**不需要 Docker**。

这是最有价值的一组测试 —— 它把"审查中发现、但项目自身从未验证过"的能力
变成了可重复执行的事实：

  * 透明前置        → 0 分歧（差分的差分，证明无自噪声/假阳性）
  * 会改写的前置    → 检出边界分歧（证明链路差分真的能工作）
  * 前置不可达      → **抛错**，绝不合成观测（防"探测失败 → 成片假阳性"）
  * 前置收下不转发  → **跳过并计数**（不合成观测、也不中止；真实前置拒绝畸形请求属正常）
  * 吃不下半关闭的前置 → 链路器**自动降级成普通客户端模式**（真 nginx 就是这样：本机实测
                        客户端立即半关闭时它既不转发也不回响应），且只多花一次连接
  * 静默丢弃某些请求的前置 → **跳过并计数**（真 gunicorn 对裸 LF / 大写块长就是这样），
                        而"上游真的不通"仍然**中止** —— 两者靠活性复探区分
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ced.adapters.http1_framing import Http1FramingAdapter
from ced.contracts import Divergence, ImplSpec, Observation
from ced.orchestrate.topology import Topology
from ced.pipeline import scan
from ced.contracts import ProbeUnreachable
from ced.probe import Evaluator

ADAPTER = Http1FramingAdapter()
FRONT = Path(__file__).resolve().parent / "fixtures" / "standin_front.py"
NGINX_LIKE_FRONT = Path(__file__).resolve().parent / "fixtures" / "nginx_like_front.py"
SILENT_DROP_FRONT = Path(__file__).resolve().parent / "fixtures" / "silent_drop_front.py"
HOST_GATE_FRONT = Path(__file__).resolve().parent / "fixtures" / "host_gate_front.py"
DEVNULL = subprocess.DEVNULL


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


class TestChainE2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.probe_data = _free_port()
        cls.probe_api = _free_port()
        cls.probe = subprocess.Popen(
            [sys.executable, "-m", "ced.probe.server",
             "--policy", "ref-cl-first",
             "--data-port", str(cls.probe_data),
             "--api-port", str(cls.probe_api)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        try:
            _wait_port(cls.probe_api)
        except unittest.SkipTest:
            cls.probe.terminate()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        _stop(cls.probe)

    # ---------------------------------------------------------------- 工具

    def _start_front(self, mode: str, upstream: int | None = None) -> int:
        """起替身前置；``upstream`` 缺省指向本测试的探针数据口。

        传一个没人监听的端口 = 复现"前置活着但上游不通"，用来验证
        「链路真故障必须仍然中止」这条底线不被活性复探削弱。
        """
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(FRONT), mode, str(port),
             str(self.probe_data if upstream is None else upstream)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)
        return port

    def _start_nginx_like_front(self) -> tuple[int, Path]:
        """起一个"吃不下客户端立即半关闭"的前置（见 fixtures/nginx_like_front.py）。

        返回 (端口, 连接计数文件) —— 计数文件用来验证"模式被记住、只多花一次连接"。
        """
        port = _free_port()
        counter = Path(tempfile.mkdtemp()) / "connections.txt"
        proc = subprocess.Popen(
            [sys.executable, str(NGINX_LIKE_FRONT), str(port),
             str(self.probe_data), str(counter)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)
        return port, counter

    def _evaluator(self, front_port: int) -> Evaluator:
        """链路侧 = 前置 → 探针（探针用的是 ref-cl-first 策略）；
        基准侧 = 直接跑 ref-cl-first。

        所以两侧的"解析器"是同一个 —— 任何分歧都只能来自**前置改写了字节**。
        """
        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="front", name="front", role="front", runner="chain",
                     endpoint=f"127.0.0.1:{front_port}",
                     probe_api=f"127.0.0.1:{self.probe_api}"),
            ImplSpec(impl_id="ref-cl-first", name="ref-cl-first", role="solo",
                     runner="local", policy="ref-cl-first"),
        ])
        return Evaluator(topo.impls)

    # ---------------------------------------------------------------- 用例

    def test_transparent_front_yields_no_divergence(self):
        """透明前置：所有观测都必须与基线一致 —— 一个假阳性都不许有。"""
        evaluator = self._evaluator(self._start_front("pass"))
        result = scan(ADAPTER, evaluator, mode="cross", limit=24, do_minimize=False)
        self.assertEqual(len(result.divergences), 0,
                         f"透明前置下出现假阳性：{result.divergences[:3]}")
        self.assertEqual(len(result.findings), 0)

    def test_rewriting_front_is_detected(self):
        """会改写 Content-Length 的前置必须被检出，且分歧落在 CL 相关字段上。"""
        evaluator = self._evaluator(self._start_front("rewrite_cl"))
        result = scan(ADAPTER, evaluator, mode="cross", limit=60, do_minimize=False)
        self.assertGreater(len(result.divergences), 0, "改写前置未被检出")
        structural = {"cl", "framing_source", "body_len", "consumed", "leftover_len"}
        for f in result.findings:
            self.assertTrue(structural & set(f.divergence.keys),
                            f"{f.case_id} 的分歧不在结构字段上：{f.divergence.keys}")

    def test_unreachable_front_raises_instead_of_fabricating(self):
        """前置端口没人监听 → 必须抛错；绝不能合成观测产出"发现"。"""
        evaluator = self._evaluator(_free_port())
        with self.assertRaises(ProbeUnreachable):
            scan(ADAPTER, evaluator, mode="cross", limit=6, do_minimize=False)

    def test_front_that_forwards_nothing_is_skipped_not_fabricated(self):
        """前置收下字节但不转发 → **跳过并计数**。

        真实前置（nginx / Envoy）对畸形请求返回 4xx 且不向后端转发，属正常行为；
        若当链路故障处理，一轮扫描会在第一条畸形请求上崩掉，对真实产品完全不可用。
        但跳过必须计数，且**绝不允许合成一个"看起来像观测"的后端视角**。
        """
        evaluator = self._evaluator(self._start_front("drop"))
        result = scan(ADAPTER, evaluator, mode="cross", limit=6, do_minimize=False)
        self.assertEqual(len(result.findings), 0, "不可观测的用例不许产出发现")
        self.assertGreater(result.rejected_cases, 0, "跳过必须计数，不许静默")

    def test_front_that_cannot_take_client_half_close(self):
        """吃不下"客户端立即半关闭"的前置 → 链路器自动降级，而不是判成链路不可用。

        本机实测（docker 里的 nginx:1.25-alpine，见 docker/README.md）：
          客户端发完立即 shutdown(SHUT_WR) → nginx 既不转发也不回响应（0.0s 断开）；
          改成不半关闭（curl 的做法）      → 正常转发。
        所以链路器必须在第一次观测失败后自己换模式，否则真实链路永远扫不了。
        """
        port, counter = self._start_nginx_like_front()
        evaluator = self._evaluator(port)
        result = scan(ADAPTER, evaluator, mode="cross", limit=24, do_minimize=False)

        # 这个前置除"吃不下半关闭"之外是透明的 → 一个分歧都不许有
        self.assertEqual(len(result.divergences), 0,
                         f"这个前置是透明的，不该出现分歧：{result.divergences[:2]}")
        self.assertEqual(len(result.findings), 0)

        # 模式要被记住：只有第一次观测会白试一遍半关闭，后续用例直连正确模式
        conns = len(counter.read_text(encoding="utf-8").split())
        self.assertLess(conns, 2 * result.total_cases,
                        f"每个用例都重试了一遍（模式没被记住）：{conns} 次连接 / "
                        f"{result.total_cases} 个用例")

    def test_silently_dropping_front_is_skipped_not_aborted(self):
        """前置**静默丢掉**某几条请求（真 gunicorn 对裸 LF / 大写块长就是这样：
        不转发、不回响应、直接关连接）→ 必须跳过并计数，而不是判成链路故障中止。

        判据是链路活性：链路器再拿一条最小正常请求走一遍，探针还能记到视角
        = 链路活着 = 这条请求只是"该前置不接受"。
        """
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(SILENT_DROP_FRONT), str(port), str(self.probe_data)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)

        evaluator = self._evaluator(port)
        result = scan(ADAPTER, evaluator, mode="cross", limit=24, do_minimize=False)

        # 这个前置只对"裸 LF"那几条静默丢弃，其余透明 → 不该有分歧
        self.assertEqual(len(result.divergences), 0,
                         f"其余请求应当被正常转发：{result.divergences[:2]}")
        self.assertGreater(result.rejected_cases, 0,
                           "静默丢弃的那几条必须被跳过并计数，不许静默、也不许中止")

    def test_front_with_dead_upstream_still_aborts(self):
        """前置活着但上游不通 → **必须仍然中止**（活性复探不得把它降级成"跳过"）。

        这是最要紧的底线：一旦把"前置转不过去"也当成"这条请求不接受"，
        一轮扫不出任何东西的报告就会看起来正常 —— 那正是本项目最想避免的假阴性。
        """
        evaluator = self._evaluator(self._start_front("pass", upstream=_free_port()))
        with self.assertRaises(ProbeUnreachable) as ctx:
            scan(ADAPTER, evaluator, mode="cross", limit=6, do_minimize=False)
        self.assertIn("没有把任何字节转发", str(ctx.exception))

    def test_probe_control_api_unreachable_raises(self):
        """前置活着但探针控制口不可达 → 报错必须指明是探针的问题。"""
        port = self._start_front("pass")
        topo = Topology(domain="http1-framing", impls=[
            ImplSpec(impl_id="front", name="front", role="front", runner="chain",
                     endpoint=f"127.0.0.1:{port}",
                     probe_api=f"127.0.0.1:{_free_port()}"),
            ImplSpec(impl_id="ref-cl-first", name="ref-cl-first", role="solo",
                     runner="local", policy="ref-cl-first"),
        ])
        with self.assertRaises(ProbeUnreachable) as ctx:
            scan(ADAPTER, Evaluator(topo.impls), mode="cross", limit=4,
                 do_minimize=False)
        self.assertIn("探针控制口", str(ctx.exception))


class TestFrontAdaptive(unittest.TestCase):
    """前置自适应：缺 Host 的请求被门禁前置拒绝 → 引擎补 Host 重试，
    观测带 ``front_adapted`` 标记；实机量化直接用实测字节。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.probe_data = _free_port()
        cls.probe_api = _free_port()
        cls.probe = subprocess.Popen(
            [sys.executable, "-m", "ced.probe.server",
             "--policy", "ref-cl-first",
             "--data-port", str(cls.probe_data),
             "--api-port", str(cls.probe_api)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        try:
            _wait_port(cls.probe_api)
        except unittest.SkipTest:
            cls.probe.terminate()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        _stop(cls.probe)

    def _start_host_gate_front(self) -> int:
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(HOST_GATE_FRONT), str(port), str(self.probe_data)],
            cwd=str(ROOT), stdout=DEVNULL, stderr=DEVNULL)
        self.addCleanup(_stop, proc)
        _wait_port(port)
        return port

    def test_hostless_request_is_adapted_and_marked(self):
        """缺 Host 的请求：先被拒（400），补 Host 重试后可观测，且带标记。"""
        from ced.probe.chain import ChainEvaluator

        port = self._start_host_gate_front()
        ev = ChainEvaluator(f"127.0.0.1:{port}", f"127.0.0.1:{self.probe_api}")
        payload = (b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")
        obs = ev("front", payload)
        self.assertEqual(obs.fields.get("front_adapted"), "补 Host 头",
                         f"自适应重试没有发生：{obs.fields}")
        self.assertGreater(obs.fields.get("forwarded_raw_len") or 0, 0,
                           "实转字节数没有进观测")

    def test_real_quantification_uses_measured_bytes(self):
        """实机量化：from链路观测的实测字段算夹带，不经过模型。"""
        from ced.contracts import Divergence, Observation
        from ced.probe.chain import ChainEvaluator

        port = self._start_host_gate_front()
        ev = ChainEvaluator(f"127.0.0.1:{port}", f"127.0.0.1:{self.probe_api}")
        payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
        obs = ev("front", payload)

        div = Divergence(case_id="t0000001", axis="test", payload=payload,
                         left=obs, right=Observation(impl_id="ref-cl-first"))
        quant = ADAPTER.quantify(payload, "front", "ref-cl-first", div=div)
        self.assertIsNotNone(quant, "有实测字段却返回了未量化")
        self.assertIn("实机测量", quant.describe)
        forwarded, back_consumed, smuggled = quant.numbers
        self.assertEqual(forwarded, obs.fields["forwarded_raw_len"])
        self.assertEqual(back_consumed, obs.fields.get("consumed") or 0)
        self.assertGreaterEqual(smuggled, 0)

    def test_variant_never_touches_present_host(self):
        """带 Host 的请求不该被变形（改了就是伪造客户行为）。"""
        from ced.probe.chain import ChainEvaluator

        ev = ChainEvaluator("127.0.0.1:1", "127.0.0.1:2")
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        self.assertEqual(ev._variants(payload), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
