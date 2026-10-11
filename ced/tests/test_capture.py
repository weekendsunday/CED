"""自动捕获的测试（不需要 Docker，不需要外网）。

覆盖的都是**消费者可见的行为**：
  * 明文 HTTP：请求被原样记录 + 被转发到真实站点（且记录与分析对象是客户端原样字节）
  * CONNECT：只记一条"未拆"，隧道照常双向直通（不假装能看 HTTPS 明文）
  * 同一份字节重复出现 → 只分析一次、计数累加
  * 静态资源默认跳过（不分析、但也不影响转发）
  * 分析层：一条请求同时喂 5 个领域；无歧义请求零分歧（防假阳性）
"""
from __future__ import annotations

import base64
import json
import socket
import sys
import tempfile
import threading
import ssl
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced.capture import Config, analyze
from ced.capture import mitm as _mitm_mod
from ced.capture.proxy import CaptureProxy
from ced.web.server import _bind


def _post(base: str, path: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(base + path, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))

BENIGN = (b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc")
#: 同一个"正常请求"，但上游指向一个必然拒绝的端口 —— 转发立刻失败，测试不用等超时
FAST = (b"POST /a HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 3\r\n\r\nabc")
CL_TE = (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 48\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
         b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(predicate, timeout: float = 15.0, step: float = 0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(step)
    return False


class _RawOrigin(threading.Thread):
    """最小 origin：把收到的字节记下来，回一个固定响应（不够聪明，够测试用）。"""

    def __init__(self, port: int, reply: bytes = b"ok") -> None:
        super().__init__(daemon=True)
        self.port = port
        self.reply = reply
        self.received: list[bytes] = []
        self.stop = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(8)
        self.srv.settimeout(0.2)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(0.4)
                buf = b""
                try:
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                        if b"\r\n\r\n" in buf and self._body_done(buf):
                            break
                except socket.timeout:
                    pass
                self.received.append(buf)
                body = self.reply
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n"
                             + body)

    @staticmethod
    def _body_done(buf: bytes) -> bool:
        head, _, body = buf.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    return len(body) >= int(line.split(b":", 1)[1].strip())
                except ValueError:
                    return True
        return True

    def close(self) -> None:
        self.stop.set()
        try:
            self.srv.close()
        except OSError:
            pass


class _ProxyHarness:
    """把代理跑在后台线程里，测试直接对它发原始字节。"""

    def __init__(self, **kwargs) -> None:
        self.port = _free_port()
        self.seen: list[dict] = []
        self.cfg = Config(port=self.port, on_result=self.seen.append, **kwargs)
        self.proxy = CaptureProxy(self.cfg)
        self.thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.thread.start()
        _wait(lambda: self._up(), timeout=5)

    def _up(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                return True
        except OSError:
            return False

    def send(self, payload: bytes, read: bool = True) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(payload)
            if not read:
                return b""
            s.settimeout(5)
            buf = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass
            return buf

    def close(self) -> None:
        self.cfg.stop.set()
        self.thread.join(timeout=5)


class TestCaptureProxy(unittest.TestCase):

    def setUp(self) -> None:
        self.origin_port = _free_port()
        self.origin = _RawOrigin(self.origin_port)
        self.origin.start()
        self.harness = _ProxyHarness()
        self.addCleanup(self.harness.close)
        self.addCleanup(self.origin.close)

    def test_plain_http_is_recorded_analyzed_and_forwarded(self):
        """明文请求：原样转发到真实站点 + 被记录 + 拿到分析结果。"""
        response = self.harness.send(
            b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
            % self.origin_port)
        self.assertIn(b"200 OK", response, "代理没有把上游的响应回给客户端")
        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1), "没有产生记录")
        self.assertTrue(self.origin.received, "代理没有把请求转发到真实站点")
        forwarded = self.origin.received[0]
        self.assertIn(b"GET /hello HTTP/1.1", forwarded)
        self.assertIn(b"Connection: close", forwarded)
        record = self.harness.seen[0]
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["path"], "/hello")
        self.assertTrue(_wait(lambda: record.get("analysis")))
        self.assertEqual(record["analysis"]["case_id"], record["case_id"])
        self.assertIn("http1-framing", record["analysis"]["domains"])

    def test_connect_is_recorded_as_tunnel_and_not_decrypted(self):
        """HTTPS 隧道直通（--no-mitm / 未装可选依赖时的行为）：记一条「未拆」，双向能通。"""
        echo_port = _free_port()
        stop = threading.Event()

        def echo() -> None:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", echo_port))
            srv.listen(4)
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    data = conn.recv(4096)
                    conn.sendall(data)
            srv.close()

        threading.Thread(target=echo, daemon=True).start()
        self.addCleanup(stop.set)

        harness = _ProxyHarness(mitm=False)          # 这个用例专门验「不拆包」路径
        self.addCleanup(harness.close)
        with socket.create_connection(("127.0.0.1", harness.port), timeout=10) as s:
            s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                      % (echo_port, echo_port))
            s.settimeout(5)
            head = s.recv(4096)
            self.assertIn(b"200 Connection Established", head)
            s.sendall(b"PING-THROUGH-TUNNEL")
            self.assertEqual(s.recv(4096), b"PING-THROUGH-TUNNEL")

        self.assertTrue(_wait(lambda: len(harness.seen) >= 1))
        record = harness.seen[0]
        self.assertTrue(record["tunnel"])
        self.assertIsNone(record["analysis"])
        self.assertIn("不拆包", record["skip"])

    def test_connect_mitm_decrypts_into_diff_pipeline(self):
        """默认配置（装有 cryptography）：CONNECT 被本地 CA 解密，明文请求进差分管线。"""
        if not _mitm_mod.mitm_available():
            self.skipTest("未装 cryptography（可选依赖），MITM 不可用")
        _mitm_mod.ensure_ca()
        _mitm_mod.leaf_context("127.0.0.1")          # 预签发叶子证书，上游服务器要用

        up_port = _free_port()
        stop = threading.Event()
        upstream_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        upstream_ctx.load_cert_chain(_mitm_mod.HOSTS_DIR / "127.0.0.1.crt",
                                     _mitm_mod.HOSTS_DIR / "127.0.0.1.key.pem")

        def tls_origin() -> None:
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", up_port))
            srv.listen(4)
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    with upstream_ctx.wrap_socket(conn, server_side=True) as tls:
                        data = tls.recv(4096)
                        body = b'{"ok":true}'
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                                    % (len(body), body))
                except (OSError, ssl.SSLError):
                    pass
            srv.close()

        threading.Thread(target=tls_origin, daemon=True).start()
        self.addCleanup(stop.set)

        with socket.create_connection(("127.0.0.1", self.harness.port), timeout=10) as s:
            s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                      % (up_port, up_port))
            s.settimeout(5)
            head = s.recv(4096)
            self.assertIn(b"200 Connection Established", head)
            tls = ssl.create_default_context(cafile=str(_mitm_mod.CA_CERT))
            with tls.wrap_socket(s, server_hostname="127.0.0.1") as secure:
                secure.sendall(b"GET /api/pay HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                secure.settimeout(5)
                resp = secure.recv(4096)
            self.assertIn(b'{"ok":true}', resp, "响应没有从 TLS 上游中继回来")

        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1))
        record = [r for r in self.harness.seen if r.get("mitm")][-1]
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["path"], "/api/pay")
        self.assertTrue(_wait(lambda: record.get("analysis")), "解密后的请求没有进差分")
        self.assertIn("http1-framing", record["analysis"]["domains"])

    def test_unreachable_connect_is_still_recorded(self):
        """CONNECT 到连不上的上游：也要**留下记录**（"我看到了什么"必须如实记），并回 502。"""
        with socket.create_connection(("127.0.0.1", self.harness.port), timeout=10) as sock:
            sock.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            sock.settimeout(5)
            head = sock.recv(4096)
        self.assertIn(b"502", head)
        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1), "连不上就不记了？")
        record = self.harness.seen[-1]
        self.assertTrue(record["tunnel"])
        self.assertIn("不可达", record["skip"])
        self.assertIn("127.0.0.1:1", record["target"])

    def test_same_bytes_are_analyzed_once(self):
        """同一份字节再来一次 → 只计数，不重复分析。"""
        request = (b"GET /dup HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
                   % self.origin_port)
        for _ in range(3):
            self.harness.send(request)
        self.assertTrue(_wait(lambda: self.harness.seen
                              and self.harness.seen[-1]["count"] == 3), "计数没有累加")
        analyzed = [r for r in self.harness.proxy.records if r.get("analysis")]
        self.assertEqual(len(analyzed), 1, "同一份字节被重复分析了")

    def test_static_assets_are_skipped_by_default(self):
        self.harness.send(b"GET /app.css HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n" % self.origin_port)
        self.assertTrue(_wait(lambda: len(self.harness.seen) >= 1))
        record = self.harness.seen[0]
        self.assertEqual(record["skip"], "静态资源")
        self.assertIsNone(record["analysis"])
        self.assertTrue(self.origin.received, "跳过分析不等于不转发")

    def test_absolute_form_is_normalized_before_analysis(self):
        """代理形式的请求行必须归一化成源站形式再分析。

        实测数字就是这条归一化存在的理由：
          绝对形式（代理原样）→ 19 条"安全级"（8 分帧 + 11 路径，全是部署位置带来的假阳性）
          源站形式（归一化后）→ 0 条
        原始字节仍然留证（raw_b64 / target），只是"分析对象"换成源站会看到的那份。
        """
        absolute = (b"GET http://127.0.0.1:%d/plain HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                    b"Proxy-Connection: keep-alive\r\n\r\n"
                    % (self.origin_port, self.origin_port))
        self.assertGreater(analyze(absolute).security, 0,
                           "前提不成立：绝对形式请求行本应触发 request-line-absolute-uri 分歧")

        self.harness.send(absolute)
        self.assertTrue(_wait(lambda: self.harness.seen
                              and self.harness.seen[-1].get("analysis")), "没有分析结果")
        record = self.harness.seen[-1]
        self.assertTrue(record["normalized"], "代理形式的请求行没有被归一化")
        self.assertEqual(record["analysis"]["divergences"], 0,
                         f"归一化后仍有分歧：{record['analysis']}")
        self.assertEqual(record["analysis"]["security"], 0)
        self.assertIn(b"http://", base64.b64decode(record["raw_b64"]), "原始字节没有留证")
        self.assertIn("http://", record["target"])

    def test_summary_counts_add_up(self):
        self.harness.send(b"GET /one HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n" % self.origin_port)
        self.assertTrue(_wait(lambda: self.harness.proxy.summary()["analyzed"] >= 1))
        parts = self.harness.proxy.summary()
        self.assertEqual(parts["requests"], 1)
        self.assertEqual(parts["analyzed"], 1)
        self.assertEqual(parts["tunnels"], 0)


class TestAnalyzeFanout(unittest.TestCase):

    def test_benign_request_has_no_divergence(self):
        """无歧义的正常请求：一个分歧都不许有（防假阳性）。"""
        result = analyze(BENIGN)
        self.assertEqual(result.divergences, 0,
                         f"正常请求出现假阳性：{result.to_dict()}")
        self.assertEqual(result.level, "none")

    def test_one_request_is_fanned_out_to_all_domains(self):
        """同一条请求要同时喂给 5 个领域（靠适配器的 extract 各自取段）。"""
        result = analyze(CL_TE)
        self.assertEqual(set(result.domains), {
            "http1-framing", "url-norm", "host-norm", "query-norm", "enc-norm"})
        self.assertGreater(result.divergences, 0, "CL+TE 应当被判出分歧")
        self.assertGreater(result.security, 0, "CL+TE 应当被判成安全级")
        self.assertIsNotNone(result.top)
        self.assertEqual(result.top.level, "security")
        self.assertEqual(result.top.case_id, result.case_id)

    def test_domain_subset_is_respected(self):
        result = analyze(CL_TE, domains=["http1-framing"])
        self.assertEqual(list(result.domains), ["http1-framing"])


class TestCaptureWebApi(unittest.TestCase):
    """网页接口：起 / 停 / 记录 / 详情 / 一键 PoC —— 走真 HTTP，不 mock。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._httpd = _bind("127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls._httpd.server_address[1]}"
        threading.Thread(target=cls._httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def setUp(self) -> None:
        import ced.capture.web as capture_web
        from ced import settings as app_settings

        from ced.web.server import CAPTURE

        CAPTURE.stop()                      # 每个用例从干净状态开始
        self.addCleanup(CAPTURE.stop)
        self.port = _free_port()
        # 设置文件也要隔离：起捕获现在会回落「设置」里的默认值，
        # 读到开发机上那份真实配置就会让用例依赖环境。
        scratch_settings = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(scratch_settings.cleanup)
        self._old_settings = app_settings.SETTINGS_PATH
        app_settings.SETTINGS_PATH = Path(scratch_settings.name) / "ced-settings.json"
        self.addCleanup(lambda: setattr(app_settings, "SETTINGS_PATH", self._old_settings))
        # PoC 落到临时目录，别污染仓库的 results/pocs
        scratch = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(scratch.cleanup)
        self._old_poc_dir = capture_web.POC_DIR
        capture_web.POC_DIR = Path(scratch.name)
        self.addCleanup(lambda: setattr(capture_web, "POC_DIR", self._old_poc_dir))

    def _drive(self, payload: bytes) -> None:
        """把一条原始字节送进代理（上游不存在也行：记录照收、分析照跑）。"""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(payload)
            sock.settimeout(5)
            try:
                while sock.recv(65536):
                    pass
            except socket.timeout:
                pass

    def _start(self, domains=None) -> dict:
        status, body = _post(self.base, "/api/capture/start",
                             {"port": self.port, "domains": domains or []})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        return body

    def test_conflicts_and_bad_domains_are_reported_at_once(self):
        """端口冲突 / 领域写错都要当场报错，而不是死在后台线程里。"""
        status, body = _post(self.base, "/api/capture/start", {"port": self.port})
        self.assertEqual(status, 200)
        status, body = _post(self.base, "/api/capture/start", {"port": self.port})
        self.assertEqual(status, 400)
        self.assertIn("已经在跑", body["error"])

        status, body = _post(self.base, "/api/capture/start",
                             {"port": self.port + 1, "domains": ["不存在的领域"]})
        self.assertEqual(status, 400)
        self.assertIn("未知领域", body["error"])

        status, body = _get(self.base, "/api/capture/state")
        self.assertTrue(body["running"], "报错不该把已经跑起来的代理弄停")

    def test_records_detail_and_poc(self):
        """完整链路：起 → 收 → 看详情 → 一键出 PoC → 停。"""
        self._start(["http1-framing"])
        self._drive(CL_TE)

        def analyzed() -> bool:
            records = _get(self.base, "/api/capture/records?since=0")[1]["records"]
            return bool(records and records[0].get("analysis"))

        self.assertTrue(_wait(analyzed), "没有分析出结果")

        _, body = _get(self.base, "/api/capture/records?since=0")
        self.assertEqual(body["summary"]["analyzed"], 1)
        self.assertGreater(body["summary"]["divergences"], 0)
        case_id = body["records"][0]["case_id"]

        _, detail = _get(self.base, f"/api/capture/record?case_id={case_id}")
        self.assertEqual(detail["case_id"], case_id)
        self.assertIn(b"Transfer-Encoding", base64.b64decode(detail["raw_b64"])
                      + detail["raw_preview"].encode())

        _, poc = _post(self.base, "/api/capture/poc", {"case_id": case_id})
        self.assertTrue(poc["ok"], poc)
        self.assertTrue(Path(poc["path"]).is_file(), "PoC 脚本没有落盘")
        self.assertEqual(poc["cwe"], "CWE-444")
        self.assertTrue(poc["steps"], "PoC 应当带复现步骤")

        _, stopped = _post(self.base, "/api/capture/stop", {})
        self.assertFalse(stopped["running"])
        _, state = _get(self.base, "/api/capture/state")
        self.assertFalse(state["running"])

    def test_duplicate_counts_are_exposed_for_the_ui(self):
        """重复请求只分析一次，并把次数通过 counts 给前端刷新 ×N。"""
        self._start(["http1-framing"])
        for _ in range(3):
            self._drive(FAST)                # 同一份字节三次
        self.assertTrue(_wait(lambda: _get(self.base, "/api/capture/records")[1]
                              .get("counts")), "counts 没有回传")
        _, body = _get(self.base, "/api/capture/records?since=0")
        self.assertEqual(len(body["records"]), 1, "同一份字节只该有一条记录")
        case_id = body["records"][0]["case_id"]
        self.assertEqual(body["counts"].get(case_id), 3)
        self.assertEqual(body["summary"]["analyzed"], 1, "只该分析一次")

    def test_poc_on_unknown_case_is_a_readable_error(self):
        self._start(["http1-framing"])
        status, body = _post(self.base, "/api/capture/poc", {"case_id": "deadbeef"})
        self.assertEqual(status, 400)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
