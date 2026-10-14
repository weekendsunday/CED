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
import os
import socket
import sys
import tempfile
import threading
import ssl
import shutil
import subprocess
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ced.capture import Config, analyze
from ced.capture import mitm as _mitm_mod
from ced.capture import proxy as capture_proxy
from ced.capture import trust as capture_trust
from ced.capture import web as capture_web
from ced.capture.proxy import CaptureProxy
from ced.web import server as web_server
from ced.web.server import _bind
from ced import settings as app_settings


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


def _isolated_ca(case: unittest.TestCase) -> Path:
    """每个证书用例独占目录与上下文缓存，避免触碰用户的 CA。"""
    scratch = Path(case.enterContext(tempfile.TemporaryDirectory()))
    for attr, value in (("CA_DIR", scratch), ("CA_CERT", scratch / "ca.crt"),
                        ("CA_KEY", scratch / "ca.key.pem"),
                        ("HOSTS_DIR", scratch / "hosts"), ("_LEAF_CACHE", {})):
        case.enterContext(mock.patch.object(_mitm_mod, attr, value))
    return scratch


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


class _TlsOrigin(threading.Thread):
    """最小 TLS origin：拿本地 CA 签的叶子证书起一个能握手的 HTTPS 端口。"""

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        super().__init__(daemon=True)
        self.port = port
        self.stop = threading.Event()
        self.ctx = _mitm_mod.leaf_context(host)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(4)
        self.srv.settimeout(0.2)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)
            except (OSError, ssl.SSLError):
                pass

    def close(self) -> None:
        self.stop.set()
        try:
            self.srv.close()
        except OSError:
            pass


class _DeadTlsOrigin(threading.Thread):
    """端口通、但接了 TCP 就不说话（立刻断开）—— 模拟"TLS 被网络重置"。"""

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.stop = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(4)
        self.srv.settimeout(0.2)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.close()

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
        _isolated_ca(self)
        if _mitm_mod.mitm_available():
            _mitm_mod.ensure_ca()
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
            tls.verify_flags |= ssl.VERIFY_X509_STRICT
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

    def test_upstream_tls_failure_is_not_blamed_on_client(self):
        """上游 TLS 握不上（端口通、握手被重置）→ 记「上游到不了」，不许赖客户端。

        这是踩过的坑：直连被墙 / 上游代理节点不通时，异常也是 ``ssl.SSLError``，
        早先和"客户端证书固定"共用一句话，排"HTTPS 为什么不拆包"时被带偏。
        """
        if not _mitm_mod.mitm_available():
            self.skipTest("未装 cryptography（可选依赖），MITM 不可用")
        _mitm_mod.ensure_ca()
        dead_port = _free_port()
        dead = _DeadTlsOrigin(dead_port)
        dead.start()
        self.addCleanup(dead.close)

        with socket.create_connection(("127.0.0.1", self.harness.port), timeout=10) as s:
            s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                      % (dead_port, dead_port))
            s.settimeout(5)
            self.assertIn(b"200 Connection Established", s.recv(4096))

        self.assertTrue(_wait(lambda: self.harness.seen), "连不上也得留记录")
        record = self.harness.seen[-1]
        self.assertTrue(record["tunnel"])
        self.assertEqual(record["tunnel_failed"], "upstream")
        self.assertIn("上游", record["skip"])
        self.assertNotIn("客户端拒绝", record["skip"], "网络的锅扣到客户端头上了")
        self.assertEqual(self.harness.proxy.summary()["upstream_failed"], 1)
        self.assertEqual(self.harness.proxy.summary()["tls_failed"], 0)

    def test_client_rejecting_local_ca_is_recorded_as_such(self):
        """上游好好的、是客户端拒绝了我们的证书 → 记「客户端拒绝本地 CA」。

        真机上很难造出"证书固定"的客户端：macOS 的 Python 走系统信任评估，本机
        钥匙串一旦信任了本地 CA，客户端反而会认它（甚至连空信任库都能握手成功）。
        所以这里只让**客户端侧那次握手**抛 ``ssl.SSLError`` —— 验的是**归因**：
        上游没问题时，失败必须记在客户端头上，而不是又写成"上游/网络"。
        """
        if not _mitm_mod.mitm_available():
            self.skipTest("未装 cryptography（可选依赖），MITM 不可用")
        _mitm_mod.ensure_ca()
        _mitm_mod.leaf_context("127.0.0.1")
        up_port = _free_port()
        origin = _TlsOrigin(up_port)
        origin.start()
        self.addCleanup(origin.close)

        class _Rejecting:
            """冒充"拒绝了本地 CA"的客户端侧握手。"""

            @staticmethod
            def wrap_socket(*_args, **_kwargs):
                raise ssl.SSLError("模拟客户端拒绝本地 CA")

        with mock.patch.object(_mitm_mod, "leaf_context", lambda _host: _Rejecting()):
            with socket.create_connection(("127.0.0.1", self.harness.port),
                                          timeout=10) as s:
                s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                          % (up_port, up_port))
                s.settimeout(5)
                self.assertIn(b"200 Connection Established", s.recv(4096))

        self.assertTrue(_wait(lambda: self.harness.seen), "拒了也得留记录")
        record = self.harness.seen[-1]
        self.assertTrue(record["tunnel"])
        self.assertEqual(record["tunnel_failed"], "client")
        self.assertIn("客户端拒绝本地 CA", record["skip"])
        self.assertEqual(self.harness.proxy.summary()["tls_failed"], 1)
        self.assertEqual(self.harness.proxy.summary()["upstream_failed"], 0)

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


class TestMitmCertificates(unittest.TestCase):

    def setUp(self) -> None:
        if not _mitm_mod.mitm_available():
            self.skipTest("未装 cryptography（可选依赖）")
        _isolated_ca(self)
        _mitm_mod.ensure_ca()

    def _strict_peer(self, host: str) -> bytes:
        origin = _TlsOrigin(_free_port(), host)
        origin.start()
        self.addCleanup(origin.close)
        client_context = ssl.create_default_context(cafile=str(_mitm_mod.CA_CERT))
        client_context.verify_flags |= ssl.VERIFY_X509_STRICT
        with socket.create_connection(("127.0.0.1", origin.port), timeout=5) as raw:
            with client_context.wrap_socket(raw, server_hostname=host) as secure:
                return secure.getpeercert(binary_form=True)

    def test_generated_certificates_pass_strict_ip_and_dns_verification(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        for host in ("127.0.0.1", "capture.example"):
            with self.subTest(host=host):
                peer = self._strict_peer(host)
                expected = x509.load_pem_x509_certificate(
                    (_mitm_mod.HOSTS_DIR / f"{host}.crt").read_bytes())
                self.assertEqual(peer, expected.public_bytes(serialization.Encoding.DER))

    def test_legacy_cached_leaf_is_reissued_with_the_same_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization

        host = "127.0.0.1"
        _mitm_mod.leaf_context(host)
        cert_path = _mitm_mod.HOSTS_DIR / f"{host}.crt"
        old = x509.load_pem_x509_certificate(cert_path.read_bytes())
        ca_bytes = _mitm_mod.CA_CERT.read_bytes()
        ca_key = serialization.load_pem_private_key(_mitm_mod.CA_KEY.read_bytes(), None)
        builder = (x509.CertificateBuilder().subject_name(old.subject)
                   .issuer_name(old.issuer).public_key(old.public_key())
                   .serial_number(old.serial_number)
                   .not_valid_before(old.not_valid_before_utc)
                   .not_valid_after(old.not_valid_after_utc))
        for ext in old.extensions:
            if not isinstance(ext.value, x509.AuthorityKeyIdentifier):
                builder = builder.add_extension(ext.value, ext.critical)
        legacy = builder.sign(ca_key, hashes.SHA256())
        cert_path.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
        (_mitm_mod.HOSTS_DIR / f"{host}.chain.crt").write_bytes(
            cert_path.read_bytes() + ca_bytes)
        _mitm_mod._LEAF_CACHE.clear()  # 模拟旧版退出后，新版进程加载磁盘证书。

        peer = x509.load_der_x509_certificate(self._strict_peer(host))
        self.assertNotEqual(peer.serial_number, old.serial_number)
        self.assertEqual(_mitm_mod.CA_CERT.read_bytes(), ca_bytes)


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

class TestCaptureCaTrustApi(unittest.TestCase):
    """证书信任入口的网页接口。单独一个类：这批用例只碰 /api/capture/ca/*，
    不需要代理生命周期那套隔离。"""

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
        _isolated_ca(self)

    def test_ca_status_is_a_readable_state(self):
        """证书状态给的是**状态名**，不是让前端自己猜——前端只按 state 分支。"""
        status, body = _get(self.base, "/api/capture/ca/status")
        self.assertEqual(status, 200, body)
        self.assertIn(body["state"], {"no_dependency", "missing", "trusted",
                                     "untrusted", "unknown", "unsupported"})
        self.assertIn("title", body)
        self.assertIn("note", body)
        self.assertEqual(body["platform"], capture_trust.PLATFORM)
        # 有依赖时状态与该平台上「到底信任没信任」必须自洽
        if body["state"] not in ("no_dependency", "unsupported"):
            self.assertIsInstance(body["trusted"], bool)

    def test_ca_download_serves_the_certificate_itself(self):
        """兜底路径：一键失败 / 平台不支持时，人还能把证书下载下来双击安装。"""
        if not capture_trust.mitm.mitm_available():
            self.skipTest("未装 cryptography（可选依赖）")
        with urllib.request.urlopen(self.base + "/api/capture/ca", timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("x-x509-ca-cert", resp.headers.get("Content-Type", ""))
            self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
            body = resp.read()
        self.assertTrue(body.startswith(b"-----BEGIN CERTIFICATE-----"), "必须是真证书")
        self.assertEqual(body, capture_trust.mitm.CA_CERT.read_bytes(), "原样发，不改一个字节")

    def test_ca_trust_requires_explicit_confirm(self):
        """改本机信任库是危险动作：没有 confirm 一律拒绝（防被网页静默触发）。"""
        status, body = _post(self.base, "/api/capture/ca/trust", {"undo": False})
        self.assertEqual(status, 400)
        self.assertIn("confirm", body["error"])
        status, body = _post(self.base, "/api/capture/ca/trust", {"confirm": "yes"})
        self.assertEqual(status, 400, "字符串 'yes' 不算确认，必须是真的布尔")

    def test_ca_trust_never_runs_a_command_it_did_not_plan(self):
        """走 HTTP 的整条链路也要能被拦住：测试里把执行器换掉，断言只执行 plan()。

        **绝不能**让用例真的去改开发机的信任库 —— 所以这里替换 _run，
        断言「发出去的命令」就是 plan() 那一份。
        """
        ran: list[list[str]] = []
        canned = subprocess.CompletedProcess(["security"], 0, "ok", "")
        with mock.patch.object(capture_trust, "_run",
                               side_effect=lambda argv: (ran.append(argv), canned)[1]):
            status, body = _post(self.base, "/api/capture/ca/trust", {"confirm": True})
        if body.get("error") and "没有一键入口" in body["error"]:
            self.skipTest("当前平台没有一键入口")
        self.assertTrue(body["ok"], body)
        self.assertTrue(ran, "命令没发出去")
        self.assertEqual(ran[0], capture_trust.plan())



def _make_ca(cn: str, *, ca: bool = True, days: int = 365):
    """现造一对（证书, 私钥）PEM —— 用例里当"别人的 CA"用，不碰本机那张真 CA。"""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=True, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                         encipher_only=False, decipher_only=False),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class TestCaptureCaImportApi(unittest.TestCase):
    """导入别人的 CA + 清理已签发的叶子证书。

    这批量身定制的隔离：**整个 CA 目录挪到临时区**。真跑了就会覆盖开发机上那张
    真 CA（本机中间人的根），那种"测试顺手改了开发机"的事一律不做。
    """

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
        if not _mitm_mod.mitm_available():
            self.skipTest("未装 cryptography（可选依赖）")
        self.dir = _isolated_ca(self)

    def _import(self, **payload):
        payload.setdefault("confirm", True)
        return _post(self.base, "/api/capture/ca/import", payload)

    def _status(self) -> dict:
        return _get(self.base, "/api/capture/ca/status")[1]

    def _leaves(self) -> list[str]:
        hosts = _mitm_mod.HOSTS_DIR
        return sorted(p.name for p in hosts.iterdir()) if hosts.is_dir() else []

    def test_import_needs_an_explicit_confirm(self):
        """换本机 CA 是有副作用的动作：与「一键信任」同一条规矩，先要 confirm。"""
        status, body = _post(self.base, "/api/capture/ca/import",
                             {"cert_b64": _b64(b"whatever")})
        self.assertEqual(status, 400)
        self.assertIn("confirm", body["error"])

    def test_a_certificate_without_its_key_is_refused(self):
        """只有证书没有私钥 = 签不出叶子证书，当场拒，别等抓流量时才发现。"""
        cert, _key = _make_ca("Team CA")
        status, body = self._import(cert_b64=_b64(cert))
        self.assertEqual(status, 400)
        self.assertIn("私钥", body["error"])
        self.assertFalse(_mitm_mod.CA_CERT.is_file(), "拒了就不该落盘")

    def test_a_non_ca_certificate_is_refused(self):
        """证书本身不是 CA（BasicConstraints CA:FALSE）也要拒 —— 它签不了叶子。"""
        cert, key = _make_ca("just a leaf", ca=False)
        status, body = self._import(cert_b64=_b64(cert), key_b64=_b64(key))
        self.assertEqual(status, 400)
        self.assertIn("不是 CA 证书", body["error"])

    def test_a_key_that_does_not_match_the_certificate_is_refused(self):
        """私钥与证书不是一对：签出来的叶子没人认，必须拒。"""
        cert, _key = _make_ca("Team CA")
        _other_cert, other_key = _make_ca("Other CA")
        status, body = self._import(cert_b64=_b64(cert), key_b64=_b64(other_key))
        self.assertEqual(status, 400)
        self.assertIn("不是一对", body["error"])

    def test_import_writes_the_pair_and_reports_what_it_saw(self):
        """导入成功：证书与私钥落盘、私钥只有本人可读，返回体如实说清是哪张、哪种形态。"""
        cert, key = _make_ca("Acme Internal CA")
        status, body = self._import(cert_b64=_b64(cert), key_b64=_b64(key))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["cn"], "Acme Internal CA")
        self.assertEqual(body["format"], "pem")
        self.assertFalse(body["replaced"])
        self.assertIn("Acme Internal CA", body["subject"])
        self.assertEqual(_mitm_mod.CA_CERT.read_bytes(), cert, "证书要原样落盘")
        if sys.platform == "win32":
            # Windows 没有 POSIX 权限位（st_mode 恒 0o666），私钥靠 ACL 守：
            # 去掉继承后应只剩本人一条 ACE。
            out = subprocess.run(["icacls", str(_mitm_mod.CA_KEY)],
                                 capture_output=True).stdout.decode("mbcs", errors="replace")
            aces = [ln for ln in out.splitlines() if ":(" in ln]
            self.assertEqual(len(aces), 1, f"私钥 ACL 应只剩本人一条：{out}")
            self.assertIn(os.environ.get("USERNAME", ""), aces[0])
        else:
            self.assertEqual(_mitm_mod.CA_KEY.stat().st_mode & 0o777, 0o600,
                             "私钥权限必须是 600")

        # 状态接口跟着变：名字取自证书本身（不是写死的默认名），并且有叶子数可看
        now = self._status()
        self.assertEqual(now["cn"], "Acme Internal CA")
        self.assertEqual(now["leaves"], 0)

    def test_import_accepts_a_pkcs12_bundle(self):
        """.p12/.pfx 也认（单位分发 CA 常见形态），口令走 password。"""
        from cryptography.hazmat.primitives.serialization import pkcs12

        cert_pem, key_pem = _make_ca("Bundle CA")
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        bundle = pkcs12.serialize_key_and_certificates(
            b"alias",
            serialization.load_pem_private_key(key_pem, password=None),
            x509.load_pem_x509_certificate(cert_pem), None,
            serialization.BestAvailableEncryption(b"team-secret"))
        status, body = self._import(cert_b64=_b64(bundle), password="team-secret")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["format"], "pkcs12")
        self.assertEqual(body["cn"], "Bundle CA")

        # 口令不对要给人话，不是抛栈
        status, body = self._import(cert_b64=_b64(bundle), password="wrong")
        self.assertEqual(status, 400)
        self.assertIn("PKCS#12", body["error"])

    def test_an_encrypted_key_needs_the_passphrase(self):
        """私钥带口令：不填就明说「把口令填上」，填对了照常导入。"""
        from cryptography.hazmat.primitives import serialization

        cert_pem, key_pem = _make_ca("Locked CA")
        key = serialization.load_pem_private_key(key_pem, password=None)
        locked = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"open-sesame"))

        status, body = self._import(cert_b64=_b64(cert_pem), key_b64=_b64(locked))
        self.assertEqual(status, 400)
        self.assertIn("口令", body["error"])
        status, body = self._import(cert_b64=_b64(cert_pem), key_b64=_b64(locked),
                                    password="open-sesame")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cn"], "Locked CA")

    def test_replacing_the_ca_needs_a_decision_and_purges_old_leaves(self):
        """换 CA：要显式确认替换；换完旧叶子必须清掉（它们是旧 CA 签的，留着必错）。"""
        first_cert, first_key = _make_ca("First CA")
        status, body = self._import(cert_b64=_b64(first_cert), key_b64=_b64(first_key))
        self.assertEqual(status, 200, body)

        _mitm_mod.HOSTS_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("a.example.crt", "a.example.chain.crt", "a.example.key.pem",
                     "b.example.crt"):
            (_mitm_mod.HOSTS_DIR / name).write_bytes(b"x")
        _mitm_mod._LEAF_CACHE["a.example"] = object()
        self.assertEqual(self._status()["leaves"], 2, "叶子数没有如实报出来")

        second_cert, second_key = _make_ca("Second CA")
        status, body = self._import(cert_b64=_b64(second_cert), key_b64=_b64(second_key))
        self.assertEqual(status, 400)
        self.assertIn("替换", body["error"])

        status, body = self._import(cert_b64=_b64(second_cert), key_b64=_b64(second_key),
                                    replace=True)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["replaced"])
        self.assertEqual((body["domains"], body["files"]), (2, 4))
        self.assertEqual(self._leaves(), [], "旧 CA 签的叶子没有清掉")
        self.assertFalse(_mitm_mod._LEAF_CACHE, "内存里的旧上下文没有清掉")
        self.assertEqual(_mitm_mod.CA_CERT.read_bytes(), second_cert)

    def test_purge_endpoint_clears_files_and_the_memory_cache(self):
        """清理键：落盘文件与内存缓存一起清；下个请求会重新签（不是把这功能关掉）。"""
        _mitm_mod.HOSTS_DIR.mkdir(parents=True, exist_ok=True)
        (_mitm_mod.HOSTS_DIR / "x.test.crt").write_bytes(b"x")
        (_mitm_mod.HOSTS_DIR / "x.test.chain.crt").write_bytes(b"x")
        (_mitm_mod.HOSTS_DIR / "y.test.crt").write_bytes(b"x")
        _mitm_mod._LEAF_CACHE["x.test"] = object()

        status, body = _post(self.base, "/api/capture/ca/purge", {})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["domains"], body["files"]), (2, 3))
        self.assertEqual(self._leaves(), [])
        self.assertFalse(_mitm_mod._LEAF_CACHE)

        # 再清一次：本来就没有，如实回 0，不假装清掉了什么
        _status, again = _post(self.base, "/api/capture/ca/purge", {})
        self.assertEqual((again["domains"], again["files"]), (0, 0))

    def test_trust_actions_follow_the_imported_name(self):
        """撤销信任 / 查状态都按**证书里实际的 CN**走 —— 导入的 CA 不叫默认名也得对。"""
        cert, key = _make_ca("Imported Team CA")
        self._import(cert_b64=_b64(cert), key_b64=_b64(key))
        old_platform = capture_trust.PLATFORM
        capture_trust.PLATFORM = "darwin"
        self.addCleanup(setattr, capture_trust, "PLATFORM", old_platform)
        argv = capture_trust.plan(undo=True)
        self.assertEqual(argv[:3], ["security", "delete-certificate", "-c"])
        self.assertEqual(argv[3], "Imported Team CA", "撤销时按的是写死的默认名？")


def _smuggle(tag: bytes) -> bytes:
    """一条带分歧的明文请求（CL.TE 那类）；上游指向必然拒绝的端口，测试不用等超时。"""
    return (b"POST /" + tag + b" HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
            b"Content-Length: 48\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n")


def _fake_interpreter(calls: list):
    """假的解读层：形状与真实解读层一致（ok / impact / cwe_hint / fix / model）。"""
    def run(finding: dict) -> dict:
        calls.append(finding)
        return {"ok": True, "impact": "人话：" + str(finding.get("kind") or ""),
                "cwe_hint": "CWE-444", "fix": "上游与前置统一分帧口径",
                "model": "fake-model"}
    return run


class TestCaptureInterpretation(unittest.TestCase):
    """流量接入的模型解读：**旁路**、可选、每条只解读最强的那一条。

    核心约束就一条 —— 模型再慢也不许拖住捕获与分析。这批用例全程用假解读层，
    不联网、不花钱，但走的是真实的那条线程与队列。
    """

    def setUp(self) -> None:
        self.origin_port = _free_port()
        self.origin = _RawOrigin(self.origin_port)
        self.origin.start()
        self.addCleanup(self.origin.close)

    def _harness(self, **kwargs) -> _ProxyHarness:
        harness = _ProxyHarness(**kwargs)
        self.addCleanup(harness.close)
        return harness

    def test_switch_off_means_no_thread_and_no_field(self):
        """不开解读：连线程都不起，记录里也不该多这个字段。"""
        harness = self._harness()
        harness.send(_smuggle(b"off"))
        self.assertTrue(_wait(lambda: harness.seen), "没有产生记录")
        self.assertTrue(_wait(lambda: harness.seen[0].get("analysis")), "没有分析结果")
        self.assertIsNone(harness.seen[0].get("interpret"))
        self.assertFalse(harness.proxy.interpret_thread.is_alive(), "没开解读不该起解读线程")

    def test_slow_model_never_blocks_the_analysis_pipeline(self):
        """模型卡住时，后续请求必须**照样完成分析** —— 这是本模块最硬的一条底线。"""
        gate = threading.Event()
        entered = threading.Event()
        self.addCleanup(gate.set)

        def stuck(finding):
            entered.set()
            gate.wait(10)
            return {"ok": True, "impact": "慢", "model": "fake"}

        harness = self._harness(interpreter=stuck)
        harness.send(_smuggle(b"slow-1"))
        self.assertTrue(_wait(entered.is_set, timeout=10), "解读没有开始跑")
        harness.send(_smuggle(b"slow-2"))            # 模型还卡着，这条必须能分析完
        self.assertTrue(_wait(lambda: len([r for r in harness.seen if r.get("analysis")]) >= 2,
                              timeout=5), "模型卡住时，后面的请求也被拖住了")
        gate.set()
        self.assertTrue(_wait(lambda: all(r.get("interpret") for r in harness.seen)
                              and len(harness.seen) >= 2, timeout=10),
                        "放行后解读没有落到记录上")
        self.assertEqual(harness.seen[0]["interpret"]["impact"], "慢")

    def test_one_call_per_request_slow_queue_is_reported(self):
        """队列被慢模型占满时：如实标出「跳过」，不是静默丢弃；分析一条都不能少。"""
        gate = threading.Event()
        self.addCleanup(gate.set)

        def stuck(finding):
            gate.wait(10)
            return {"ok": True, "impact": "慢", "model": "fake"}

        harness = self._harness(interpreter=stuck)
        for i in range(capture_proxy.INTERPRET_QUEUE + 6):
            harness.send(_smuggle(b"q%02d" % i))
        self.assertTrue(_wait(lambda: len(harness.seen) >= capture_proxy.INTERPRET_QUEUE + 6,
                              timeout=15), "记录数不够")
        dropped = [r for r in harness.seen
                   if "队列已满" in ((r.get("interpret") or {}).get("error") or "")]
        self.assertTrue(dropped, "队列满了却没有任何一条如实标记")
        self.assertGreater(harness.proxy.interpret_stats["dropped"], 0)
        analyzed = [r for r in harness.seen if r.get("analysis")]
        self.assertEqual(len(analyzed), len(harness.seen), "模型卡住时分析落下了几条")


class TestCaptureInterpretationApi(unittest.TestCase):
    """走真 HTTP 接口的这一层：开关怎么落到配置上、解读怎么回到网页。"""

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
        from ced.web.server import CAPTURE
        CAPTURE.stop()
        self.addCleanup(CAPTURE.stop)
        self.port = _free_port()
        # 设置文件隔离：起捕获会回落「设置」里的默认值，读到开发机那份就会依赖环境
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(scratch), True)
        self._old_settings = app_settings.SETTINGS_PATH
        app_settings.SETTINGS_PATH = scratch / "ced-settings.json"
        self.addCleanup(lambda: setattr(app_settings, "SETTINGS_PATH", self._old_settings))

    def _start(self, **payload) -> dict:
        payload.setdefault("port", self.port)
        status, body = _post(self.base, "/api/capture/start", payload)
        self.assertEqual(status, 200, body)
        return body

    def _drive(self, payload: bytes) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(payload)
            sock.settimeout(3)
            try:
                while sock.recv(65536):
                    pass
            except (socket.timeout, OSError):
                pass

    def _records(self) -> list:
        return _get(self.base, "/api/capture/records?since=0")[1]["records"]

    def _interpretations(self) -> dict:
        return _get(self.base, "/api/capture/interpretations")[1]

    def test_switch_off_does_not_even_build_an_interpreter(self):
        with mock.patch.object(web_server, "_make_interpreter") as made:
            body = self._start(interpret=False)
        made.assert_not_called()
        self.assertFalse(body["interpret"])

    def test_switch_on_wires_the_interpreter_and_returns_the_text(self):
        calls: list = []
        with mock.patch.object(web_server, "_make_interpreter",
                               side_effect=lambda: _fake_interpreter(calls)):
            body = self._start(interpret=True)
        self.assertTrue(body["interpret"])
        self._drive(_smuggle(b"api-on"))
        self.assertTrue(_wait(lambda: self._interpretations()["items"], timeout=10),
                        "解读没有出现在列表里")
        item = self._interpretations()["items"][0]
        self.assertEqual(item["interpret"]["model"], "fake-model")
        self.assertTrue(item["interpret"]["impact"])
        self.assertEqual(item["level"], "security")
        # 喂给模型的是**内核已经定好的那条**：领域 / 级别 / 理由都在，判定字段一个不少
        self.assertTrue(calls and calls[0].get("level") and calls[0].get("domain"))
        # 记录本身也带着解读（证据面板直接用这一份）
        record = [r for r in self._records() if r["case_id"] == item["case_id"]][0]
        self.assertTrue(record["interpret"]["ok"])

    def test_switch_on_without_a_model_says_so_instead_of_pretending(self):
        with mock.patch.object(web_server, "_make_interpreter", return_value=None):
            body = self._start(interpret=True)
        self.assertIn("模型没配好", body.get("interpret_note", ""))
        self.assertFalse(body["interpret"], "没配好模型就不该说这次开了模型解读")

    def test_running_state_tells_the_page_whether_interpretation_is_on(self):
        with mock.patch.object(web_server, "_make_interpreter",
                               return_value=_fake_interpreter([])):
            self._start(interpret=True)
        self.assertTrue(_get(self.base, "/api/capture/state")[1]["interpret"])


class TestCaptureForgetApi(unittest.TestCase):
    """删记录：动的是网页那份列表，JSONL 台账一个字节都不动。"""

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
        from ced.web.server import CAPTURE
        CAPTURE.stop()
        self.addCleanup(CAPTURE.stop)
        self.port = _free_port()
        # 设置文件与台账都放进临时目录：起捕获会回落「设置」里的默认值，
        # 读到开发机上那份就会让用例依赖环境。
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(scratch), True)
        self._old_settings = app_settings.SETTINGS_PATH
        app_settings.SETTINGS_PATH = scratch / "ced-settings.json"
        self.addCleanup(lambda: setattr(app_settings, "SETTINGS_PATH", self._old_settings))
        self.ledger = scratch / "capture.jsonl"

    def _start(self, **payload) -> dict:
        payload.setdefault("port", self.port)
        payload.setdefault("interpret", False)
        payload.setdefault("jsonl", str(self.ledger))
        status, body = _post(self.base, "/api/capture/start", payload)
        self.assertEqual(status, 200, body)
        return body

    def _drive(self, payload: bytes) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(payload)
            sock.settimeout(3)
            try:
                while sock.recv(65536):
                    pass
            except (socket.timeout, OSError):
                pass

    def _records(self) -> list:
        return _get(self.base, "/api/capture/records?since=0")[1]["records"]

    def _interpretations(self) -> list:
        return _get(self.base, "/api/capture/interpretations")[1]["items"]

    def _record_count(self, want: int) -> list:
        self.assertTrue(_wait(lambda: len(self._records()) >= want), "记录没有到齐")
        return self._records()

    def test_delete_one_record_leaves_the_ledger_alone(self):
        """列表里删掉一条：JSONL 台账里那条原样还在 —— 删的是视图，不是证据。"""
        self._start()
        self._drive(FAST)
        record = self._record_count(1)[0]
        self.assertTrue(_wait(lambda: self.ledger.is_file()), "台账文件没有写出来")

        status, body = _post(self.base, "/api/capture/forget", {"seq": record["seq"]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["removed"], 1)
        self.assertEqual(self._records(), [], "列表里还留着这条")
        self.assertEqual(body["summary"]["requests"], 0, "统计没有跟着减")

        lines = [json.loads(ln) for ln in
                 self.ledger.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, "JSONL 台账被删记录动到了")
        self.assertEqual(lines[0]["case_id"], record["case_id"])

        # 幂等：再删一次既不报错，也不许顺手删掉别的东西
        _, again = _post(self.base, "/api/capture/forget", {"seq": record["seq"]})
        self.assertEqual(again["removed"], 0)

    def test_delete_takes_the_duplicate_count_and_the_interpretation_with_it(self):
        """删掉记录，它的 ×N 计数与模型解读一起走；同一份字节再来算新的一条。"""
        calls: list = []
        with mock.patch.object(web_server, "_make_interpreter",
                               side_effect=lambda: _fake_interpreter(calls)):
            self._start(interpret=True)
        for _ in range(2):
            self._drive(_smuggle(b"del"))
        record = self._record_count(1)[0]
        self.assertTrue(_wait(lambda: self._interpretations()), "解读没有出现在列表里")
        _, before = _get(self.base, "/api/capture/records?since=0")
        self.assertEqual(before["counts"].get(record["case_id"]), 2, "重复计数没有生效")

        _post(self.base, "/api/capture/forget", {"seq": record["seq"]})
        self.assertEqual(self._interpretations(), [], "记录删了，它的解读还挂在面板上")
        _, after = _get(self.base, "/api/capture/records?since=0")
        self.assertNotIn(record["case_id"], after["counts"], "×N 计数没有跟着删")

        self._drive(_smuggle(b"del"))          # 同一份字节再来
        again = self._record_count(1)[0]
        self.assertNotEqual(again["seq"], record["seq"])
        self.assertEqual(again["count"], 1, "删过的记录回来该是新的一条，不接旧计数")

    def test_tunnel_records_are_deletable_by_seq(self):
        """HTTPS 隧道那条**没有 case_id** —— 删它只能靠 seq，这就是按 seq 删的原因。"""
        self._start()
        self._drive(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        self._drive(FAST)
        records = self._record_count(2)
        tunnel = [r for r in records if r["tunnel"]][0]
        self.assertIsNone(tunnel["case_id"])

        _, body = _post(self.base, "/api/capture/forget", {"seq": tunnel["seq"]})
        self.assertEqual(body["removed"], 1)
        self.assertEqual([r["seq"] for r in self._records()],
                         [r["seq"] for r in records if not r["tunnel"]],
                         "删隧道那条时连带删了别的记录")

    def test_clear_all_empties_the_list_and_the_stats(self):
        """清空：列表、×N 计数、解读一起空；JSONL 里两条都还在。"""
        self._start()
        self._drive(FAST)
        self._drive(_smuggle(b"clear"))
        self._record_count(2)

        status, body = _post(self.base, "/api/capture/forget_all", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["removed"], 2)
        self.assertEqual(self._records(), [])
        self.assertEqual(body["summary"]["requests"], 0)
        self.assertEqual(_get(self.base, "/api/capture/records?since=0")[1]["counts"], {})

        lines = [ln for ln in self.ledger.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2, "清空列表把 JSONL 台账也清了")

    def test_forget_while_stopped_is_a_quiet_no_op(self):
        """捕获没在跑时删：返回成功、removed 0 —— 界面上那份列表本来就是空的。"""
        status, body = _post(self.base, "/api/capture/forget", {"seq": 1})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["removed"], 0)
        status, body = _post(self.base, "/api/capture/forget_all", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["removed"], 0)


class TestCaTrustCommands(unittest.TestCase):
    """「一键导入信任库」的命令拼装 —— 只查拼出来的 argv，绝不碰真的信任库。"""

    def setUp(self) -> None:
        _isolated_ca(self)
        self._old_platform = capture_trust.PLATFORM
        self.addCleanup(lambda: setattr(capture_trust, "PLATFORM", self._old_platform))

    @unittest.skipUnless(sys.platform == "win32", "Windows 原生命令输出编码")
    def test_native_command_diagnostics_decode_in_utf8_mode(self):
        message = "证书验证失败：找不到指定的证书"
        raw = message.encode("oem", errors="replace")
        expected = raw.decode("oem")
        script = (f"import os; os.write(1, {raw!r}); "
                  f"os.write(2, {raw!r}); raise SystemExit(1)")
        result = capture_trust._run([sys.executable, "-c", script])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, expected)

    def test_mac_uses_the_user_keychain_and_ssl_policy_only(self):
        capture_trust.PLATFORM = "darwin"
        argv = capture_trust.plan()
        self.assertEqual(argv[:2], ["security", "add-trusted-cert"])
        self.assertIn("ssl", argv, "只该给 TLS 策略授信，不做全局根")
        self.assertIn(str(capture_trust.MAC_USER_KEYCHAIN), argv)
        self.assertNotIn("/Library/Keychains/System.keychain", argv, "不碰系统钥匙串")
        self.assertNotIn("sudo", argv, "不自动提权")
        self.assertEqual(argv[-1], str(capture_trust.mitm.CA_CERT))

    def test_mac_status_tracks_the_user_trust_settings(self):
        """macOS 的状态读用户域信任设置 —— 实测 verify-cert 会因策略不符误报、
        撤销之后还缓存着旧结论，所以那条路不能用。"""
        capture_trust.PLATFORM = "darwin"
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(scratch), True)
        fake_ca = scratch / "ca.crt"
        fake_ca.write_bytes(b"-----BEGIN CERTIFICATE-----\n")

        def with_run(proc):
            return mock.patch.object(capture_trust, "_run", return_value=proc)

        with mock.patch.object(capture_trust.mitm, "CA_CERT", fake_ca), \
             mock.patch.object(capture_trust.mitm, "mitm_available", return_value=True):
            with with_run(subprocess.CompletedProcess([], 0, "Cert 0: CED Local Capture CA", "")):
                self.assertEqual(capture_trust.status()["state"], "trusted")
            with with_run(subprocess.CompletedProcess([], 1, "", "No Trust Settings were found.")):
                self.assertEqual(capture_trust.status()["state"], "untrusted",
                                 "没有任何信任设置 = 没信任")
            with with_run(subprocess.CompletedProcess([], 0, "Cert 0: 别的证书", "")):
                self.assertEqual(capture_trust.status()["state"], "untrusted",
                                 "有别人的信任设置 ≠ 我们的被信任")

    def test_undo_targets_only_our_ca(self):
        capture_trust.PLATFORM = "darwin"
        argv = capture_trust.plan(undo=True)
        self.assertEqual(argv[0], "security")
        self.assertIn(capture_trust.mitm.CA_COMMON_NAME, argv, "只该删我们这张")

    def test_windows_goes_to_the_user_store(self):
        capture_trust.PLATFORM = "win32"
        argv = capture_trust.plan()
        self.assertEqual(argv[0], "certutil")
        self.assertIn("-user", argv, "写当前用户证书库，不弹 UAC")
        self.assertEqual(capture_trust.plan(undo=True)[:3], ["certutil", "-user", "-delstore"])

    def test_linux_has_no_one_click_entry(self):
        capture_trust.PLATFORM = "linux"
        self.assertIsNone(capture_trust.plan(), "Linux 那一步必然要管理员权限，不做一键")
        if _mitm_mod.mitm_available():
            _mitm_mod.ensure_ca()
        view = capture_trust.status()
        self.assertIn(view["state"], {"unsupported", "no_dependency"})
        self.assertFalse(view["supported"])

    def test_failure_is_reported_with_the_system_wording(self):
        """命令非零退出 → ok=False 且带上系统原话，不允许「看起来成功了」。"""
        if not capture_trust.mitm.mitm_available():
            self.skipTest("未装 cryptography（可选依赖）")
        capture_trust.PLATFORM = "darwin"
        capture_trust.mitm.ensure_ca()
        failed = subprocess.CompletedProcess(["security"], 1, "", "SecKeychain error -25293")
        with mock.patch.object(capture_trust, "_run", return_value=failed):
            result = capture_trust.apply()
        self.assertFalse(result["ok"])
        self.assertIn("SecKeychain error", result["error"])
        self.assertIn("security add-trusted-cert", result["hint"])

    def test_missing_dependency_is_reported_not_faked(self):
        with mock.patch.object(capture_trust.mitm, "mitm_available", return_value=False):
            result = capture_trust.apply()
            view = capture_trust.status()
        self.assertFalse(result["ok"])
        self.assertIn("cryptography", result["error"])
        self.assertEqual(view["state"], "no_dependency")
        self.assertFalse(view["mitm"])

    def test_missing_ca_is_not_pretended_to_be_undoable(self):
        gone = Path(tempfile.mkdtemp()) / "ca.crt"        # 这个路径不存在，就是「CA 还没生成」
        self.addCleanup(shutil.rmtree, str(gone.parent), True)
        with mock.patch.object(capture_trust.mitm, "CA_CERT", gone):
            result = capture_trust.apply(undo=True)
        self.assertFalse(result["ok"])
        self.assertIn("没有 CA", result["error"])


class TestCaptureSessionArchive(unittest.TestCase):
    """会话归档：侧栏按"一次接入一条"回看，点开就是当时的记录与证据。

    这一层专门守住"回看真的点得开"：归档条目要留住记录、证据（``record``）、
    解读（``interpretations``）与 PoC 材料 —— 少一样，侧栏那一行就成了死链。
    """

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
        from ced.web.server import CAPTURE
        CAPTURE.stop()
        self.addCleanup(CAPTURE.stop)
        self.addCleanup(self._clear_archive)     # 归档在进程内共享，别留给下一个用例
        self._clear_archive()                    # 也别接过别的用例留下的归档
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(scratch), True)
        self._old_settings = app_settings.SETTINGS_PATH
        app_settings.SETTINGS_PATH = scratch / "ced-settings.json"
        self.addCleanup(lambda: setattr(app_settings, "SETTINGS_PATH", self._old_settings))
        # PoC 落到临时目录，别污染仓库的 results/pocs
        self._old_poc_dir = capture_web.POC_DIR
        capture_web.POC_DIR = scratch / "pocs"
        self.addCleanup(lambda: setattr(capture_web, "POC_DIR", self._old_poc_dir))
        self.ledger = scratch / "capture.jsonl"
        self.port = 0

    # ---------------------------------------------------------------- 辅助
    def _clear_archive(self) -> None:
        for item in self._sessions():
            if not item["running"]:
                _post(self.base, "/api/capture/session/forget", {"id": item["id"]})

    def _start(self, **payload) -> dict:
        payload.setdefault("port", _free_port())
        payload.setdefault("jsonl", str(self.ledger))
        status, body = _post(self.base, "/api/capture/start", payload)
        self.assertEqual(status, 200, body)
        self.port = body["port"]
        return body

    def _stop(self) -> dict:
        status, body = _post(self.base, "/api/capture/stop", {})
        self.assertEqual(status, 200, body)
        return body

    def _drive(self, payload: bytes) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(payload)
            sock.settimeout(3)
            try:
                while sock.recv(65536):
                    pass
            except (socket.timeout, OSError):
                pass

    def _sessions(self) -> list:
        return _get(self.base, "/api/capture/sessions")[1]["sessions"]

    def _records(self, session: str = "") -> dict:
        tail = "&session=" + session if session else ""
        return _get(self.base, "/api/capture/records?since=0" + tail)[1]

    def _run_one_session(self, count: int = 1) -> list:
        """接一次会话（带 count 条记录）再停下，返回停下后的会话清单。"""
        self._start()
        for index in range(count):
            self._drive(_smuggle(b"cap%d" % index))
        self.assertTrue(_wait(lambda: len(self._records()["records"]) >= count),
                        "记录没有到齐")
        self._stop()
        return self._sessions()

    # ---------------------------------------------------------------- 用例
    def test_live_session_is_listed_while_running(self):
        """正在跑的那次也在清单里（侧栏那行标「进行中」），统计跟着记录走。"""
        self._start()
        self._drive(_smuggle(b"live"))
        self.assertTrue(_wait(lambda: self._records()["records"]), "记录没有到齐")
        sessions = self._sessions()
        self.assertEqual(len(sessions), 1, sessions)
        self.assertTrue(sessions[0]["running"])
        self.assertTrue(sessions[0]["id"], "会话没有身份，侧栏就没法定位它")
        self.assertEqual(sessions[0]["summary"]["requests"], 1)

    def test_finished_session_keeps_its_records_evidence_and_interpretation(self):
        """停下来的那次：记录、证据、解读都还点得开 —— 回看能成立全靠这三样。"""
        calls: list = []
        with mock.patch.object(web_server, "_make_interpreter",
                               side_effect=lambda: _fake_interpreter(calls)):
            self._start(interpret=True)
        self._drive(_smuggle(b"keep"))
        self.assertTrue(_wait(lambda: self._records()["records"]), "记录没有到齐")
        self.assertTrue(_wait(lambda: _get(self.base, "/api/capture/interpretations")[1]["items"]),
                        "解读没有出现在列表里")
        self._stop()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 1, sessions)
        item = sessions[0]
        self.assertFalse(item["running"])
        self.assertGreaterEqual(item["t1"], item["t0"])
        self.assertEqual(item["summary"]["requests"], 1)
        self.assertTrue(item["interpret"], "这次开了模型解读，回看时要知道")

        self.assertEqual(self._records()["records"], [], "停下之后当前列表该是空的")
        past = self._records(item["id"])
        self.assertEqual(len(past["records"]), 1, "归档里没有留下这次会话的记录")
        case_id = past["records"][0]["case_id"]
        self.assertTrue(case_id)

        detail = _get(self.base, "/api/capture/record?case_id=%s&session=%s"
                      % (case_id, item["id"]))[1]
        self.assertEqual(detail["case_id"], case_id)
        self.assertTrue(detail.get("raw_b64"), "回看时的证据没有原始字节")
        self.assertIn("raw_preview", detail)

        interp = _get(self.base, "/api/capture/interpretations?session=%s" % item["id"])[1]
        self.assertEqual([x["case_id"] for x in interp["items"]], [case_id],
                         "回看时那次会话的解读没留下")
        self.assertEqual(interp["stats"]["done"], 1)

    def test_poc_can_still_be_built_for_a_past_session(self):
        """出 PoC 要 `_finding` —— 归档把 seen 一起留着，老会话照样能出脚本。"""
        self._run_one_session(count=1)
        item = self._sessions()[0]
        case_id = self._records(item["id"])["records"][0]["case_id"]
        # 落盘那一步用的是 3.10+ 才有的 Path.write_text(newline=)，本机 3.9 跑不了；
        # 这条用例要守的是**归档里还有没有 PoC 材料**，所以把写文件换成等价的写法。
        write = lambda path, text: Path(path).write_text(text, encoding="utf-8")
        with mock.patch.object(capture_web.artifacts, "write_text", write):
            status, body = _post(self.base, "/api/capture/poc",
                                 {"case_id": case_id, "session": item["id"]})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"], body)
        self.assertTrue(body["path"].endswith(".py"))
        self.assertEqual(body["level"], "security")
        self.assertTrue(Path(body["path"]).read_text(encoding="utf-8").strip())

    def test_an_empty_session_is_not_archived(self):
        """起了就停、一条都没过：归档它只是噪声，侧栏不该凭空多一行。"""
        before = [item["id"] for item in self._sessions()]
        self._start()
        self._stop()
        self.assertEqual([item["id"] for item in self._sessions()], before)

    def test_only_the_last_few_sessions_are_kept(self):
        """内存只留最近 ARCHIVE_SESSIONS 次：更老的会话从侧栏消失（JSONL 里仍在）。"""
        ids = []
        for _ in range(capture_web.ARCHIVE_SESSIONS + 1):
            self._run_one_session(count=1)
            ids.append(self._sessions()[0]["id"])    # 刚停下的那次排在最前
        kept = [s["id"] for s in self._sessions()]
        self.assertEqual(len(kept), capture_web.ARCHIVE_SESSIONS, kept)
        self.assertNotIn(ids[0], kept, "最老的那次会话还留在侧栏里")
        self.assertIn(ids[-1], kept, "最新那次会话反而不见了")
        self.assertEqual(self._records(ids[0])["records"], [],
                         "已经挤出去的会话还点得开")

    def test_forgetting_a_session_removes_it_from_the_list(self):
        """侧栏那条 ✕：移除一次已结束的会话；正在跑的那次不在这里删。"""
        self._run_one_session(count=1)
        item = self._sessions()[0]
        status, body = _post(self.base, "/api/capture/session/forget", {"id": item["id"]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["removed"], 1)
        self.assertEqual(self._sessions(), [])
        self.assertEqual(self._records(item["id"])["records"], [])
        self.assertEqual(_post(self.base, "/api/capture/session/forget",
                               {"id": item["id"]})[1]["removed"], 0)

    def test_unknown_session_is_an_empty_read_not_an_error(self):
        """查一个不存在的会话：空列表 / 人话错误，不是 500 —— 别把前端轮询打断。"""
        status, body = _get(self.base, "/api/capture/records?since=0&session=nope")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["records"], [])
        self.assertEqual(body["summary"]["requests"], 0)
        status, body = _get(self.base, "/api/capture/record?case_id=x&session=nope")
        self.assertEqual(status, 200, body)
        self.assertIn("找不到", body["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
