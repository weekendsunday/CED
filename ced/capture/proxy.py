"""本机捕获代理：把客户端**真实发出**的请求自动送进差分 oracle。

它不是网卡抓包（那需要 Npcap 驱动 + 管理员权限，而且 HTTPS 只能拿到密文），
而是一个本机 HTTP 代理：你把浏览器 / 客户端 / 系统代理指向它，请求就自动落进来。

    client ──> 本代理 ──> 真实站点
                 │
                 └─ 每条请求：原样记录 → 过滤 / 去重 → 跑差分 → 落 JSONL + 回调

**捕获与转发是两件不同的事**（这条边界要在报告里讲清）：
  * 捕获的是**客户端原样发来的字节**（记录里的 ``raw_b64`` / ``target`` 就是它）；
  * 但**送去分析的是"源站会看到的那份字节"** —— 请求行从代理的绝对形式归一化成
    源站形式（见 ``_origin_form``）。不这么做，每条请求都会因为
    ``request-line-absolute-uri`` 这条已知分歧轴刷出十几条安全级假阳性；
  * 转发时只加一条 `Connection: close`（让上游读完即关，省掉响应定帧），其余不动。

HTTPS 默认仍是一条 `CONNECT` 隧道直通（记一条"到 x:443（未拆）"），装了可选依赖
``cryptography`` 并对本机信任库导入本地 CA 后才解密进同一条管线；不信任本地 CA
的客户端如实记为握手失败。明确不做：网卡混杂抓包、解析 pcap、建驱动、要管理员。

模型解读同样是**可选旁路**：`Config.interpreter` 给了回调才起一条独立的解读线程，
每条请求只解读「最强的那一条」，串行调模型、有界队列削峰 —— 慢的是模型，
绝不允许它拖住转发或分析（这是本模块最硬的一条底线）。
"""
from __future__ import annotations

import base64
import json
import queue
import socket
import ssl
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..pipeline import case_id_of
from .analyze import analyze
from . import mitm as _mitm_mod

#: 单个请求（头 + 体）的读取上限，防内存爆炸
MAX_REQUEST = 1 << 20
#: 请求头部的读取上限（超了说明这不是一条正常请求）
MAX_HEAD = 64 << 10
#: 连上游 / 读上游的超时
UPSTREAM_TIMEOUT = 30.0
#: 分析队列容量：满了就只转发不分析（绝不因为分析而阻塞转发）
QUEUE_SIZE = 512
#: 解读队列容量 + 单次捕获的解读条数上限：模型慢（一次几秒到几十秒），
#: 队列只用来削峰；满了 / 到顶就**如实跳过并计数**，绝不拿模型去堵住捕获本身。
INTERPRET_QUEUE = 16
INTERPRET_MAX = 200
#: 内存里保留多少条解读给网页看（与 records 一个口径：只保最近这些）
INTERPRET_KEEP = 200
#: 内存里给网页/CLI 保留多少条记录（完整记录在 JSONL 里，一条不丢）
MAX_RECORDS = 2000

#: 默认跳过的静态资源后缀 —— 一个页面里绝大多数请求都是这些，全跑只是噪声
STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".map", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".gz", ".br",
)


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 18081
    jsonl: Path | None = None
    domains: list[str] | None = None          # None = 全部 5 个领域
    analyze_all: bool = False                 # True = 连静态资源也分析
    #: True = 装有可选依赖 ``cryptography`` 时对 CONNECT 做本地 CA MITM（解密进差分）；
    #: 没装则自动退回隧道直通，一律如实计数。False = 强制只做隧道直通。
    mitm: bool = True
    #: 上游代理（如公司/科学上网代理 ``127.0.0.1:10090``）：浏览器 → 本捕获 → 上游。
    #: 给了它之后，所有出站连接（HTTP 明文、CONNECT 隧道、MITM 的上游侧）都先
    #: 对上游发 CONNECT 隧道再走 —— 被墙站点才能通，捕获才真能挂进日常浏览。
    upstream: str | None = None
    on_result: object = None                  # callable(record) —— 给 CLI / 前端用
    #: 解读层回调 ``callable(finding_dict) -> dict``；None = 不解读。
    #: 为什么在**起捕获那一刻**定死：用不用模型是一次运行的选择 —— 跑到一半突然
    #: 开始调模型，只会让人搞不清时间和钱花在了哪。
    interpreter: object = None
    stop: threading.Event = field(default_factory=threading.Event)


# --------------------------------------------------------------------- 读一条请求

def _read_head(sock: socket.socket, buf: bytes = b"") -> tuple[bytes, bytes]:
    """读到请求头结束（``\\r\\n\\r\\n``）。返回 (含结束符的头, 之后多读到的字节)。"""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEAD:
            return buf, b""
        chunk = sock.recv(65536)
        if not chunk:
            return buf, b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head + b"\r\n\r\n", rest


def _head_field(head: bytes, name: bytes) -> bytes | None:
    for line in head.split(b"\r\n"):
        if line.lower().startswith(name):
            return line.split(b":", 1)[1].strip()
    return None


def _chunked_complete(body: bytes) -> bool:
    """body 是否已经是一个完整的分块流（含结尾 0 块与最后的空行）。"""
    i = 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return False
        token = body[i:j].split(b";")[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            return False                     # 畸形块长：不猜
        i = j + 2
        if size == 0:
            while True:                       # 0 块之后允许有 trailer，直到空行
                k = body.find(b"\r\n", i)
                if k < 0:
                    return False
                if k == i:
                    return True
                i = k + 2
        else:
            i += size
            if len(body) < i + 2:
                return False
            i += 2                             # 跳过块数据后的 CRLF


def _read_request(sock: socket.socket) -> bytes:
    """读全一条请求（头 + 体），返回**客户端原样发来的字节**。

    体长只按 Content-Length / 分块编码判定 —— 判不出来就只读到头的结尾，
    绝不替客户端"猜"一个体长（那会让分析对象变成我们自己造的字节）。
    """
    head, rest = _read_head(sock)
    if not head:
        return b""
    raw = head + rest
    lower = head.lower()
    if b"chunked" in (head if b"transfer-encoding:" not in lower
                      else lower.split(b"transfer-encoding:", 1)[1][:32]):
        while not _chunked_complete(raw[len(head):]):
            if len(raw) > MAX_REQUEST:
                break
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
        return raw
    token = _head_field(head, b"content-length:")
    try:
        length = int(token or b"0")
    except ValueError:
        length = 0
    while len(raw) - len(head) < length:
        if len(raw) > MAX_REQUEST:
            break
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    return raw


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ") if lines else []
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(b":")
        key = name.decode("latin-1").strip().lower()
        if key:
            headers[key] = value.decode("latin-1").strip()
    return method, target, headers


def _upstream_of(target: str, headers: dict[str, str]) -> tuple[str, int, str]:
    """从请求行 / Host 头算出 (上游主机, 端口, origin-form 路径)。

    代理收到的请求行通常是绝对形式（``GET http://host/path HTTP/1.1``）；
    退化成 origin 形式时用 Host 头定位上游。
    """
    if target.startswith("http://"):
        authority, _, path = target[len("http://"):].partition("/")
        host, _, port_s = authority.partition(":")
        return host, int(port_s or 80), ("/" + path if path else "/")
    host, _, port_s = headers.get("host", "").partition(":")
    return host, int(port_s or 80), target or "/"


def _origin_form(raw: bytes, path: str) -> bytes:
    """把「代理形式」的请求行改写成「源站形式」，再拿去分析。

    为什么必须做（冒烟时实测到的假阳性）：客户端发给**代理**的请求行是绝对形式
    （``GET http://host/path HTTP/1.1``），而源站看到的是相对形式（``GET /path HTTP/1.1``）。
    项目里本来就有 ``request-line-absolute-uri`` 这条已知分歧轴（一侧放行、一侧拒绝），
    不归一化的话**每一条请求**都会刷出十几条安全级"发现"——那是代理这个部署位置带来的
    假阳性，不是耦合误差。归一化后分析的是「源站会看到的那份字节」。

    原始字节不丢：记录里保留 ``target``（原始绝对 URL）与 ``raw_b64``（原样字节）。
    顺带去掉 ``Proxy-Connection``（代理专用的跳步头，源站看不到它）。
    """
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if len(lines) >= 1:
        parts = lines[0].split(b" ")
        if len(parts) == 3:
            lines[0] = b" ".join([parts[0], path.encode("latin-1"), parts[2]])
    lines = [lines[0]] + [ln for ln in lines[1:]
                          if not ln.lower().startswith(b"proxy-connection:")]
    head = b"\r\n".join(lines)
    return head + sep + body if sep else head


def _skip_reason(method: str, path: str) -> str:
    if method == "CONNECT":
        return ""
    if path.lower().split("?")[0].endswith(STATIC_SUFFIXES):
        return "静态资源"
    return ""


def _head_and_body(raw: bytes) -> tuple[bytes, bytes]:
    head, sep, body = raw.partition(b"\r\n\r\n")
    return (head + b"\r\n\r\n") if sep else raw, (body if sep else b"")


def _upstream_request(raw: bytes, host: str, port: int) -> bytes:
    """经上游代理转发时的请求：连接用 CONNECT 隧道，但请求行要改回**绝对形式**
    （有些上游对明文端口的 CONNECT 不放行，绝对形式是链式代理的标准做法）。"""
    fb = _forward_bytes(raw)
    lines = fb.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) == 3:
        lines[0] = b" ".join([parts[0],
                              f"http://{host}:{port}".encode("latin-1") + parts[1],
                              parts[2]])
    return b"\r\n".join(lines)


def _forward_bytes(raw: bytes) -> bytes:
    """转发用：把 Connection 换掉（其余原样），让上游读完即关。"""
    head, body = _head_and_body(raw)
    lines = [ln for ln in head.split(b"\r\n")
             if not ln.lower().startswith(b"connection:")
             and not ln.lower().startswith(b"proxy-connection:")]
    while lines and lines[-1] == b"":
        lines.pop()
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _pump(a: socket.socket, b: socket.socket) -> None:
    """两个方向对拷到任一侧结束（CONNECT 隧道的全部内容）。"""

    def one_way(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    thread = threading.Thread(target=one_way, args=(a, b), daemon=True)
    thread.start()
    one_way(b, a)
    thread.join(timeout=1.0)


class _UpstreamTLSFailed(Exception):
    """上游（真实站点）TLS 握手失败 —— 网络到不了它，与客户端信不信任本地 CA 无关。

    为什么单独一个类型：上游握手失败和客户端拒绝本地 CA 都会冒泡成
    ``ssl.SSLError``，早先的代码把两者写成同一句"疑似证书固定"，于是
    **直连被墙 / 上游代理节点不通**这类网络问题被记成了客户端的锅（排查
    "HTTPS 为什么不拆包"时被这句话带偏过）。分开报才对得上事实。
    """


# --------------------------------------------------------------------- 代理主体

class CaptureProxy:
    """一条请求进来：先去分析队列，再转发给真实站点（两者互不阻塞）。"""

    def __init__(self, config: Config) -> None:
        self.cfg = config
        self.seq = 0
        self.lock = threading.Lock()
        self.seen: dict[str, dict] = {}          # case_id → 记录（用于去重计数）
        #: case_id → 当前出现次数（只记重复过的那些）—— 网页靠它把 ×N 刷新到已有行上
        self.duplicate_counts: dict[str, int] = {}
        self.records: deque = deque(maxlen=MAX_RECORDS)   # 供前端 / 总结用（限长防爆内存）
        self.queue: queue.Queue = queue.Queue(maxsize=QUEUE_SIZE)
        self.worker = threading.Thread(target=self._consume, daemon=True)
        #: 解读是**旁路**：单独一条线程 + 有界队列。慢的是模型 ——
        #: 绝不能让它占住分析线程（分析一慢，队列就满，真实流量就开始丢）。
        self.interpret_queue: queue.Queue = queue.Queue(maxsize=INTERPRET_QUEUE)
        self.interpret_thread = threading.Thread(target=self._interpret_loop, daemon=True)
        self.interpretations: deque = deque(maxlen=INTERPRET_KEEP)
        self.interpret_stats = {"done": 0, "failed": 0, "dropped": 0, "capped": 0}
        self._server: socket.socket | None = None

    # ------------------------------------------------------------------ 输出

    def _emit(self, record: dict) -> None:
        if self.cfg.jsonl is not None:
            payload = {k: v for k, v in record.items() if not k.startswith("_")}
            with open(self.cfg.jsonl, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        if callable(self.cfg.on_result):
            try:
                self.cfg.on_result(record)
            except Exception:                # noqa: BLE001 —— 回调不许拖垮代理
                pass

    def _consume(self) -> None:
        """单个分析线程：代理只负责收，分析在后台排队做 —— 别把连接卡住。"""
        while not self.cfg.stop.is_set():
            try:
                record = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if record is None:
                return
            started = time.time()
            raw = record.pop("raw", b"")
            try:
                analysis = analyze(raw, self.cfg.domains)
                record["analysis"] = analysis.to_dict()
                # 私有字段（下划线开头）：只给"一键出 PoC"用，绝不进 JSONL
                record["_finding"] = analysis.top_finding
                record["_top_domain"] = analysis.top.domain if analysis.top else ""
            except Exception as exc:         # noqa: BLE001 —— 一条算不动不许停整个捕获
                record["analysis"] = None
                record["skip"] = f"分析异常：{type(exc).__name__}: {exc}"
            record["elapsed_ms"] = round((time.time() - started) * 1000, 1)
            self._emit(record)
            self._enqueue_interpret(record, analysis)

    def _enqueue_interpret(self, record: dict, analysis) -> None:
        """把「最强的那一条」丢给解读线程。**绝不等待、绝不抛异常**。

        为什么只解读最强的一条：一条请求最多挂 5 个领域的发现，全解读等于把模型
        调用量乘以领域数，而证据面板展示的本来也就是最强的那条。想看全部领域，
        走手动检测（那边一条输入扇出的发现少得多）。
        """
        if self.cfg.interpreter is None or analysis.top_finding is None:
            return
        stats = self.interpret_stats
        if stats["done"] + stats["failed"] >= INTERPRET_MAX:
            stats["capped"] += 1
            record["interpret"] = {"ok": False,
                                   "error": f"本次捕获的模型解读已达上限 {INTERPRET_MAX} 条"}
            return
        try:
            self.interpret_queue.put_nowait((record, analysis.top.to_dict()))
        except queue.Full:
            stats["dropped"] += 1
            record["interpret"] = {"ok": False, "error": "解读队列已满（模型跟不上流量），这条跳过"}

    def _interpret_loop(self) -> None:
        """解读线程：串行调模型。慢是预期内的 —— 它既不挡转发，也不挡分析。"""
        while not self.cfg.stop.is_set():
            try:
                item = self.interpret_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                return
            record, finding = item
            try:
                data = self.cfg.interpreter(finding)
                if not isinstance(data, dict):
                    data = {"ok": False, "error": "解读返回的不是对象"}
            except Exception as exc:             # noqa: BLE001 —— 模型挂了不许影响捕获
                data = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if not data.get("ok"):
                data = {"ok": False, "error": data.get("error") or "解读不可用"}
            with self.lock:
                record["interpret"] = data
                self.interpret_stats["done" if data.get("ok") else "failed"] += 1
                # 记录已经被删掉（网页上按了删除）就别再把解读挂回列表：模型慢，
                # 这一条可能在删除之后才回来，挂上去就成了列表里找不到的幽灵条目。
                if data.get("ok") and record.get("case_id") in self.seen:
                    self.interpretations.append({
                        "case_id": record.get("case_id", ""),
                        "ts": record.get("ts", ""),
                        "method": record.get("method", ""),
                        "host": record.get("host", ""),
                        "path": record.get("path", ""),
                        "domain": finding.get("domain", ""),
                        "level": finding.get("level", ""),
                        "kind": finding.get("kind", ""),
                        "reason": finding.get("reason", ""),
                        "interpret": data})

    # ------------------------------------------------------------------ 处理

    def _handle(self, conn: socket.socket, client: tuple) -> None:
        try:
            raw = _read_request(conn)
            if not raw:
                return
            method, target, headers = _parse_head(_head_and_body(raw)[0])
            if method == "CONNECT":
                self._tunnel(conn, client, target)
            else:
                self._record_and_forward(conn, client, method, target, headers, raw)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ 上游

    def _connect_upstream(self, host: str, port: int) -> socket.socket:
        """建立到真实目标的出站连接：配置了上游代理时先对它 CONNECT 隧道。"""
        if not self.cfg.upstream:
            return socket.create_connection((host, port), timeout=UPSTREAM_TIMEOUT)
        up_host, _, up_port = self.cfg.upstream.rpartition(":")
        sock = socket.create_connection((up_host or "127.0.0.1", int(up_port)),
                                        timeout=UPSTREAM_TIMEOUT)
        try:
            sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\n"
                         f"Host: {host}:{port}\r\n\r\n".encode("ascii"))
            reply = b""
            while b"\r\n\r\n" not in reply:
                chunk = sock.recv(4096)
                if not chunk:
                    raise OSError("上游代理提前断开（CONNECT 无响应）")
                reply += chunk
            status = reply.split(b" ", 2)[1] if reply.startswith(b"HTTP/") else b""
            if not status.startswith(b"2"):
                raise OSError(f"上游代理拒绝 CONNECT {host}:{port}："
                              f"{reply.splitlines()[0].decode('latin-1', 'replace')}")
            return sock
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise

    def _tunnel(self, conn: socket.socket, client: tuple, target: str) -> None:
        """CONNECT：能 MITM 就解密进差分，不能就老老实实做双向隧道（各自如实记录）。

        上游连不上也要**先记下来**再回 502 —— 探针/web 的职责是"如实记录我看到了什么"，
        连不上的那条 CONNECT 同样是证据（说明客户端试过访问那个站点）。
        """
        host, _, port_s = target.partition(":")
        upstream = None
        try:
            upstream = self._connect_upstream(host, int(port_s or 443))
        except OSError as exc:
            self._tunnel_record(conn, client, host, target,
                                f"HTTPS：CONNECT 隧道（上游 {target} 不可达：{exc}）")
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # 可选 MITM：装有 cryptography 且未关掉时，解密进差分；
        # 没装 / 握手失败 / 用户关掉 → 隧道直通（如实计数），零依赖底线不动。
        if self.cfg.mitm and _mitm_mod.mitm_available():
            try:
                self._mitm_relay(conn, upstream, host, client)
                return
            except _UpstreamTLSFailed as exc:
                # 上游握不上：这条 HTTPS 是真的到不了（本机直连被挡、或上游代理
                # 节点不通）。这与客户端、与本地 CA 都无关，如实这么记。
                self._tunnel_record(conn, client, host, target,
                                    f"上游 TLS 握手失败：到不了 {target}"
                                    f"（本机直连被挡或上游代理节点不通，"
                                    f"与本地 CA 无关）：{exc}",
                                    failed="upstream")
                return
            except ssl.SSLError as exc:
                # 客户端拒绝了本地 CA（典型：证书固定）。这条连接已废 ——
                # 客户端看到的是我们的证书，无法"退回"成隧道，只能如实记录。
                self._tunnel_record(conn, client, host, target,
                                    f"客户端拒绝本地 CA（证书固定或未信任）："
                                    f"{exc.__class__.__name__}",
                                    failed="client")
                return
            finally:
                upstream.close()
        try:
            self._tunnel_record(conn, client, host, target,
                                "HTTPS：CONNECT 隧道直通，不拆包"
                                "（未启用本地 CA 解密：未装依赖或 --no-mitm）")
            _pump(conn, upstream)
        finally:
            upstream.close()

    def _tunnel_record(self, conn: socket.socket, client: tuple, host: str,
                       target: str, note: str,
                       failed: str | None = None) -> None:
        """记一条「没拆成」的记录；``failed`` 是机器可读的归因（见 :meth:`summary`）。"""
        with self.lock:
            self.seq += 1
            record = {"ts": datetime.now().isoformat(timespec="seconds"),
                      "seq": self.seq, "client": f"{client[0]}:{client[1]}",
                      "case_id": None, "method": "CONNECT", "host": host,
                      "path": "", "target": target, "tunnel": True, "count": 1,
                      "skip": note, "analysis": None, "elapsed_ms": None,
                      "tunnel_failed": failed}
            self.records.append(record)
        self._emit(record)

    def _mitm_relay(self, conn: socket.socket, upstream: socket.socket,
                    host: str, client: tuple) -> None:
        """对一条已建立的 CONNECT 隧道做本地 CA 中间人：明文请求进差分管线。

        每条请求：读客户端明文 → 记录/入分析队列 → 用 TLS 转给真实站点 →
        把响应原样送回客户端。上游我们主动带 ``Connection: close``（复用
        :func:`_forward_bytes`），所以响应读到 EOF 即完整。

        **两条 TLS 的顺序就是归因**：先握上游、再握客户端。反过来（先握客户端）
        上游失败时异常同样落在 ``ssl.SSLError`` 上，会被记成"客户端拒绝证书"——
        网络的锅扣到客户端头上。所以上游先握、失败即抛
        :class:`_UpstreamTLSFailed`；留给上层的 ``ssl.SSLError`` 就只剩
        "客户端不肯接受我们的证书"这一种含义。顺序不影响正常链路：客户端发来的
        ClientHello 待在缓冲区里等我们，不会丢。
        """
        try:
            up_tls = _mitm_mod.upstream_context().wrap_socket(
                upstream, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            raise _UpstreamTLSFailed(f"{type(exc).__name__}: {exc}") from exc
        try:
            _mitm_mod.ensure_ca()
            client_tls = _mitm_mod.leaf_context(host).wrap_socket(
                conn, server_side=True)
        except BaseException:
            up_tls.close()
            raise
        try:
            client_tls.settimeout(UPSTREAM_TIMEOUT)
            up_tls.settimeout(UPSTREAM_TIMEOUT)
            while True:
                try:
                    raw = _read_request(client_tls)
                except (OSError, ssl.SSLEOFError):
                    break
                if not raw:
                    break
                method, target, headers = _parse_head(_head_and_body(raw)[0])
                self._enroll(raw, method, f"https://{host}{target}",
                             host, target, client, mitm=True)
                try:
                    up_tls.sendall(_forward_bytes(raw))
                    while True:
                        chunk = up_tls.recv(65536)
                        if not chunk:
                            break
                        client_tls.sendall(chunk)
                except (OSError, ssl.SSLError):
                    break
        finally:
            for sock in (client_tls, up_tls):
                try:
                    sock.close()
                except OSError:
                    pass

    def _enroll(self, raw: bytes, method: str, target: str, host: str, path: str,
                client: tuple, *, mitm: bool = False,
                normalized: bool = False, evidence: bytes | None = None) -> None:
        """记录一条请求并送进分析队列（HTTP 明文与 MITM 解密共用这一个口）。

        ``raw`` 是**分析对象**（明文路径下是源站会看到的归一化字节）；
        ``evidence`` 是**原始留证字节**（缺省 = raw，用于留证列）。
        """
        case_id = case_id_of(raw)
        evidence = base64.b64encode((evidence if evidence is not None else raw)[:4096]
                                    ).decode("ascii")

        with self.lock:
            self.seq += 1
            previous = self.seen.get(case_id)
            if previous is not None:
                previous["count"] += 1
                self.duplicate_counts[case_id] = previous["count"]
                record = previous
                duplicate = True
            else:
                record = {"ts": datetime.now().isoformat(timespec="seconds"),
                          "seq": self.seq, "client": f"{client[0]}:{client[1]}",
                          "case_id": case_id, "method": method, "target": target,
                          "host": host, "path": path, "tunnel": False, "count": 1,
                          "mitm": mitm, "skip": "", "analysis": None,
                          "elapsed_ms": None,
                          "raw_len": len(raw), "raw_b64": evidence,
                          "normalized": normalized}
                self.seen[case_id] = record
                self.records.append(record)
                duplicate = False

        if duplicate:
            self._emit(dict(record))             # 重复请求：只计数，不重复分析
        else:
            reason = "" if self.cfg.analyze_all else _skip_reason(method, path)
            if reason:
                record["skip"] = reason
                self._emit(record)
            else:
                record["raw"] = raw
                try:
                    self.queue.put_nowait(record)
                except queue.Full:
                    record.pop("raw", None)
                    record["skip"] = "分析队列已满（代理仍在正常转发）"
                    self._emit(record)

    def _record_and_forward(self, conn: socket.socket, client: tuple, method: str,
                            target: str, headers: dict, raw: bytes) -> None:
        host, port, path = _upstream_of(target, headers)
        # 分析对象 = 源站会看到的那份字节（见 _origin_form 的说明）；原始字节留证
        analyzed = _origin_form(raw, path)
        self._enroll(analyzed, method, target, host, path, client,
                     normalized=analyzed != raw, evidence=raw)

        # 转发：只加 Connection: close，其余原样；有上游代理时改绝对形式
        try:
            with self._connect_upstream(host, port) as up:
                out = (_upstream_request(raw, host, port) if self.cfg.upstream
                       else _forward_bytes(raw))
                up.sendall(out)
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(chunk)
        except OSError:
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass

    # ------------------------------------------------------------------ 生命周期

    def bind(self) -> None:
        """先把端口占住。

        为什么单独一步：网页里点"开始"时，端口被占必须**同步**报回给用户，
        而不是死在后台线程里只留一行没人看的日志。
        """
        if self._server is not None:
            return
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.cfg.host, self.cfg.port))
        except OSError:
            server.close()
            raise
        server.listen(128)
        server.settimeout(0.3)
        self._server = server

    def serve_forever(self) -> None:
        self.bind()
        server = self._server
        self.worker.start()
        if self.cfg.interpreter is not None:
            self.interpret_thread.start()        # 解读是旁路：没开就一条线程都不起
        if self.cfg.mitm and _mitm_mod.mitm_available():
            ca = _mitm_mod.ensure_ca()
            print(f"捕获代理已就绪：{self.cfg.host}:{self.cfg.port}"
                  f"（HTTP 明文 + HTTPS 本地 CA 解密；不信任本地 CA 的客户端走隧道直通）")
            print(_mitm_mod.install_hint(ca))
        else:
            print(f"捕获代理已就绪：{self.cfg.host}:{self.cfg.port}"
                  f"（HTTP 明文；HTTPS 只做隧道直通"
                  + ("——已关闭 MITM）" if not self.cfg.mitm
                    else "——装 `pip install cryptography` 可启用本地 CA 解密）"))
        print("把浏览器 / 客户端 / 系统代理指向它即可；Ctrl+C 停止。"
              "仅用于你自有或已获授权的目标。MITM 解密只发生本机，数据不出本机。")
        if self.cfg.jsonl:
            print(f"记录写入：{self.cfg.jsonl}", flush=True)
        try:
            while not self.cfg.stop.is_set():
                try:
                    conn, client = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle, args=(conn, client),
                                 daemon=True).start()
        finally:
            self.cfg.stop.set()
            try:
                self.queue.put_nowait(None)
            except queue.Full:
                pass
            server.close()

    # ------------------------------------------------------------------ 小结

    def summary(self) -> dict:
        analyzed = [r for r in self.records if r.get("analysis")]
        security = [r for r in analyzed if r["analysis"]["security"]]
        return {"requests": len(self.records),
                "analyzed": len(analyzed),
                "skipped": len([r for r in self.records if r.get("skip")]),
                "tunnels": len([r for r in self.records if r.get("tunnel")]),
                "tls_failed": len([r for r in self.records
                                   if r.get("tunnel_failed") == "client"]),
                "upstream_failed": len([r for r in self.records
                                        if r.get("tunnel_failed") == "upstream"]),
                "security_requests": len(security),
                "divergences": sum(r["analysis"]["divergences"] for r in analyzed),
                "interpreted": self.interpret_stats["done"],
                "interpret_failed": self.interpret_stats["failed"],
                "interpret_skipped": (self.interpret_stats["dropped"]
                                      + self.interpret_stats["capped"])}

    # ------------------------------------------------------------------ 删记录

    def forget(self, seq: int) -> int:
        """从网页那份列表里删掉一条记录，返回删掉了几条。

        按 ``seq`` 定位而不是 case_id：HTTPS 隧道那条根本没有 case_id，同一份字节
        重复出现时多条记录也共用一个 case_id —— 只有 seq 是每条记录唯一的。

        删的只是**内存里给网页看的那份视图**（记录 / ×N 计数 / 它的模型解读）：
        JSONL 是留证台账，那份记录一个字节都不动 —— 网页是视图，台账是事实。
        删掉之后同一份字节再来，会当作新记录重新出现（计数从 1 开始）。
        """
        if not seq:
            return 0
        with self.lock:
            target = next((r for r in self.records if r.get("seq") == seq), None)
            if target is None:
                return 0
            case_id = target.get("case_id")
            self.records = deque((r for r in self.records if r.get("seq") != seq),
                                 maxlen=MAX_RECORDS)
            if case_id:
                self.seen.pop(case_id, None)
                self.duplicate_counts.pop(case_id, None)
                self.interpretations = deque(
                    (it for it in self.interpretations if it.get("case_id") != case_id),
                    maxlen=INTERPRET_KEEP)
            return 1

    def forget_all(self) -> int:
        """清空网页那份列表（同样不动 JSONL）。

        ``interpret_stats`` 是**模型调用**的账（多少次产出 / 失败 / 跳过），
        也是单次捕获的调用上限依据，所以清列表不重置它：清了它，等于把
        INTERPRET_MAX 那道闸门又放开一次。
        """
        with self.lock:
            removed = len(self.records)
            self.records.clear()
            self.seen.clear()
            self.duplicate_counts.clear()
            self.interpretations.clear()
            return removed


def summary_line(parts: dict) -> str:
    """一行小结（Ctrl+C 收工时打印；测试也用它）。"""
    return (f"共看到 {parts['requests']} 条请求："
            f"分析 {parts['analyzed']} 条 · 跳过 {parts['skipped']} 条 · "
            f"HTTPS 隧道 {parts['tunnels']} 条"
            f"（客户端拒绝本地 CA {parts.get('tls_failed', 0)} 条 · "
            f"上游到不了 {parts.get('upstream_failed', 0)} 条） · "
            f"分歧 {parts['divergences']} 处 · 安全级 {parts['security_requests']} 条请求")


def serve(config: Config) -> int:
    proxy = CaptureProxy(config)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    print()
    print(summary_line(proxy.summary()))
    return 0


__all__ = ["Config", "CaptureProxy", "serve", "summary_line", "STATIC_SUFFIXES"]
