"""探针服务：把"某处收到的字节"变成一个可被差分的观测。

    python -m ced.probe.server --policy ref-cl-first --data-port 8800 --api-port 8801

两个端口：
  数据口  扮演**真实后端**：收原始字节 → 按策略解析 → 记录一个视角；
          回复一个合法的 HTTP 响应（响应体就是观测 JSON），
          这样前置（nginx 等）与直连客户端都能正常使用同一端口。
  控制口  GET /health、GET /views、POST /reset —— 供差分器取回视角。

**收全就处理，绝不空等**。三种收尾方式，优先级从高到低：

1. 客户端半关闭（替身前置会透传）→ 读到 EOF 立刻处理；
2. **按 HTTP 消息边界判断收全**（有 Content-Length 且没有 Transfer-Encoding）→
   到边界就处理。真实 nginx 不对上游半关闭，没有这一条就得白等
   ``IDLE_TIMEOUT``（5 秒/条，一轮 60 条就是 5 分钟）；
3. 判不出来（分块体 / CL+TE 冲突 / 畸形 CL）→ 回落 EOF/空闲超时。

第 2 条之后还给 **``DRAIN_GRACE`` 一小段宽限**：前置常把"这条请求 + 夹带的尾巴"
放在同一次 write 里，宽限只是把**同一批已经在路上**的字节读进来，不是等对端
再说下一句。少了它，恰好会把夹带类分歧最要紧的那几个字节截掉。
**任何一条路径都不合成视角**：判不出来就等，不猜边界。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..adapters import ADAPTERS, names
from ..impls import local_specs

MAX_BYTES = 1 << 20        # 1MB 上限，防内存爆炸
IDLE_TIMEOUT = 5.0         # 兜底：客户端不半关闭时
#: 认出"一条消息收全了"之后再等这么久 —— 只为把同一批字节读进来（见模块注释）
#: 跨网链路（写入被拆成多段）可以调大：``CED_PROBE_DRAIN=0.5``。
DRAIN_GRACE = float(os.environ.get("CED_PROBE_DRAIN") or 0.15)

_lock = threading.Lock()
_views: list[dict] = []
_next_id = 1


# --------------------------------------------------------------------------- 观测

def observe(payload: bytes, policy, parse, extract) -> dict:
    res = parse(extract(payload), policy)
    return {"ok": res.ok,
            "error": None if res.ok else res.reason,
            "fields": res.to_fields()}


def record(payload: bytes, policy, parse, extract) -> dict:
    """记录一个视角并返回它（id 单调递增，供差分器区分新旧）。"""
    global _next_id
    view = {"id": 0, "raw_len": len(payload),
            **observe(payload, policy, parse, extract)}
    with _lock:
        view["id"] = _next_id
        _next_id += 1
        _views.append(view)
    return view


def get_views() -> list[dict]:
    with _lock:
        return [dict(v) for v in _views]


def reset() -> None:
    with _lock:
        _views.clear()


# --------------------------------------------------------------------------- 数据口

def _http_reply(obs: dict) -> bytes:
    body = json.dumps(obs, ensure_ascii=False).encode("utf-8")
    status = b"200 OK" if obs.get("ok") else b"400 Bad Request"
    return (b"HTTP/1.1 " + status + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body)


def handle_conn(conn: socket.socket, policy, parse, extract) -> None:
    conn.settimeout(IDLE_TIMEOUT)
    buf = b""
    try:
        while len(buf) < MAX_BYTES:
            need = message_length(buf)
            if need is not None and len(buf) >= need:
                buf += _drain(conn)        # 收全了：捞走同一批，立刻处理
                break
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                break
            if not chunk:              # 客户端半关闭 → 立刻处理
                break
            buf += chunk
        conn.sendall(_http_reply(record(buf, policy, parse, extract)))
    except OSError:
        pass
    finally:
        conn.close()


def message_length(buf: bytes) -> int | None:
    """按 HTTP/1.1 消息边界算"收全了没有"：够了返回总字节数，判不出来返回 None。

    只在**能确定**的时候给结论 —— 有 ``Content-Length``、没有 ``Transfer-Encoding``、
    CL 是合法十进制、且没有重复 CL。其余一律 None（回落到 EOF / 空闲超时）：
    分块体的边界要靠读完 0 块才知道，CL+TE 冲突本身就是分歧点，
    这时候"猜一个边界"会把本该观测到的字节截掉 —— 那正是夹带类分歧最要紧的地方。
    """
    sep = buf.find(b"\r\n\r\n")
    if sep == -1:
        return None
    length = None
    for line in buf[:sep].split(b"\r\n")[1:]:
        if b":" not in line or line[:1] in (b" ", b"\t"):
            return None                # 畸形行 / obs-fold 折行：不猜
        name, _, value = line.partition(b":")
        low = name.strip().lower()
        if low == b"transfer-encoding":
            return None
        if low == b"content-length":
            if length is not None:
                return None            # 重复 CL：定帧有歧义，不猜
            try:
                length = int(value.strip())
            except ValueError:
                return None
    if length is None:
        length = 0                     # 既没有 CL 也没有 TE → 这条请求没有体（RFC 7230）
    if length < 0:
        return None
    return sep + 4 + length


def _drain(conn: socket.socket, grace: float = DRAIN_GRACE) -> bytes:
    """把消息边界之后、**同一批已经在路上**的字节读进来。

    这是"读"不是"猜"：读到的每个字节本来就会在下一瞬到达，观测内容与
    "一直等到 EOF/超时"完全一致，只是不再白等那 5 秒。总时长封顶 ``grace``，
    所以对端若一直不停地说，也不会把这里变成无底洞。
    """
    out = b""
    deadline = time.monotonic() + grace
    while len(out) < MAX_BYTES:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        conn.settimeout(left)
        try:
            chunk = conn.recv(65536)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        out += chunk
    conn.settimeout(IDLE_TIMEOUT)      # 别让收尾的 sendall 带着毫秒级超时
    return out


# --------------------------------------------------------------------------- 控制口

class _ApiHandler(BaseHTTPRequestHandler):

    def do_GET(self):                                   # noqa: N802
        if self.path == "/health":
            self._send(200, json.dumps(self._identity(),
                                       ensure_ascii=False).encode("utf-8"))
        elif self.path == "/views":
            self._send(200, json.dumps({"views": get_views()},
                                       ensure_ascii=False).encode("utf-8"))
        else:
            self._send(404, b'{"error":"not found"}')

    def _identity(self) -> dict:
        """自报身份：我在哪个领域、用的是哪种读法。

        引擎起任务前拿它对一遍 —— "记录员"和"这次要跑的领域"不是一回事，
        那整轮结果都没有意义，必须当场拦住（见 ``orchestrate.topology``）。
        旧版探针没有这两个字段，引擎会如实报"无法校验"。
        """
        ident = getattr(self.server, "ced_identity", None) or {}
        return {"status": "ok", "domain": ident.get("domain", ""),
                "policy": ident.get("policy", "")}

    def do_POST(self):                                  # noqa: N802
        if self.path == "/reset":
            reset()
            self._send(204, b"")
        else:
            self._send(404, b'{"error":"not found"}')

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):                       # 安静模式
        pass


# --------------------------------------------------------------------------- 启动

def serve(host: str, data_port: int, api_port: int, policy,
          *, domain: str = "http1-framing") -> None:
    adapter = ADAPTERS[domain]()
    _, parse = adapter.local_parser()
    extract = adapter.extract

    api = ThreadingHTTPServer((host, api_port), _ApiHandler)
    #: 控制口自报的身份，由 /health 返回（线程与 handler 都是这个 server 的实例）
    api.ced_identity = {"domain": domain, "policy": getattr(policy, "name", "")}
    threading.Thread(target=api.serve_forever, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, data_port))
    srv.listen(64)
    print(f"probe ready: data={host}:{data_port} api={host}:{api_port} "
          f"domain={domain} policy={policy.name}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn,
                         args=(conn, policy, parse, extract), daemon=True).start()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="CED 探针服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--domain", choices=names(), default="http1-framing",
                    help="领域名（默认 http1-framing）")
    ap.add_argument("--data-port", type=int, default=8800)
    ap.add_argument("--api-port", type=int, default=8801)
    ap.add_argument("--policy", default=None,
                    help="参照实现策略名，默认取该领域第一个参照实现；"
                         "见 ced.impls.reference.REFERENCES / 各领域 *_reference")
    args = ap.parse_args()

    adapter = ADAPTERS[args.domain]()
    policy_of, _ = adapter.local_parser()
    impl_id = args.policy or local_specs(args.domain)[0].impl_id
    serve(args.host, args.data_port, args.api_port, policy_of(impl_id),
          domain=args.domain)


if __name__ == "__main__":
    main()
