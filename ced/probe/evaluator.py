"""观测源：把 payload 交给某个实现/链路，取回它的"理解"。

三种 runner：
  local  —— 进程内跑参照实现（快、确定性，用于内部基准）
  socket —— 直连探针（把某处收到的字节变成观测）
  chain  —— 真实前置 → 探针，观测"前置转发出去的字节"（收敛自 diffmine）
"""
from __future__ import annotations

import json
import socket

from ..adapters import ADAPTERS
from ..contracts import ImplSpec, Observation, ProbeUnreachable, parse_addr
from ..impls import local_parser
from .chain import ChainEvaluator

SOCKET_TIMEOUT = 10.0
DEFAULT_API_PORT = 8801


def http_body(raw: bytes) -> bytes:
    """取出 HTTP 响应体；不是 HTTP 响应时原样返回（容忍自定义探针）。"""
    idx = raw.find(b"\r\n\r\n")
    return raw[idx + 4:] if idx != -1 else raw


class LocalEvaluator:
    """进程内跑参照实现。按 ``spec.domain`` 分派到该领域的解析器。

    与探针服务同一条口径：先按领域的 ``extract`` 从原始字节里取出观测对象，
    再交给该领域的解析器。内置语料是裸对象（``extract`` 原样返回）行为不变；
    喂完整请求时，两侧（本地参照实现 / 探针）可比较。
    """

    def __init__(self, specs: dict[str, ImplSpec]) -> None:
        self._specs = specs
        self._extract: dict[str, object] = {}

    def _extractor(self, domain: str):
        extract = self._extract.get(domain)
        if extract is None:
            extract = ADAPTERS[domain]().extract
            self._extract[domain] = extract
        return extract

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        spec = self._specs[impl_id]
        policy_of, parse = local_parser(spec.domain)
        policy = policy_of(spec.policy or spec.impl_id)
        res = parse(self._extractor(spec.domain)(payload), policy)
        return Observation(impl_id=impl_id, ok=res.ok,
                           error=None if res.ok else res.reason,
                           fields=res.to_fields())


class SocketEvaluator:
    """直连探针：发原始字节 → 收观测 JSON（探针以 HTTP 响应体返回）。"""

    def __init__(self, endpoint: str) -> None:
        self.addr = parse_addr(endpoint)

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        try:
            with socket.create_connection(self.addr, timeout=SOCKET_TIMEOUT) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)       # 发完即半关闭 —— 探针读到 EOF 立刻处理
                raw = b""
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
        except OSError as exc:
            raise ProbeUnreachable(f"探针 {self.addr[0]}:{self.addr[1]} 不可达：{exc}") from exc

        body = http_body(raw)
        if not body:
            raise ProbeUnreachable(f"探针 {self.addr[0]}:{self.addr[1]} 未返回观测")
        data = json.loads(body.decode("utf-8"))
        return Observation(impl_id=impl_id, ok=data.get("ok", True),
                           error=data.get("error"),
                           fields=data.get("fields", {}))


class Evaluator:
    """按 ImplSpec.runner 分派到 local / socket / chain。"""

    def __init__(self, specs: list[ImplSpec]) -> None:
        self.specs: dict[str, ImplSpec] = {s.impl_id: s for s in specs}
        self._local = LocalEvaluator(self.specs)
        self._sockets: dict[str, SocketEvaluator] = {}
        self._chains: dict[str, ChainEvaluator] = {}

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        spec = self.specs.get(impl_id)
        if spec is None:
            raise KeyError(f"未注册的实现: {impl_id}")

        if spec.runner == "chain":
            if spec.endpoint is None:
                raise ValueError(f"{impl_id} 的 runner=chain 需要 endpoint（前置地址）")
            probe_api = spec.probe_api or f"{parse_addr(spec.endpoint)[0]}:{DEFAULT_API_PORT}"
            client = self._chains.setdefault(
                impl_id, ChainEvaluator(spec.endpoint, probe_api))
            return client(impl_id, payload)

        if spec.runner == "socket":
            if spec.endpoint is None:
                raise ValueError(f"{impl_id} 的 runner=socket 需要 endpoint（探针地址）")
            client = self._sockets.setdefault(impl_id, SocketEvaluator(spec.endpoint))
            return client(impl_id, payload)

        return self._local(impl_id, payload)


__all__ = ["Evaluator", "LocalEvaluator", "SocketEvaluator", "ChainEvaluator",
           "ProbeUnreachable", "parse_addr", "http_body"]
