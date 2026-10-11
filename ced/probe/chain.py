"""链路观测：看**真实前置**到底把什么字节转发给了后端。

收敛进来的能力（原先在 diffmine 里叫 `chain_views`）：
    把 payload 发给前置，前置按自己的定帧策略处理后转发，
    再从前置后面的探针那里取回"后端实际收到了什么"。

与旧实现的差别有两点，都是针对已知缺陷的：

1. **不做"到达顺序配对"**。每次观测前先 `POST /reset` 清空探针的视角，
   再发送、再取第一条新视角 —— 不存在"迟到的视角被下一条用例消费"的错位。
2. **探测失败必须抛错**。前置不可达、或没把任何字节转发过去时，
   直接抛 `ProbeUnreachable`，绝不合成一个"被拒绝"的视角 ——
   合成的视角必然与基线不同，会把"探测失败"变成成片的假阳性安全结论。
"""
from __future__ import annotations

import json
import socket
import time
import urllib.request

from ..contracts import Observation, ProbeRejected, ProbeUnreachable

SEND_TIMEOUT = 10.0     # 发字节 + 读响应的超时
VIEW_WAIT = 3.0         # 等探针记录视角的超时（前置没回响应时用）
#: 前置已经回了响应、但探针还没有视角 —— 只给这么久的宽限就判定"它没转发"。
#: 转发型前置必须先拿到后端响应才能回复客户端，所以视角必然先于响应出现。
REJECT_GRACE = 1.0

#: 活性复探用的最小请求。只在"某条用例既没被转发、也没回响应"时发一次，
#: 用来判断链路到底还活着没有。Host 特意写成可识别的值，方便在前置日志里
#: 认出"这是引擎在探链路，不是某条用例"。
LIVENESS_PAYLOAD = (b"GET / HTTP/1.1\r\nHost: ced-liveness-check\r\n"
                    b"Connection: close\r\n\r\n")


def _parse_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host or "127.0.0.1", int(port)


def _send_raw(addr: tuple[str, int], payload: bytes, *,
              half_close: bool = True) -> bytes:
    """发原始字节后读尽响应。

    ``half_close``（本机实测过的两种前置行为**不一样**，所以必须可选）：

    ``True``（默认 / 快路径）
        发完就半关闭写端，用 FIN 告诉对端"输入到此为止"。
        对**替身前置**（``ced/probe/front.py``）这是最快路径：它把这个半关闭透传给
        探针，探针读到 EOF 立刻处理 —— 一条用例约 0.004s。

    ``False``（普通 HTTP 客户端行为）
        curl / 浏览器都不会半关闭。**真实 nginx 必须用这个模式**：
        客户端立即半关闭时，nginx 1.25.5 既不会把任何字节转发给上游、也不会回响应
        （实测：探针记到的视角 ``raw_len=0``，客户端 0.0s 就断了），
        于是整轮链路扫描会以"链路不可用"中止。
        代价是探针只能靠 ``IDLE_TIMEOUT``（5 秒）判定输入结束，每条用例约 5s。
        详见 :meth:`ChainEvaluator._observe` 的注释与 ``docker/README.md``。
    """
    with socket.create_connection(addr, timeout=SEND_TIMEOUT) as sock:
        sock.sendall(payload)
        if half_close:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        out = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out


class ChainEvaluator:
    """通过"前置 → 探针"观测链路。``probe_api`` 是前置后面那个探针的控制口。"""

    def __init__(self, front: str, probe_api: str) -> None:
        self.front = _parse_addr(front)
        self.api = _parse_addr(probe_api)
        #: 这个前置吃不吃"客户端半关闭"那一套。None/True 起手先试快路径，
        #: 一旦发现前置既没转发也没回响应，就改成普通客户端模式（不半关闭）并**记住**，
        #: 后续用例不再白试一遍 —— 真 nginx 只多花一次连接，替身前置仍走 4ms 快路径。
        self._half_close = True

    # ---------------------------------------------------------------- 控制口

    def _api(self, path: str, method: str = "GET") -> bytes:
        url = f"http://{self.api[0]}:{self.api[1]}{path}"
        req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT) as resp:
            return resp.read()

    def healthy(self) -> bool:
        try:
            return json.loads(self._api("/health")).get("status") == "ok"
        except Exception:
            return False

    def reset(self) -> None:
        self._api("/reset", method="POST")

    def views(self) -> list[dict]:
        return json.loads(self._api("/views")).get("views", [])

    # ---------------------------------------------------------------- 观测

    @property
    def label(self) -> str:
        return f"{self.front[0]}:{self.front[1]}"

    def _await_view(self, payload: bytes, response: bytes) -> dict | None:
        """等探针写出本次用例的视角；等不到返回 None。

        前置把字节转发给后端后，必须等后端响应才能回复客户端 —— 所以**响应到达时，
        视角早已写好**。反过来，如果前置回了响应却没有视角，它一定是没转发。
        据此把"被拒绝"的等待从 VIEW_WAIT 缩短到 REJECT_GRACE：
        一轮扫描里被拒绝的用例可能占多数，白等 3 秒会把整轮扫描拖成分钟级。
        """
        deadline = time.time() + (REJECT_GRACE if response else VIEW_WAIT)
        while time.time() < deadline:
            for view in self.views():
                # 零字节观测不可能对应一个非空请求 —— 它一定是端口探活之类的
                # 噪声连接被前置转发进来的。若把它当成本次用例的视角，
                # 就会产出与基线"必然不同"的假阳性。跳过它，继续等真正的视角。
                if payload and not view.get("raw_len"):
                    continue
                return view
            time.sleep(0.02)
        return None

    def _link_alive(self) -> bool:
        """链路还活着吗：拿一条最小正常请求走一遍，探针能记到视角就是活着。

        只在"某条用例既没被转发、也没回响应"时才调用 —— 用来把两种完全不同的情况分开：

          * 前置**静默丢掉**了这一条。真实 gunicorn 就是这样：对裸 LF 分行、大写块长
            （``0A``）这类它不认的写法，既不转发、也不回响应，直接关连接（本机实测）。
            这是**前置的正常行为**，只该跳过这一条并计数。
          * 链路真的坏了：连最小正常请求都转不过去（或上游不通）。

        把两者混为一谈的代价是两头都错：判成故障 → 整轮扫描被一条畸形请求打断
        （对真实产品不可用）；判成拒绝 → 把"链路故障"降级成"全被拒绝"，
        于是一轮扫不出任何东西却看起来正常。所以这里多花一次请求去问清楚。
        """
        try:
            self.reset()
            response = _send_raw(self.front, LIVENESS_PAYLOAD,
                                 half_close=self._half_close)
        except OSError:
            return False
        return self._await_view(LIVENESS_PAYLOAD, response) is not None

    def _variants(self, payload: bytes) -> list[tuple[str, bytes]]:
        """被前置拒绝时尝试的「过门变形」。

        只修复**部署位置造成**的缺失（比如内置语料里有些请求没带 Host 头 ——
        真实攻击者一定会带），不改写任何与分歧语义相关的字节；改写过的变形
        一律不做，否则观测到的就不是客户的行为了。
        """
        head, sep, body = payload.partition(b"\r\n\r\n")
        variants: list[tuple[str, bytes]] = []
        if not sep or b"\r\n" not in head:
            return variants        # 裸 LF 等畸形行尾：补头必然改变分歧语义，不做
        lines = head.split(b"\r\n")
        has_host = any(ln.lower().startswith(b"host:") for ln in lines[1:])
        if not has_host:
            patched = b"\r\n".join([lines[0], b"Host: ced-probe.local"] + lines[1:])
            variants.append(("补 Host 头", patched + b"\r\n\r\n" + body))
        return variants

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        try:
            self.reset()
        except OSError as exc:
            raise ProbeUnreachable(
                f"前置 {self.label} 后面的探针控制口 "
                f"{self.api[0]}:{self.api[1]} 不可达：{exc}") from exc

        # 先按记下来的模式试；若前置**既没转发、也没回响应**，换另一种客户端收尾方式
        # 再问一次。为什么值得多问一次（本机实测）：真实 nginx 对"客户端立即半关闭"
        # 的反应就是既不转发也不回响应 —— 若直接判成"链路不可用"，真实链路永远扫不了。
        modes = [self._half_close] + ([False] if self._half_close else [])
        last_response = b""
        for index, half_close in enumerate(modes):
            last = index == len(modes) - 1
            if index:
                # 换模式前清掉上一轮留下的噪声视角，避免它被下一条用例消费
                try:
                    self.reset()
                except OSError:
                    pass
            try:
                last_response = _send_raw(self.front, payload, half_close=half_close)
            except OSError as exc:
                raise ProbeUnreachable(f"前置 {self.label} 不可达：{exc}") from exc

            view = self._await_view(payload, last_response)
            if view is not None:
                self._half_close = half_close        # 记住这个前置吃哪一套
                fields = dict(view.get("fields", {}))
                # 实测诊断字段：真实前置转发了多少字节（不进 compare_keys，只供
                # 实机量化与 PoC --chain 使用 —— 见 adapters/http1_framing.quantify）
                fields["forwarded_raw_len"] = view.get("raw_len")
                return Observation(impl_id=impl_id,
                                   ok=view.get("ok", True),
                                   error=view.get("error"),
                                   fields=fields)
            if not last and not last_response:
                continue
            break

        if last_response:
            # 过门变形：前置拒绝了，但请求缺的可能是**部署性**字段（如 Host）——
            # 补上再试一次；变形仍被拒才判"前置拒绝"。变形成功的观测带
            # ``front_adapted`` 诊断字段，报告里看得出它被改过。
            for label, candidate in self._variants(payload):
                try:
                    self.reset()
                    response = _send_raw(self.front, candidate,
                                         half_close=self._half_close)
                except OSError:
                    continue
                view = self._await_view(candidate, response)
                if view is not None:
                    fields = dict(view.get("fields", {}))
                    fields["forwarded_raw_len"] = view.get("raw_len")
                    fields["front_adapted"] = label
                    return Observation(impl_id=impl_id,
                                       ok=view.get("ok", True),
                                       error=view.get("error"),
                                       fields=fields)
            raise ProbeRejected(
                f"前置 {self.label} 收到 {len(payload)} 字节，"
                f"但未向后端转发任何字节（回了 {len(last_response)} 字节响应）"
                f"—— 按自身策略拒绝了这条请求，本条不可观测")
        # 既没转发、也没回响应 —— 必须再问一次才知道是"被静默丢掉"还是"链路坏了"
        if self._link_alive():
            raise ProbeRejected(
                f"前置 {self.label} 收到 {len(payload)} 字节后**静默丢弃**了它"
                f"（不转发、也不回响应），但用一条最小正常请求复探时链路是通的"
                f"—— 按「该前置不接受这条请求」处置，本条不可观测")
        raise ProbeUnreachable(
            f"前置 {self.label} 没有把任何字节转发到探针，也没有回响应"
            f"（被拒绝，或链路没起来）—— 拒绝合成视角，避免把探测失败当成耦合误差")
