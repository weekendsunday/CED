"""HTTP 消息的结构化拆解/重组工具（保持原始行尾，不擅自规范化）。"""
from __future__ import annotations

from dataclasses import dataclass

CRLF = b"\r\n"


@dataclass
class Message:
    lines: list[bytes]   # 请求行 + 头行
    eol: bytes           # 行分隔符（原样保留）
    sep: bytes           # 头部结束分隔符
    tail: bytes          # 后续字节（body 等，原样）

    def build(self) -> bytes:
        return self.eol.join(self.lines) + self.sep + self.tail

    def header_lines(self) -> list[tuple[int, bytes]]:
        """(行号, 内容)，跳过请求行。"""
        return [(i, ln) for i, ln in enumerate(self.lines) if i > 0]


def split(payload: bytes) -> Message | None:
    """拆解一条消息；找不到头部终止符返回 None。"""
    idx = payload.find(CRLF + CRLF)
    sep = CRLF + CRLF
    if idx == -1:
        idx = payload.find(b"\n\n")
        sep = b"\n\n"
        if idx == -1:
            return None
    head = payload[:idx]
    eol = CRLF if CRLF in head else b"\n"
    lines = head.split(eol)
    return Message(lines=lines, eol=eol, sep=sep, tail=payload[idx + len(sep):])


def drop_line(msg: Message, index: int) -> Message:
    """去掉某一行，返回新消息。"""
    return Message(lines=[ln for i, ln in enumerate(msg.lines) if i != index],
                   eol=msg.eol, sep=msg.sep, tail=msg.tail)


def replace_line(msg: Message, index: int, line: bytes) -> Message:
    lines = list(msg.lines)
    lines[index] = line
    return Message(lines=lines, eol=msg.eol, sep=msg.sep, tail=msg.tail)


def header_name(line: bytes) -> bytes | None:
    """取头名（小写）；不是头行返回 None。"""
    idx = line.find(b":")
    if idx <= 0:
        return None
    return line[:idx].strip().lower()


# --------------------------------------------------------------------------- 改写

def request_line_parts(line: bytes) -> tuple[bytes, bytes, bytes] | None:
    """拆请求行 → (method, target, version)；拆不出来返回 None。"""
    parts = line.split()
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def with_target(payload: bytes, new_target: bytes) -> bytes:
    """把请求行的 target 换成 ``new_target``。

    认不出请求（裸 target / 非 HTTP 字节）时**按裸对象处理**：直接返回新值。
    各领域的 ``extract`` 就是这么判的，改写必须与它同一口径 ——
    否则"裸对象"输入会被硬塞进一个根本不存在的请求行里。
    """
    msg = split(payload)
    if msg is None or not msg.lines:
        return new_target
    parts = request_line_parts(msg.lines[0])
    if parts is None:
        return new_target
    method, _old, version = parts
    msg.lines[0] = b" ".join((method, new_target, version))
    return msg.build()


def with_header(payload: bytes, name: bytes, value: bytes) -> bytes:
    """把头 ``name`` 的值换成 ``value``（保留原头名的写法）；没有就追加。

    认不出请求时按裸对象处理：直接返回新值（Host 领域的观测对象就是头值本身）。
    """
    msg = split(payload)
    if msg is None or not msg.lines:
        return value
    key = name.lower()
    for index, line in enumerate(msg.lines):
        if index == 0:
            continue
        idx = line.find(b":")
        if idx > 0 and line[:idx].strip().lower() == key:
            return replace_line(msg, index, line[:idx] + b": " + value).build()
    msg.lines.append(name + b": " + value)
    return msg.build()


# --------------------------------------------------------------------------- 规范写法

#: RFC 3986 unreserved —— 百分号编码时不需要转义的字符
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def brief(raw: bytes, limit: int = 32) -> str:
    """把一段字节压成适合写进"改了什么"的人话片段。"""
    text = raw[:limit].decode("utf-8", "replace")
    return text + ("…" if len(raw) > limit else "")


def percent_encode(text: str, safe: str = "") -> str:
    """把文本按 UTF-8 百分号编码；规范形式是**大写十六进制**（RFC 3986 §2.1）。

    为什么一定要重编一遍：歧义恰恰藏在"没写清楚"的字节里 —— ``%2e%2e`` 到底
    是不是 ``..``、``%41`` 到底是不是 ``A``。统一写成规范形式，每个实现读到的
    就是同一个东西。
    """
    extra = set(safe)
    out: list[str] = []
    for ch in text:
        if ch in _UNRESERVED or ch in extra:
            out.append(ch)
        else:
            for byte in ch.encode("utf-8", "surrogateescape"):
                out.append(f"%{byte:02X}")
    return "".join(out)


def percent_encode_like(text: str, template: str) -> str:
    """只修**字符编码**、不动 URL 结构的百分号编码。

    ``template`` 是原始写法：在它里面以**字面 ASCII** 出现过的字符保持原样（这样
    ``?`` ``&`` ``=`` ``/`` 这类结构字符不会被顺手编码掉，把一条 URL 编成一段
    谁也认不出的字节），只有"解码出来的那部分"才转义成 ``%XX``。

    ``%`` 永远转义 —— 它本身就是歧义的源头，留着它等于把歧义又写回去。
    """
    safe = {ch for ch in template
            if ch.isascii() and ch.isprintable() and ch != "%"}
    out: list[str] = []
    for ch in text:
        if ch in safe:
            out.append(ch)
        else:
            for byte in ch.encode("utf-8", "surrogateescape"):
                out.append(f"%{byte:02X}")
    return "".join(out)


def with_path(payload: bytes, new_path: bytes) -> bytes:
    """把请求行 target 里 ``?`` **之前**的部分换成 ``new_path``（查询串原样保留）。

    与 :func:`with_target` 的区别：绝对形式的 target（``http://host/p``）也算路径段，
    只换它、不动 ``?`` 之后。认不出请求时按裸对象处理，但**仍然只换问号之前那段** ——
    否则会把查询串一起吞掉。
    """
    msg = split(payload)
    if msg is None or not msg.lines:
        base, sep, rest = payload.partition(b"?")
        return new_path + (sep + rest if sep else b"")
    parts = request_line_parts(msg.lines[0])
    if parts is None:
        base, sep, rest = payload.partition(b"?")
        return new_path + (sep + rest if sep else b"")
    method, target, version = parts
    _, sep, rest = target.partition(b"?")
    msg.lines[0] = b" ".join((method,
                              new_path + (sep + rest if sep else b""), version))
    return msg.build()


def with_query(payload: bytes, new_query: bytes) -> bytes:
    """把请求行 target 里 ``?`` 之后的查询串换成 ``new_query``。

    认不出请求时按裸对象处理：那时 payload **就是**查询串本身，直接返回新值
    （与 ``query-norm`` 的 ``extract`` 同一口径）。传空字节表示"不带查询串"。
    """
    msg = split(payload)
    if msg is None or not msg.lines:
        return new_query
    parts = request_line_parts(msg.lines[0])
    if parts is None:
        return new_query
    method, target, version = parts
    base = target.split(b"?", 1)[0]
    new_target = base + (b"?" + new_query if new_query else b"")
    msg.lines[0] = b" ".join((method, new_target, version))
    return msg.build()
