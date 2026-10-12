"""六类分歧轴：每个轴上构造"同一语义、不同写法"的请求。

轴不是随机选的 —— 每一条都是真实世界里出现过解析分歧的语法点。
这是"15 天能做完"的根本原因：搜索空间有限且可穷举。
"""
from __future__ import annotations

from .engine import build_corpus

CRLF = b"\r\n"
LF = b"\n"
HOST = (b"Host", b"localhost")

#: 六条轴的名字（与方案 §0.1 一致）
AXES: tuple[str, ...] = (
    "cl_value",
    "te_value",
    "cl_te_conflict",
    "chunk_syntax",
    "header_syntax",
    "request_line",
)


# --------------------------------------------------------------------------- 构造工具

def build(method: bytes = b"POST", target: bytes = b"/", headers: tuple = (),
          body: bytes = b"", sep: bytes = CRLF) -> bytes:
    lines = [method + b" " + target + b" HTTP/1.1"]
    lines += [k + b": " + v for k, v in headers]
    return sep.join(lines) + sep + sep + body


def chunked_body(payload: bytes, size: bytes | None = None, ext: bytes = b"",
                 sep: bytes = CRLF, terminate: bool = True) -> bytes:
    hex_size = size if size is not None else format(len(payload), "x").encode()
    out = hex_size + ext + sep + payload + sep
    if terminate:
        out += b"0" + sep + sep
    return out


def _chunked(headers_body: bytes) -> bytes:
    return build(headers=[HOST, (b"Transfer-Encoding", b"chunked")], body=headers_body)


# --------------------------------------------------------------------------- 各轴语料

def case_cl_value() -> list[bytes]:
    """A1 Content-Length 写法：前导零 / 符号 / 空白 / 非数字 / 重复。"""
    def req(cl: bytes, body: bytes = b"abc") -> bytes:
        return build(headers=[HOST, (b"Content-Length", cl)], body=body)

    return [
        req(b"3"),
        req(b"03"),
        req(b"+3"),
        req(b" 3"),
        req(b"3 "),
        req(b"abc"),
        req(b"0x3"),
        build(headers=[HOST, (b"Content-Length", b"3"), (b"Content-Length", b"3")], body=b"abc"),
        build(headers=[HOST, (b"Content-Length", b"3"), (b"Content-Length", b"4")], body=b"abcd"),
    ]


def case_te_value() -> list[bytes]:
    """A2 Transfer-Encoding 写法：重复 / 大小写 / 非标准 token / 多编码。"""
    body = chunked_body(b"hello")
    def req(*values: bytes) -> bytes:
        return build(headers=[HOST] + [(b"Transfer-Encoding", v) for v in values], body=body)

    return [
        req(b"chunked"),
        req(b"Chunked"),
        req(b"CHUNKED"),
        req(b"xchunked"),
        req(b"identity, chunked"),
        req(b"gzip, chunked"),
        req(b"chunked", b"chunked"),            # 重复头：两行 Transfer-Encoding: chunked
    ]


def case_cl_te_conflict() -> list[bytes]:
    """A3 CL 与 TE 并存 —— 请求走私的结构性前提。"""
    smuggled = b"GET /smuggled HTTP/1.1" + CRLF + b"Host: localhost" + CRLF + CRLF
    body = b"0" + CRLF + CRLF + smuggled
    cl = str(len(body)).encode()
    return [
        build(headers=[HOST, (b"Content-Length", cl), (b"Transfer-Encoding", b"chunked")], body=body),
        build(headers=[HOST, (b"Transfer-Encoding", b"chunked"), (b"Content-Length", cl)], body=body),
    ]


def case_chunk_syntax() -> list[bytes]:
    """A4 分块语法：扩展 / 十六进制大小写 / 裸 LF / 终止条件。"""
    return [
        _chunked(chunked_body(b"hello", size=b"5")),
        _chunked(chunked_body(b"hello", size=b"5;ext=1")),
        _chunked(chunked_body(b"hello", size=b"0A")),
        _chunked(chunked_body(b"hello", sep=LF)),
        _chunked(chunked_body(b"hello")[:-1]),                 # 缺最终 CRLF
    ]


def case_header_syntax() -> list[bytes]:
    """A5 头语法：行终止符 / obs-fold / 冒号前空白。"""
    base = build(headers=[HOST, (b"X-A", b"1"), (b"Content-Length", b"3")], body=b"abc")
    folded = CRLF.join([b"POST / HTTP/1.1", b"Host: localhost",
                        b"X-Fold: part1", b" part2"]) + CRLF + CRLF
    return [
        base,
        base.replace(CRLF, LF),                                 # 裸 LF 行尾
        folded,                                                 # obs-fold 折行
        build(headers=[HOST, (b"Content-Length ", b"3")], body=b"abc"),   # 冒号前空格
        build(headers=[HOST, (b"Content-Length", b"3")], body=b"abc",
              sep=LF),                                          # 全裸 LF
    ]


def case_request_line() -> list[bytes]:
    """A6 请求行：绝对 URI / 方法大小写 / 多余空白。"""
    return [
        build(headers=[HOST]),
        build(method=b"post", headers=[HOST]),
        build(target=b"http://localhost/", headers=[HOST]),
        build(headers=[HOST]).replace(b"POST / HTTP/1.1", b"POST  /  HTTP/1.1", 1),
    ]


_BUILDERS = {
    "cl_value": case_cl_value,
    "te_value": case_te_value,
    "cl_te_conflict": case_cl_te_conflict,
    "chunk_syntax": case_chunk_syntax,
    "header_syntax": case_header_syntax,
    "request_line": case_request_line,
}


def corpus() -> list[tuple[str, bytes]]:
    """全部种子：(轴名, 原始字节)。"""
    return build_corpus(AXES, _BUILDERS)
