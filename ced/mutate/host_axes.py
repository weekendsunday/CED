"""Host / 路由归一化领域的语料与定向变异。

与 ``url_axes.py`` 对称：每条轴上的用例都打在**已知有分歧历史的语法点**上，
而不是泛泛地 fuzz Host。载荷是 **Host 头的值**（authority 部分字节）本身 ——
这一领域的观测对象就是 Host。

轴与参照实现一一对应（见 ``impls/host_reference.AXIS_PAIRS``）：

    host_trailing_dot    尾随点 `example.com.`        → 虚拟主机绕过
    host_case_fold       主机名大小写                 → 缓存键分叉
    host_default_port    默认端口 `example.com:80`    → 缓存键 / 路由分叉
    host_userinfo        `user@example.com`           → 虚拟主机绕过 / 缓存投毒
    host_duplicate_dot   重复点 `example..com`        → 缓存键分叉
    host_idn             非 ASCII / IDN 主机名        → 虚拟主机绕过
    host_ipv6            IPv6 字面量规范形式          → ACL / 缓存键绕过
    host_percent         百分号编码主机名             → 缓存键分叉
    host_benign          完全规范的 Host              → **必须零分歧**（防假阳性）
"""
from __future__ import annotations

import ipaddress
import random
import re
from typing import Callable
from .engine import Mutator as _Mutator, build_corpus

#: 轴的顺序（与 AXIS_PAIRS 的键一致，外加良性对照轴）
AXES: tuple[str, ...] = (
    "host_trailing_dot",
    "host_case_fold",
    "host_default_port",
    "host_userinfo",
    "host_duplicate_dot",
    "host_idn",
    "host_ipv6",
    "host_percent",
    "host_benign",
)


# --------------------------------------------------------------------------- 各轴语料

def case_trailing_dot() -> list[bytes]:
    """A1 尾随点：DNS 根标签 / FQDN 写法，有的实现剥掉、有的原样保留。"""
    return [
        b"example.com.",
        b"a.b.c.",
        b"sub.example.com..",
        b"internal.example.",
    ]


def case_case_fold() -> list[bytes]:
    """A2 主机名大小写：DNS 不敏感，但原始字节的 vhost 表 / 缓存键敏感。"""
    return [
        b"EXAMPLE.com",
        b"Example.COM",
        b"WWW.EXAMPLE.COM",
        b"Admin.Internal.",
    ]


def case_default_port() -> list[bytes]:
    """A3 默认端口：`example.com:80` 与 `example.com` 是不是同一个键。"""
    return [
        b"example.com:80",
        b"example.com:443",
        b"example.com:8080",
        b"internal.example:80",
    ]


def case_userinfo() -> list[bytes]:
    """A4 userinfo：WHATWG URL 会剥掉，朴素处理器把整串当主机名。"""
    return [
        b"user@example.com",
        b"evil.com@victim.example",
        b"admin@internal.example:80",
        b"a@b@c.example",
    ]


def case_duplicate_dot() -> list[bytes]:
    """A5 重复点（空标签）：有的归一化折叠它，于是与规范名共键。"""
    return [
        b"example..com",
        b"a...b",
        b"..example.com",
        b"example.com..",
    ]


def case_idn() -> list[bytes]:
    """A6 IDN：浏览器按 IDNA 转 punycode，字节级服务器拿 Unicode 比对。"""
    return [
        "münich.example".encode("utf-8"),
        "café.example".encode("utf-8"),
        "例如.example".encode("utf-8"),
    ]


def case_ipv6() -> list[bytes]:
    """A7 IPv6 字面量：RFC 5952 规范形式（压缩 / 小写）与否。"""
    return [
        b"[0:0:0:0:0:0:0:1]",
        b"[2001:0DB8:0000:0000:0000:0000:0000:0001]",
        b"[::FFFF:127.0.0.1]",
    ]


def case_percent() -> list[bytes]:
    """A8 百分号编码主机名：有的反向代理解码 Host，有的原样保留。"""
    return [
        b"exa%6Dple.com",
        b"%65xample.com",
        b"example%2Ecom",
    ]


def case_benign() -> list[bytes]:
    """A0 良性对照：完全规范的 Host，**任何一对实现都不该有分歧**。

    没有这条轴，"假阳性"就没人守着 —— 与 ``test_url_norm`` 里
    「良性轴零分歧」那条测试是同一个用意。
    """
    return [
        b"example.com",
        b"a.b.c",
        b"sub.example.com",
        b"example.com:8080",
        b"192.168.0.1",
    ]


_BUILDERS = {
    "host_trailing_dot": case_trailing_dot,
    "host_case_fold": case_case_fold,
    "host_default_port": case_default_port,
    "host_userinfo": case_userinfo,
    "host_duplicate_dot": case_duplicate_dot,
    "host_idn": case_idn,
    "host_ipv6": case_ipv6,
    "host_percent": case_percent,
    "host_benign": case_benign,
}


def corpus() -> list[tuple[str, bytes]]:
    """全部种子：(轴名, Host 字节)。"""
    return build_corpus(AXES, _BUILDERS)


# --------------------------------------------------------------------------- 定向变异

def _op_append_dot(host: bytes, rng: random.Random) -> bytes | None:
    """在末尾追加一个点 —— 尾随点分歧最直接的放大器。"""
    return host + b"."


def _op_flip_case(host: bytes, rng: random.Random) -> bytes | None:
    """翻转一个字母的大小写。"""
    letters = [i for i, ch in enumerate(host)
               if 0x41 <= ch <= 0x5A or 0x61 <= ch <= 0x7A]
    if not letters:
        return None
    idx = rng.choice(letters)
    ch = host[idx:idx + 1]
    return host[:idx] + ch.swapcase() + host[idx + 1:]


def _op_append_default_port(host: bytes, rng: random.Random) -> bytes | None:
    """在没有端口的 Host 后追加默认端口。"""
    if b":" in host:
        return None
    return host + rng.choice([b":80", b":443"])


def _op_prepend_userinfo(host: bytes, rng: random.Random) -> bytes | None:
    """在最前面插入 userinfo。"""
    if b"@" in host:
        return None
    return rng.choice([b"user@", b"evil.com@"]) + host


def _op_duplicate_dot(host: bytes, rng: random.Random) -> bytes | None:
    """把某个点变成两个点。"""
    positions = [i for i, ch in enumerate(host) if ch == 0x2E]
    if not positions:
        return None
    idx = rng.choice(positions)
    return host[:idx] + b".." + host[idx + 1:]


def _op_encode_char(host: bytes, rng: random.Random) -> bytes | None:
    """把某个点或字母换成百分号编码。"""
    positions = [i for i, ch in enumerate(host)
                 if ch == 0x2E or 0x41 <= ch <= 0x5A or 0x61 <= ch <= 0x7A]
    if not positions:
        return None
    idx = rng.choice(positions)
    return host[:idx] + b"%%%02X" % host[idx] + host[idx + 1:]


OPS = (_op_append_dot, _op_flip_case, _op_append_default_port,
       _op_prepend_userinfo, _op_duplicate_dot, _op_encode_char)


class Mutator(_Mutator):
    """对每个种子随机叠加 1~2 个算子，产出确定性变体。"""

    OPERATORS = OPS
    MAX_OPS = 2


# --------------------------------------------------------------------------- 消融实验

def _text(raw: bytes) -> str:
    return raw.decode("latin-1")


def _bytes(text: str) -> bytes:
    return text.encode("latin-1")


def _strip_port(host: bytes) -> bytes:
    """抹掉尾部 `:80` / `:443` 默认端口（IPv6 的方括号端口也一样）。"""
    text = _text(host)
    if text.startswith("["):
        end = text.find("]")
        rest = text[end + 1:] if end != -1 else ""
        if rest in (":80", ":443"):
            return _bytes(text[:end + 1])
        return host
    for suffix in (":80", ":443"):
        if text.endswith(suffix):
            return _bytes(text[:-len(suffix)])
    return host


def _ab_drop_dot(host: bytes) -> bytes:
    """抹掉尾随点。"""
    return host.rstrip(b".") or host


def _ab_lower(host: bytes) -> bytes:
    """把主机名小写（只动 ASCII 字母）。"""
    return bytes(ch + 32 if 0x41 <= ch <= 0x5A else ch for ch in host)


def _ab_drop_default_port(host: bytes) -> bytes:
    """抹掉默认端口 `:80` / `:443`。"""
    return _strip_port(host)


def _ab_drop_userinfo(host: bytes) -> bytes:
    """抹掉 `@` 之前的 userinfo。"""
    idx = host.find(b"@")
    return host[idx + 1:] if idx != -1 else host


def _ab_collapse_dots(host: bytes) -> bytes:
    """折叠连续的点（空标签）。"""
    return re.sub(rb"\.{2,}", b".", host)


def _ab_idna(host: bytes) -> bytes:
    """把非 ASCII 主机名转成 IDNA A-label（punycode）—— 抹掉"是否 IDN"这个承载者。"""
    text = _text(host)
    if not any(ord(ch) > 127 for ch in text):
        return host
    try:
        decoded = host.decode("utf-8")
        return decoded.encode("idna")
    except (UnicodeError, ValueError):
        return host


def _ab_ipv6_canonical(host: bytes) -> bytes:
    """把方括号里的 IPv6 压成 RFC 5952 最短形式。"""
    text = _text(host)
    if not (text.startswith("[") and text.endswith("]")):
        return host
    try:
        return _bytes("[" + str(ipaddress.IPv6Address(text[1:-1])) + "]")
    except ValueError:
        return host


def _ab_decode_percent(host: bytes) -> bytes:
    """把百分号编码解一层 —— 抹掉"编码与否"这个承载者。"""
    out: list[bytes] = []
    i, n = 0, len(host)
    while i < n:
        if (host[i:i + 1] == b"%" and i + 3 <= n
                and _is_hex(host[i + 1]) and _is_hex(host[i + 2])):
            out.append(bytes([int(host[i + 1:i + 3], 16)]))
            i += 3
        else:
            out.append(host[i:i + 1])
            i += 1
    return b"".join(out)


def _is_hex(ch: int) -> bool:
    return (0x30 <= ch <= 0x39) or (0x41 <= ch <= 0x46) or (0x61 <= ch <= 0x66)


#: 消融实验：逐条"抹掉一类字节"重放两侧，看分歧是否消失。
#: 与分帧领域"逐条移除请求头"完全同一条原理 —— 而 Host 是攻击者直接发送的，故可控。
ABLATIONS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("抹掉尾随点", _ab_drop_dot),
    ("把主机名全部小写", _ab_lower),
    ("抹掉默认端口（:80 / :443）", _ab_drop_default_port),
    ("抹掉 userinfo（@ 之前）", _ab_drop_userinfo),
    ("折叠重复点（空标签）", _ab_collapse_dots),
    ("把非 ASCII 主机名转成 punycode", _ab_idna),
    ("把 IPv6 压成最短形式", _ab_ipv6_canonical),
    ("把百分号编码解一层", _ab_decode_percent),
)


__all__ = ["AXES", "OPS", "ABLATIONS", "Mutator", "corpus"]
