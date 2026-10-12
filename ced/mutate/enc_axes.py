"""编码 / Unicode 归一化领域的语料与定向变异。

与 ``mutate/url_axes.py`` 对称：每条轴上的用例都打在**已知有分歧历史的解释点**上，
而不是泛泛地 fuzz 字节。载荷是**待解释的一段字节**（一个参数值 / 关键字的原文，
可含百分号转义与原始高字节），这一领域的观测对象就是这段字节被读成了什么文本。

轴与参照实现一一对应（见 ``impls/enc_reference.AXIS_PAIRS``）：

    enc_overlong_utf8    过长 UTF-8 是否接受（`%c0%af` → `/`） → 编码绕过
    enc_unicode_nfc      Unicode NFC 规范化                        → 关键字/路径绕过
    enc_unicode_nfd      Unicode NFD 规范化                        → 关键字/路径绕过
    enc_fullwidth        全角字符是否折叠成 ASCII                  → 路径/扩展名绕过
    enc_percent_u        `%uXXXX` 遗留转义是否解                   → 编码绕过
    enc_case_fold        Unicode 大小写折叠（Kelvin / 长 s / 连字） → 黑名单绕过
    enc_byte_encoding    UTF-8 还是 Latin-1 解释                   → 编码混淆
    enc_lone_surrogate   孤立代理项怎么处理（CESU-8）              → 编码绕过
    enc_nul              `%00` 是否截断                             → 扩展名/路径绕过
    enc_benign           完全规范的 ASCII 字符串                   → **必须零分歧**（防假阳性）
"""
from __future__ import annotations

import random
import re
import unicodedata
from typing import Callable

from ..impls.enc_norm import unescape
from ..minimize.ddmin import ddmin
from .engine import Mutator as _Mutator, build_corpus

#: 轴的顺序（与 AXIS_PAIRS 的键一致）
AXES: tuple[str, ...] = (
    "enc_overlong_utf8",
    "enc_unicode_nfc",
    "enc_unicode_nfd",
    "enc_fullwidth",
    "enc_percent_u",
    "enc_case_fold",
    "enc_byte_encoding",
    "enc_lone_surrogate",
    "enc_nul",
    "enc_benign",
)


# --------------------------------------------------------------------------- 各轴语料

def case_overlong_utf8() -> list[bytes]:
    """A1 过长 UTF-8：`%c0%af` 是 `/` 的过长编码，严格解码器拒绝。

    先例：IIS 4.0/5.0 的 `%c0%af%c0%af…` 目录穿越（CVE-2000-0884）；
    现代栈按 RFC 3629 拒绝过长序列，于是"检查侧拒绝、执行侧解成 `/`"。
    """
    return [
        b"%c0%afadmin",
        b"..%c0%af..%c0%afetc%c0%afpasswd",
        b"%c1%9cwindows%c1%9csystem32",
        b"%e0%80%afadmin",
    ]


def case_unicode_nfc() -> list[bytes]:
    """A2 NFC：组合序列被合并成预组合字符（`e`+U+0301 → `é`）。

    先例：多数 WAF / 浏览器在匹配前做 NFC；只做字节比较的栈看到的是
    带组合附加符号的原串 —— "看起来一样、码点不同"。
    """
    return [
        b"cafe%CC%81",
        b"A%CC%8A",
        b"sen%CC%83or",
    ]


def case_unicode_nfd() -> list[bytes]:
    """A3 NFD：预组合字符被拆成基字符 + 组合附加符号（`é` → `e`+U+0301）。

    先例：macOS 文件系统用 NFD；与用 NFC 的检查侧比对时字符序列不一致。
    """
    return [
        b"caf%C3%A9",
        b"%C3%85ngstrom",
        b"na%C3%AFve",
    ]


def case_fullwidth() -> list[bytes]:
    """A4 全角折叠：全角斜杠 `／`（U+FF0F）、全角点 `．`（U+FF0E）等。

    先例：路径/扩展名过滤器常只看 ASCII，而做 NFKC / ICU 折叠的栈把
    全角字符变回 ASCII —— 于是 `／` 绕过了只认 `/` 的黑名单。
    """
    return [
        b"%EF%BC%8Fadmin",
        b"%EF%BD%81dmin",
        b"%EF%BC%8E%EF%BC%8E%EF%BC%8Fetc",
        b"admin%EF%BC%8E",
    ]


def case_percent_u() -> list[bytes]:
    """A5 `%uXXXX` 遗留转义：IIS 认，Apache/PHP 不认。

    先例：IIS 的 `%u002e%u002e%u002f` 目录穿越；只认 `%XX` 的栈把它当字面量。
    """
    return [
        b"%u002fadmin",
        b"%u002e%u002e%u002fetc%u002fpasswd",
        b"admin%u002e%u002e%u002f",
        b"%uFF0Fadmin",
    ]


def case_case_fold() -> list[bytes]:
    """A6 Unicode 大小写折叠：Kelvin `K`、长 s `ſ`、连字 `ﬀ`、`İ`。

    先例：只做 ASCII 小写的关键字黑名单挡不住 casefold 后才现形的等价字符。
    """
    return [
        b"pa%C5%BFs",
        b"o%EF%AC%80ice",
        b"a%E2%84%AA",
        b"caf%C4%B0",
    ]


def case_byte_encoding() -> list[bytes]:
    """A7 字节按 UTF-8 还是 Latin-1 解释：`%C3%A9` 是 `é` 还是 `Ã©`。

    先例：经典 UTF-8 / Latin-1 混淆；网关按一种解释做检查，后端按另一种解释执行。
    """
    return [
        b"%C3%A9",
        b"%E2%82%AC",
        b"admin%C2%A0",
        b"%C3%BCser",
    ]


def case_lone_surrogate() -> list[bytes]:
    """A8 孤立代理项（CESU-8）：`%ED%A0%80` = U+D800。

    先例：严格 UTF-8 解码器拒绝代理项，而把字节直接映射到 UTF-16 码元的
    后端会把它解出来 —— 两侧对同一段字节的接受性不同。
    """
    return [
        b"%ED%A0%80",
        b"x%ED%B0%80y",
        b"%ED%A0%80admin",
    ]


def case_nul() -> list[bytes]:
    """A9 `%00` 截断：C 字符串 / PHP 的 NUL 截断。

    先例：`shell.php%00.jpg` 骗过只查后缀的白名单，而执行侧在 NUL 处截断。
    """
    return [
        b"admin%00.txt",
        b"safe%00../../etc/passwd",
        b"%00.jpg",
        b"a%00b%00c",
    ]


def case_benign() -> list[bytes]:
    """A0 良性对照：完全规范的 ASCII 字符串，**任何一对实现都不该有分歧**。

    没有这条轴，"假阳性"就没人守着 —— 它和 ``test_enc_norm`` 里
    「规范输入所有实现必须一致」那条测试是同一个用意。
    """
    return [
        b"admin",
        b"hello-world",
        b"a/b/c.txt",
        b"index.html",
        b"user=alice",
    ]


_BUILDERS = {
    "enc_overlong_utf8": case_overlong_utf8,
    "enc_unicode_nfc": case_unicode_nfc,
    "enc_unicode_nfd": case_unicode_nfd,
    "enc_fullwidth": case_fullwidth,
    "enc_percent_u": case_percent_u,
    "enc_case_fold": case_case_fold,
    "enc_byte_encoding": case_byte_encoding,
    "enc_lone_surrogate": case_lone_surrogate,
    "enc_nul": case_nul,
    "enc_benign": case_benign,
}


def corpus() -> list[tuple[str, bytes]]:
    """全部种子：(轴名, 待解释字节)。"""
    return build_corpus(AXES, _BUILDERS)


# --------------------------------------------------------------------------- 定向变异

def _pct(data: bytes) -> bytes:
    """把字节串整体写成 `%XX` 转义（大写），便于嵌进 payload。"""
    return b"".join(b"%%%02X" % b for b in data)


def _op_encode_high(payload: bytes, rng: random.Random) -> bytes | None:
    """把某个原始高字节写成它的 `%XX` 转义。"""
    positions = [i for i, ch in enumerate(payload) if ch >= 0x80]
    if not positions:
        return None
    i = rng.choice(positions)
    return payload[:i] + b"%%%02X" % payload[i] + payload[i + 1:]


def _op_slash_to_overlong(payload: bytes, rng: random.Random) -> bytes | None:
    """把某个斜杠换成它的过长 UTF-8 编码（三种长度都试）。"""
    positions = [i for i, ch in enumerate(payload) if ch == 0x2F]
    if not positions:
        return None
    i = rng.choice(positions)
    return (payload[:i] + rng.choice([b"%c0%af", b"%e0%80%af", b"%c1%9c"])
            + payload[i + 1:])


def _op_inject_percent_u(payload: bytes, rng: random.Random) -> bytes | None:
    """把某个斜杠写成 `%uXXXX` 遗留转义。"""
    positions = [i for i, ch in enumerate(payload) if ch == 0x2F]
    if not positions:
        return None
    i = rng.choice(positions)
    return payload[:i] + rng.choice([b"%u002f", b"%uFF0F"]) + payload[i + 1:]


def _op_inject_nul(payload: bytes, rng: random.Random) -> bytes | None:
    """在随机位置插入一个 `%00`。"""
    i = rng.randrange(len(payload) + 1)
    return payload[:i] + b"%00" + payload[i:]


def _op_fullwidth_char(payload: bytes, rng: random.Random) -> bytes | None:
    """把某个可见 ASCII 字符换成它的全角等价字符（百分号编码）。"""
    positions = [i for i, ch in enumerate(payload) if 0x21 <= ch <= 0x7E]
    if not positions:
        return None
    i = rng.choice(positions)
    fullwidth = 0xFF01 + (payload[i] - 0x21)
    return payload[:i] + _pct(chr(fullwidth).encode("utf-8")) + payload[i + 1:]


def _op_append_combining(payload: bytes, rng: random.Random) -> bytes | None:
    """在某个字母后追加一个组合附加符号（U+0301 / U+030A）。"""
    positions = [i for i, ch in enumerate(payload)
                 if 0x41 <= ch <= 0x5A or 0x61 <= ch <= 0x7A]
    if not positions:
        return None
    i = rng.choice(positions)
    mark = rng.choice(["\u0301", "\u030a"])
    return payload[:i + 1] + _pct(mark.encode("utf-8")) + payload[i + 1:]


def _op_casefold_letter(payload: bytes, rng: random.Random) -> bytes | None:
    """把 `k` / `s` 换成 casefold 后才等价于它的字符（Kelvin / 长 s）。"""
    positions = [i for i, ch in enumerate(payload) if ch in (0x6B, 0x73)]
    if not positions:
        return None
    i = rng.choice(positions)
    repl = "\u212a" if payload[i] == 0x6B else "\u017f"
    return payload[:i] + _pct(repl.encode("utf-8")) + payload[i + 1:]


def _op_inject_surrogate(payload: bytes, rng: random.Random) -> bytes | None:
    """在随机位置插入一个孤立代理项的 CESU-8 编码。"""
    i = rng.randrange(len(payload) + 1)
    return payload[:i] + rng.choice([b"%ED%A0%80", b"%ED%B0%80"]) + payload[i:]


OPS = (_op_encode_high, _op_slash_to_overlong, _op_inject_percent_u,
       _op_inject_nul, _op_fullwidth_char, _op_append_combining,
       _op_casefold_letter, _op_inject_surrogate)


class Mutator(_Mutator):
    """对每个种子随机叠加 1~2 个算子，产出确定性变体。"""

    OPERATORS = OPS
    MAX_OPS = 2


# --------------------------------------------------------------------------- 消融实验

def _decode_lossy(data: bytes) -> str:
    """宽松 UTF-8 解码（非法序列用 U+FFFD 顶替）—— 仅用于消融变换本身。"""
    return data.decode("utf-8", "replace")


def _pct_ascii(text: str) -> bytes:
    """把文本重建为**纯 ASCII** 的 payload：可见 ASCII 原样，其余百分号编码。

    重建出的 payload 两侧解释完全一致（只剩 ASCII 与 `%XX`），
    于是"抹掉了哪类承载者"就能从"分歧是否消失"读出来。
    """
    out = bytearray()
    for ch in text:
        b = ch.encode("utf-8", "replace")
        if len(b) == 1 and 0x20 <= b[0] < 0x7F and b[0] != 0x25:
            out += b
        else:
            out += b"".join(b"%%%02X" % x for x in b)
    return bytes(out)


def _ab_drop_percent_u(payload: bytes) -> bytes:
    """把 `%uXXXX` 序列整个删掉。"""
    return re.sub(rb"%u[0-9A-Fa-f]{4}", b"", payload)


def _ab_drop_nul(payload: bytes) -> bytes:
    """把 NUL（`%00` 转义或原始 0x00 字节）删掉。"""
    return payload.replace(b"%00", b"").replace(b"\x00", b"")


def _ab_ascii_only(payload: bytes) -> bytes:
    """把转义解出来，再把非 ASCII 字节与 `%` 替换成 `?`。"""
    data = unescape(payload)
    return bytes(0x3F if (b >= 0x80 or b == 0x25) else b for b in data)


def _ab_drop_combining(payload: bytes) -> bytes:
    """把组合附加符号（U+0300–U+036F）删掉。"""
    text = _decode_lossy(unescape(payload))
    filtered = "".join(ch for ch in text
                       if not (0x0300 <= ord(ch) <= 0x036F))
    return _pct_ascii(filtered)


def _ab_fold_fullwidth(payload: bytes) -> bytes:
    """把全角 ASCII 变体折叠成 ASCII 等价物。"""
    text = _decode_lossy(unescape(payload))
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif o == 0x3000:
            out.append(" ")
        else:
            out.append(ch)
    return _pct_ascii("".join(out))


def _ab_nfc(payload: bytes) -> bytes:
    """把文本做一次 NFC 合并。"""
    return _pct_ascii(unicodedata.normalize("NFC", _decode_lossy(unescape(payload))))


def _ab_casefold(payload: bytes) -> bytes:
    """把文本整体做一次 Unicode 大小写折叠。"""
    return _pct_ascii(_decode_lossy(unescape(payload)).casefold())


#: 消融实验：逐条"抹掉一类承载者"重放两侧，看分歧是否消失。
#: 与分帧领域"逐条移除请求头"完全同一条原理 —— 而这些字节是攻击者直接发送的，故可控。
ABLATIONS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("把 `%uXXXX` 转义整个删掉", _ab_drop_percent_u),
    ("把 NUL（`%00` / 0x00）删掉", _ab_drop_nul),
    ("把非 ASCII 字节及其转义替换成 `?`", _ab_ascii_only),
    ("把组合附加符号（U+0300–U+036F）删掉", _ab_drop_combining),
    ("把全角字符折叠成 ASCII 等价物", _ab_fold_fullwidth),
    ("把文本做一次 NFC 合并", _ab_nfc),
    ("把文本整体做一次 Unicode 大小写折叠", _ab_casefold),
)


# --------------------------------------------------------------------------- 最小化

def _tokens(payload: bytes) -> list[bytes]:
    """把 payload 切成最小语义单元：`%uXXXX` / `%XX` 各算一个，其余逐字节。"""
    tokens: list[bytes] = []
    i, n = 0, len(payload)
    while i < n:
        if (payload[i:i + 2] == b"%u" and i + 6 <= n
                and all(_hex(b) for b in payload[i + 2:i + 6])):
            tokens.append(payload[i:i + 6])
            i += 6
        elif (payload[i:i + 1] == b"%" and i + 3 <= n
                and _hex(payload[i + 1]) and _hex(payload[i + 2])):
            tokens.append(payload[i:i + 3])
            i += 3
        else:
            tokens.append(payload[i:i + 1])
            i += 1
    return tokens


def _hex(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x46 or 0x61 <= b <= 0x66


def minimize_bytes(payload: bytes, predicate: Callable[[bytes], bool]) -> bytes:
    """在"转义片段 / 字节"这一粒度上最小化，保持分歧仍在。

    `%c0%afadmin` 会被压成 `%c0%af` 级别的最小承载片段。

    **编码领域**的最小化单元（``EncNormAdapter.minimize`` 调用它）。
    """
    if not predicate(payload):
        return payload
    tokens = _tokens(payload)
    if len(tokens) < 2:
        return payload

    def build(keep: list[int]) -> bytes:
        return b"".join(tokens[i] for i in keep)

    everything = list(range(len(tokens)))
    if not predicate(build(everything)):
        return payload
    kept = ddmin(everything, lambda ks: bool(ks) and predicate(build(ks)))
    rebuilt = build(list(kept))
    return rebuilt if predicate(rebuilt) else payload


__all__ = ["AXES", "OPS", "ABLATIONS", "Mutator", "corpus", "minimize_bytes"]
