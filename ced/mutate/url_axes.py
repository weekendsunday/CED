"""URL 路径归一化领域的语料与定向变异。

与 ``mutate/axes.py`` 对称：每条轴上的用例都打在**已知有分歧历史的语法点**上，
而不是泛泛地 fuzz URL。载荷是**请求目标**（origin-form 的 target 字节）本身，
不是整条 HTTP 请求 —— 这一领域的观测对象就是 target。

轴与参照实现一一对应（见 ``impls/url_reference.AXIS_PAIRS``）：

    path_dot_segments    `..` 解算与否          → 路径穿越
    path_decoding        解码一次与否           → 编码绕过
    path_double_decode   解码层数               → 双重编码绕过
    path_percent_case    百分号十六进制大小写   → 编码绕过
    path_backslash       反斜杠是否当分隔符     → Windows/IIS 绕过
    path_slash_collapse  连续斜杠是否折叠       → 路由/匹配绕过
    path_trailing_dot    尾随点与空格           → 文件系统语义绕过
    path_semicolon       矩阵参数是否剥离       → 路由绕过
    path_case_fold       路径大小写             → 路由绕过
    path_benign          完全规范的 target      → **必须零分歧**（防假阳性）
"""
from __future__ import annotations

import random
import re
from typing import Callable

from ..impls.path_norm import lower_preserving_escapes
from .engine import Mutator as _Mutator, build_corpus

#: 轴的顺序（与 AXIS_PAIRS 的键一致，外加良性对照轴）
AXES: tuple[str, ...] = (
    "path_dot_segments",
    "path_decoding",
    "path_double_decode",
    "path_percent_case",
    "path_backslash",
    "path_slash_collapse",
    "path_trailing_dot",
    "path_semicolon",
    "path_case_fold",
    "path_overlong_utf8",
    "path_null_byte",
    "path_benign",
)


# --------------------------------------------------------------------------- 各轴语料

def case_dot_segments() -> list[bytes]:
    """A1 `..` 与 `.` 段：解算 / 保留 / 拒绝，三种实现都真实存在。"""
    return [
        b"/admin/../pub",
        b"/pub/../admin",
        b"/a/b/../../admin",
        b"/./admin",
        b"/admin/.",
        b"/x/../../admin",
    ]


def case_decoding() -> list[bytes]:
    """A2 解码一次与否：不归一化的前置会把 %2F 原样转发。"""
    return [
        b"/pub%2Fadmin",
        b"/a%2Fb%2Fc",
        b"/pub%2F..%2Fadmin",
        b"/admin%2E",
        b"/%2Fadmin",
    ]


def case_double_decode() -> list[bytes]:
    """A3 解码层数：双重编码要靠**第二层**解码才现形（故本轴用大写十六进制）。"""
    return [
        b"/pub/%252E%252E/admin",
        b"/pub/%252Fadmin",
        b"/%252E%252E/admin",
        b"/a/%252E%252E%252Fadmin",
    ]


def case_percent_case() -> list[bytes]:
    """A4 百分号十六进制大小写：RFC 3986 §2.1 只承认大写，但多数实现两种都收。

    含两条大写对照（两侧都该解出来，**不该**产生分歧）。
    """
    return [
        b"/pub/%2e%2e/admin",
        b"/pub/%2fadmin",
        b"/admin%2e",
        b"/pub/%2E%2E/admin",
        b"/pub/%2Fadmin",
    ]


def case_backslash() -> list[bytes]:
    """A5 反斜杠：RFC 3986 里它是普通 pchar，Windows/IIS 里它是分隔符。"""
    return [
        b"/admin\\..\\pub",
        b"/admin\\pub",
        b"/pub\\..\\admin",
        b"\\\\admin",
    ]


def case_slash_collapse() -> list[bytes]:
    """A6 连续斜杠：RFC 3986 不折叠，不少框架会折叠。"""
    return [
        b"//admin",
        b"///admin",
        b"/pub//admin",
        b"/a//b///c",
    ]


def case_trailing_dot() -> list[bytes]:
    """A7 段尾的点与空格：Windows 文件系统会剥掉它们。"""
    return [
        b"/admin.",
        b"/admin..",
        b"/admin%20",
        b"/pub/admin./x",
    ]


def case_semicolon() -> list[bytes]:
    """A8 矩阵参数：Tomcat 等把 `;` 之后当路径参数丢掉。"""
    return [
        b"/admin;x=/pub",
        b"/admin;jsessionid=abc",
        b"/a;b/c;d",
        b"/admin;/",
    ]


def case_case_fold() -> list[bytes]:
    """A9 路径大小写：大小写不敏感的文件系统 / 路由表。"""
    return [
        b"/ADMIN",
        b"/Admin/Pub",
        b"/admin/ADMIN",
    ]


def case_overlong_utf8() -> list[bytes]:
    """A10 过长 UTF-8：RFC 3629 禁止，但历史实现接受 —— `%c0%ae` 表示 `.`。

    `%c0%ae` / `%e0%80%ae` 都是"用多余的字节编码一个 ASCII 字符"，
    接受它们的实现会把它解成 `.`，于是 `%c0%ae%c0%ae%2f` 等价于 `../`。
    """
    return [
        b"/pub/%c0%ae%c0%ae%2fadmin",
        b"/%c0%afadmin",
        b"/pub/%e0%80%ae%e0%80%ae%2fadmin",
        b"/%c0%ae%c0%ae/%c0%ae%c0%ae/admin",
    ]


def case_null_byte() -> list[bytes]:
    """A11 空字节：历史实现把 `%00` 当字符串结束（"空字节截断"）。"""
    return [
        b"/admin%00.jpg",
        b"/admin%00/pub",
        b"/pub%00/../admin",
        b"/admin%00",
    ]


def case_benign() -> list[bytes]:
    """A0 良性对照：完全规范的 target，**任何一对实现都不该有分歧**。

    没有这条轴，"假阳性"就没人守着 —— 它和 ``test_pipeline`` 里
    「正常请求所有实现必须一致」那条测试是同一个用意。
    """
    return [
        b"/",
        b"/admin",
        b"/a/b/c",
        b"/pub/admin?x=1",
        b"/index.html",
    ]


_BUILDERS = {
    "path_dot_segments": case_dot_segments,
    "path_decoding": case_decoding,
    "path_double_decode": case_double_decode,
    "path_percent_case": case_percent_case,
    "path_backslash": case_backslash,
    "path_slash_collapse": case_slash_collapse,
    "path_trailing_dot": case_trailing_dot,
    "path_semicolon": case_semicolon,
    "path_case_fold": case_case_fold,
    "path_overlong_utf8": case_overlong_utf8,
    "path_null_byte": case_null_byte,
    "path_benign": case_benign,
}


def corpus() -> list[tuple[str, bytes]]:
    """全部种子：(轴名, target 字节)。"""
    return build_corpus(AXES, _BUILDERS)


# --------------------------------------------------------------------------- 定向变异

_ESC_DOT = (b"%2E", b"%2e", b"%252E")
_PLAIN_DOT = b"."


def _op_append_dot_segment(target: bytes, rng: random.Random) -> bytes | None:
    """在末尾追加 `/..` 或 `/.` —— 路径穿越最直接的放大器。"""
    seg = rng.choice([b"/..", b"/.", b"/../..", b"/..%2F"])
    return target + seg


def _op_encode_last_dot(target: bytes, rng: random.Random) -> bytes | None:
    """把最后一个 `.` 换成百分号编码（三种写法）。"""
    idx = target.rfind(_PLAIN_DOT)
    if idx == -1:
        return None
    esc = rng.choice(_ESC_DOT)
    return target[:idx] + esc + target[idx + 1:]


def _op_slash_to_escape(target: bytes, rng: random.Random) -> bytes | None:
    """把某个斜杠换成 `%2F` / `%252F` 或反斜杠。"""
    positions = [i for i, ch in enumerate(target) if ch == 0x2F]
    if not positions:
        return None
    idx = rng.choice(positions)
    repl = rng.choice([b"%2F", b"%2f", b"%252F", b"\\"])
    return target[:idx] + repl + target[idx + 1:]


def _op_segment_tail(target: bytes, rng: random.Random) -> bytes | None:
    """在某个段尾加点、空格或它们编码后的形式。"""
    if not target.startswith(b"/"):
        return None
    parts = target.split(b"/")
    if len(parts) < 2:
        return None
    idx = rng.randrange(1, len(parts))
    parts[idx] += rng.choice([b".", b"..", b"%2E", b"%20"])
    return b"/".join(parts)


def _op_duplicate_slash(target: bytes, rng: random.Random) -> bytes | None:
    positions = [i for i, ch in enumerate(target) if ch == 0x2F]
    if not positions:
        return None
    idx = rng.choice(positions)
    return target[:idx] + b"//" + target[idx:]


def _op_inject_semicolon(target: bytes, rng: random.Random) -> bytes | None:
    if not target.startswith(b"/"):
        return None
    parts = target.split(b"/")
    if len(parts) < 2:
        return None
    idx = rng.randrange(1, len(parts))
    parts[idx] += rng.choice([b";x=1", b";jsessionid=abc"])
    return b"/".join(parts)


def _op_flip_case(target: bytes, rng: random.Random) -> bytes | None:
    letters = [i for i, ch in enumerate(target) if 0x41 <= ch <= 0x5A or 0x61 <= ch <= 0x7A]
    if not letters:
        return None
    idx = rng.choice(letters)
    ch = target[idx:idx + 1]
    return target[:idx] + ch.swapcase() + target[idx + 1:]


OPS = (_op_append_dot_segment, _op_encode_last_dot, _op_slash_to_escape,
       _op_segment_tail, _op_duplicate_slash, _op_inject_semicolon,
       _op_flip_case)


class Mutator(_Mutator):
    """对每个种子随机叠加 1~2 个算子，产出确定性变体。"""

    OPERATORS = OPS
    MAX_OPS = 2


#: 供测试引用：这些 target 必须是**合法**的 origin-form（变异后也要能解析）
VALID_TARGET = re.compile(rb"^/|^[A-Za-z][A-Za-z0-9+.\-]*://")


# --------------------------------------------------------------------------- 消融实验

def _split_query(target: bytes) -> tuple[bytes, bytes]:
    idx = target.find(b"?")
    return (target, b"") if idx == -1 else (target[:idx], target[idx:])


def _text(raw: bytes) -> str:
    return raw.decode("latin-1")


def _bytes(text: str) -> bytes:
    return text.encode("latin-1")


def _ab_drop_semicolons(target: bytes) -> bytes:
    """抹掉矩阵参数（`;` 之后到段尾）。"""
    path, query = _split_query(target)
    return _bytes("/".join(seg.split(";", 1)[0]
                           for seg in _text(path).split("/"))) + query


def _ab_drop_trailing(target: bytes) -> bytes:
    """抹掉段尾的点与空格（点段本身不动 —— 那是另一类承载者）。"""
    path, query = _split_query(target)
    out = [seg if seg in (".", "..") else seg.rstrip(". ")
           for seg in _text(path).split("/")]
    return _bytes("/".join(out)) + query


def _ab_backslash_to_slash(target: bytes) -> bytes:
    """把反斜杠换成正斜杠。"""
    return target.replace(b"\\", b"/")


def _ab_collapse_slashes(target: bytes) -> bytes:
    """折叠连续斜杠。"""
    path, query = _split_query(target)
    return re.sub(rb"/{2,}", b"/", path) + query


def _ab_decode_one(target: bytes) -> bytes:
    """把百分号编码解一层（大小写都认）—— 抹掉"编码层数"这个承载者。"""
    path, query = _split_query(target)
    out: list[bytes] = []
    i, n = 0, len(path)
    while i < n:
        if (path[i:i + 1] == b"%" and i + 3 <= n
                and _is_hex(path[i + 1]) and _is_hex(path[i + 2])):
            out.append(bytes([int(path[i + 1:i + 3], 16)]))
            i += 3
        else:
            out.append(path[i:i + 1])
            i += 1
    return b"".join(out) + query


def _ab_drop_dot_segments(target: bytes) -> bytes:
    """把 `.` / `..` 段整个删掉 —— 两侧就都没有可解算的东西了。"""
    path, query = _split_query(target)
    keep = [seg for seg in _text(path).split("/") if seg not in (".", "..")]
    return _bytes("/".join(keep)) + query


def _ab_lower(target: bytes) -> bytes:
    """把路径小写（保留百分号转义，免得顺手改了另一类承载者）。"""
    path, query = _split_query(target)
    return _bytes(lower_preserving_escapes(_text(path))) + query


def _ab_strip_null(target: bytes) -> bytes:
    """抹掉 NUL 及其之后的部分 —— 两侧就都只看到 NUL 之前的内容。"""
    low = target.lower()
    for marker in (b"%00",):
        idx = low.find(marker)
        if idx != -1:
            return target[:idx] or b"/"
    return target


#: 过长 UTF-8 序列 → 最短形式（`%c0%ae` 就是 `.`）
_OVERLONG_TO_SHORT = {
    b"%c0%ae": b"%2E", b"%c0%af": b"%2F", b"%c1%9c": b"%5C",
    b"%e0%80%ae": b"%2E", b"%e0%80%af": b"%2F",
}


def _ab_shorten_overlong(target: bytes) -> bytes:
    """把过长 UTF-8 序列换成最短形式 —— 抹掉"编码是否过长"这个承载者。"""
    out = target
    for long_form, short in _OVERLONG_TO_SHORT.items():
        while True:
            idx = out.lower().find(long_form)
            if idx == -1:
                break
            out = out[:idx] + short + out[idx + len(long_form):]
    return out


def _is_hex(ch: int) -> bool:
    return (0x30 <= ch <= 0x39) or (0x41 <= ch <= 0x46) or (0x61 <= ch <= 0x66)


#: 消融实验：逐条"抹掉一类字节"重放两侧，看分歧是否消失。
#: 与分帧领域"逐条移除请求头"完全同一条原理 —— 而 target 是攻击者直接发送的，故可控。
ABLATIONS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("抹掉矩阵参数（`;` 之后）", _ab_drop_semicolons),
    ("抹掉段尾的点与空格", _ab_drop_trailing),
    ("把反斜杠换成正斜杠", _ab_backslash_to_slash),
    ("折叠连续斜杠", _ab_collapse_slashes),
    ("把百分号编码解一层", _ab_decode_one),
    ("把点段（`.` / `..`）整个删掉", _ab_drop_dot_segments),
    ("把过长 UTF-8 序列换成最短形式", _ab_shorten_overlong),
    ("抹掉 NUL 及其之后的部分", _ab_strip_null),
    ("把路径全部小写（保留转义）", _ab_lower),
)


__all__ = ["AXES", "OPS", "ABLATIONS", "Mutator", "corpus", "VALID_TARGET"]
