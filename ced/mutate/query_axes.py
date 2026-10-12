"""查询串解析领域的语料与定向变异。

与 ``mutate/url_axes.py`` 对称：每条轴上的用例都打在**已知有分歧历史的语法点**上，
而不是泛泛地 fuzz 查询串。载荷是**查询串本身**（`?` 之后的字节），
不是整条 HTTP 请求 —— 这一领域的观测对象就是查询串。

轴与参照实现一一对应（见 ``impls/query_reference.AXIS_PAIRS``）：

    query_separators    `;` 是否也是分隔符       → 参数集不同
    query_duplicate     重复参数取首/取尾        → 参数污染（HPP）
    query_dup_multi     重复参数取首/全要        → 参数污染（HPP）
    query_decoding      解码一次与否             → 编码绕过
    query_double_decode 解码层数                 → 双重编码绕过
    query_plus          `+` 是否当空格           → 取值不同
    query_empty         空值参数是否保留         → 参数集不同
    query_bracket       `a[]` 括号是否归一       → 参数名不同
    query_case          参数名大小写敏感度       → 参数名不同
    query_sort          参数是否排序             → 缓存键/签名不同
    query_benign        完全规范的查询串         → **必须零分歧**（防假阳性）
"""
from __future__ import annotations

import random
from typing import Callable
from .engine import Mutator as _Mutator, build_corpus

#: 轴的顺序（与 AXIS_PAIRS 的键一致，外加良性对照轴）
AXES: tuple[str, ...] = (
    "query_separators",
    "query_duplicate",
    "query_dup_multi",
    "query_decoding",
    "query_double_decode",
    "query_plus",
    "query_empty",
    "query_bracket",
    "query_case",
    "query_sort",
    "query_benign",
)


# --------------------------------------------------------------------------- 各轴语料

def case_separators() -> list[bytes]:
    """A1 `;` 是否当分隔符：PHP 5.3 前后、Tomcat / W3C 建议都出现过。"""
    return [
        b"a=1;b=2",
        b"a=1&b=2;c=3",
        b"x=1;y=2",
        b"semicolon=1;2",
    ]


def case_duplicate() -> list[bytes]:
    """A2 重复参数取首还是取尾 —— HPP 的核心。"""
    return [
        b"a=1&a=2",
        b"id=1&id=2&id=3",
        b"role=user&role=admin",
        b"a=1&b=2&a=3",
    ]


def case_dup_multi() -> list[bytes]:
    """A3 取首 vs 全要：ASP.NET 逗号合并全部，Java 取首。"""
    return [
        b"a=1&a=2",
        b"role=user&role=admin",
        b"id=1&id=2",
    ]


def case_decoding() -> list[bytes]:
    """A4 解码一次与否：不归一化的前置会把 `%26` 原样转发。"""
    return [
        b"a=%26b%3D1",
        b"q=%41%42",
        b"x=%2Fadmin",
        b"a=%3D",
    ]


def case_double_decode() -> list[bytes]:
    """A5 解码层数：双重编码要靠**第二层**解码才现形。"""
    return [
        b"a=%2526b%253D1",
        b"q=%2541",
        b"x=%25252F",
    ]


def case_plus() -> list[bytes]:
    """A6 `+` 是否当空格：表单编码认，`decodeURIComponent` 不认。"""
    return [
        b"a=1+2",
        b"q=a+b+c",
        b"name=John+Doe",
        b"x=+1",
    ]


def case_empty() -> list[bytes]:
    """A7 空值参数是否保留：`a=` / 裸 `a`。"""
    return [
        b"a=&b=1",
        b"a&b=1",
        b"x=&y=&z=1",
        b"flag=",
    ]


def case_bracket() -> list[bytes]:
    """A8 括号语法：PHP 数组参数 `a[]` / `a[0]` / `user[name]`。"""
    return [
        b"a[]=1",
        b"a[0]=1&a[1]=2",
        b"user[name]=x&user[age]=9",
        b"a[]=1&a[]=2",
    ]


def case_case() -> list[bytes]:
    """A9 参数名大小写：规范敏感，但部分应用 / 网关小写化后再匹配。"""
    return [
        b"UserID=1&userid=2",
        b"A=1&a=2",
        b"Name=x",
    ]


def case_sort() -> list[bytes]:
    """A10 参数排序：缓存键 / WAF 规范化 / 签名基串。"""
    return [
        b"b=2&a=1",
        b"z=1&m=2&a=3",
        b"token=x&id=5",
    ]


def case_benign() -> list[bytes]:
    """A0 良性对照：完全规范的查询串，**任何一对实现都不该有分歧**。

    刻意满足所有策略：名字唯一且已小写、值非空、无 `%`/`+`/`;`/`[]`、且已按名排序 ——
    这样连"排序"这条开关都不会改动它。没有这条轴，"假阳性"就没人守着。
    """
    return [
        b"a=1",
        b"a=1&b=2",
        b"a=1&b=2&c=3",
        b"id=5&token=abc",
    ]


_BUILDERS = {
    "query_separators": case_separators,
    "query_duplicate": case_duplicate,
    "query_dup_multi": case_dup_multi,
    "query_decoding": case_decoding,
    "query_double_decode": case_double_decode,
    "query_plus": case_plus,
    "query_empty": case_empty,
    "query_bracket": case_bracket,
    "query_case": case_case,
    "query_sort": case_sort,
    "query_benign": case_benign,
}


def corpus() -> list[tuple[str, bytes]]:
    """全部种子：(轴名, 查询串字节)。"""
    return build_corpus(AXES, _BUILDERS)


# --------------------------------------------------------------------------- 定向变异

def _split(text: str) -> list[str]:
    return [tok for tok in text.split("&") if tok != ""]


def _join(tokens: list[str]) -> bytes:
    return "&".join(tokens).encode("latin-1")


def _op_add_semicolon(payload: bytes, rng: random.Random) -> bytes | None:
    """在某个 `&` 处改成 `;` —— 放大"分隔符"这条轴。"""
    text = payload.decode("latin-1")
    positions = [i for i, ch in enumerate(text) if ch == "&"]
    if not positions:
        return None
    idx = rng.choice(positions)
    return (text[:idx] + ";" + text[idx + 1:]).encode("latin-1")


def _op_duplicate_param(payload: bytes, rng: random.Random) -> bytes | None:
    """复制一个参数（改个值），制造同名重复 —— 放大 HPP。"""
    tokens = _split(payload.decode("latin-1"))
    if not tokens:
        return None
    idx = rng.randrange(len(tokens))
    token = tokens[idx]
    name, sep, _ = token.partition("=")
    clone = f"{name}={rng.randint(0, 9)}" if sep else token
    pos = rng.randrange(len(tokens) + 1)
    return _join(tokens[:pos] + [clone] + tokens[pos:])


def _op_encode_value(payload: bytes, rng: random.Random) -> bytes | None:
    """把值里的某个 ASCII 字符百分号编码（一层或两层）。"""
    text = payload.decode("latin-1")
    idx = text.find("=")
    if idx == -1 or idx + 1 >= len(text):
        return None
    value = text[idx + 1:]
    if not value:
        return None
    j = rng.randrange(len(value))
    ch = value[j]
    if not ch.isascii() or not ch.isprintable() or ch in "%":
        return None
    enc = rng.choice([f"%{ord(ch):02X}", f"%25{ord(ch):02X}"])
    return (text[:idx + 1] + value[:j] + enc + value[j + 1:]).encode("latin-1")


def _op_add_plus(payload: bytes, rng: random.Random) -> bytes | None:
    """在某个值里插一个 `+`（或编码后的 `%2B`）。"""
    text = payload.decode("latin-1")
    idx = text.find("=")
    if idx == -1 or idx + 1 > len(text):
        return None
    ins = rng.choice(["+", "%2B"])
    pos = rng.randint(idx + 1, len(text))
    return (text[:pos] + ins + text[pos:]).encode("latin-1")


def _op_add_empty(payload: bytes, rng: random.Random) -> bytes | None:
    """追加一个空值参数（`z=`）。"""
    name = rng.choice(["z", "empty", "opt", "flag"])
    sep = "&" if payload else ""
    return (payload.decode("latin-1") + f"{sep}{name}=").encode("latin-1")


def _op_add_bracket(payload: bytes, rng: random.Random) -> bytes | None:
    """给某个参数名加上 `[]` / `[k]` 后缀。"""
    tokens = _split(payload.decode("latin-1"))
    if not tokens:
        return None
    idx = rng.randrange(len(tokens))
    name, sep, value = tokens[idx].partition("=")
    suffix = rng.choice(["[]", "[0]", "[key]"])
    tokens[idx] = f"{name}{suffix}{sep}{value}"
    return _join(tokens)


def _op_flip_name_case(payload: bytes, rng: random.Random) -> bytes | None:
    """翻转某个参数名里的一个字母大小写。"""
    text = payload.decode("latin-1")
    limit = text.find("=") if "=" in text else len(text)
    letters = [i for i, ch in enumerate(text[:limit]) if ch.isascii() and ch.isalpha()]
    if not letters:
        return None
    idx = rng.choice(letters)
    return (text[:idx] + text[idx].swapcase() + text[idx + 1:]).encode("latin-1")


def _op_swap_order(payload: bytes, rng: random.Random) -> bytes | None:
    """交换两个参数的位置 —— 放大"是否排序"。"""
    tokens = _split(payload.decode("latin-1"))
    if len(tokens) < 2:
        return None
    i, j = rng.sample(range(len(tokens)), 2)
    tokens[i], tokens[j] = tokens[j], tokens[i]
    return _join(tokens)


OPS = (_op_add_semicolon, _op_duplicate_param, _op_encode_value, _op_add_plus,
       _op_add_empty, _op_add_bracket, _op_flip_name_case, _op_swap_order)


class Mutator(_Mutator):
    """对每个种子随机叠加 1~2 个算子，产出确定性变体。"""

    OPERATORS = OPS
    MAX_OPS = 2


# --------------------------------------------------------------------------- 消融实验

def _pairs(text: str) -> list[str]:
    return [tok for tok in text.split("&") if tok != ""]


def _ab_drop_dups_first(payload: bytes) -> bytes:
    """抹掉重复参数（每个名字只留第一次出现）—— 消掉"取首/取尾"分歧。"""
    seen: set[str] = set()
    out: list[str] = []
    for token in _pairs(payload.decode("latin-1")):
        name = token.partition("=")[0]
        if name in seen:
            continue
        seen.add(name)
        out.append(token)
    return _join(out)


def _ab_semicolon_to_amp(payload: bytes) -> bytes:
    """把 `;` 换成正 `&` —— 消掉"分隔符"分歧。"""
    return payload.replace(b";", b"&")


def _ab_plus_to_encoded(payload: bytes) -> bytes:
    """把 `+` 换成 `%20` —— 消掉"`+` 是否当空格"分歧（两种口径都解成空格）。"""
    return payload.replace(b"+", b"%20")


def _ab_decode_one_layer(payload: bytes) -> bytes:
    """把百分号编码解一层 —— 消掉"解码层数"分歧。"""
    from ..impls.query_norm import _decode_once

    text, _ = _decode_once(payload.decode("latin-1"))
    return text.encode("latin-1")


def _ab_drop_empty(payload: bytes) -> bytes:
    """抹掉空值参数 —— 消掉"空值是否保留"分歧。"""
    return _join([tok for tok in _pairs(payload.decode("latin-1"))
                  if tok.partition("=")[2] != ""])


def _ab_strip_brackets(payload: bytes) -> bytes:
    """把参数名里的 `[...]` 去掉 —— 消掉"括号是否归一"分歧。"""
    import re

    out: list[str] = []
    for token in _pairs(payload.decode("latin-1")):
        name, sep, value = token.partition("=")
        out.append(re.sub(r"\[[^\]]*\]", "", name) + sep + value)
    return _join(out)


def _ab_lowercase_names(payload: bytes) -> bytes:
    """把参数名小写 —— 消掉"大小写敏感度"分歧。"""
    out: list[str] = []
    for token in _pairs(payload.decode("latin-1")):
        name, sep, value = token.partition("=")
        out.append(name.lower() + sep + value)
    return _join(out)


def _ab_sort_params(payload: bytes) -> bytes:
    """把参数按名字排序 —— 消掉"是否排序"分歧。"""
    tokens = _pairs(payload.decode("latin-1"))
    return _join(sorted(tokens, key=lambda t: (t.partition("=")[0], t)))


#: 消融实验：逐条"抹掉一类承载者 / 统一一种解释"重放两侧，看分歧是否消失。
#: 与路径领域同一条原理 —— 而查询串是攻击者直接发送的，故可控。
ABLATIONS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("抹掉重复参数（每个名字只留第一次出现）", _ab_drop_dups_first),
    ("把 `;` 换成正 `&`", _ab_semicolon_to_amp),
    ("把 `+` 换成 `%20`", _ab_plus_to_encoded),
    ("把百分号编码解一层", _ab_decode_one_layer),
    ("抹掉空值参数", _ab_drop_empty),
    ("把参数名里的 `[...]` 去掉", _ab_strip_brackets),
    ("把参数名全部小写", _ab_lowercase_names),
    ("把参数按名字排序", _ab_sort_params),
)


__all__ = ["AXES", "OPS", "ABLATIONS", "Mutator", "corpus"]
