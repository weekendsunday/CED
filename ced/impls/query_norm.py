"""可配置的查询串解析读取器 —— query-norm 领域的参照实现内核。

与 ``path_norm.py`` 同构、只建模一件事：**同一段查询串字节，两个实现认为
它携带了哪一组参数、每个参数取什么值**。

观测对象是 `?` **之后**的原始字节（如 ``b"a=1&a=2"``），不是整条请求。
不覆盖查询串全部语义 —— 耦合误差恰恰出在"同一份字节被判成不同参数集"上，而
"前置按自己的解析结果做校验、后端按自己的解析结果执行业务、两者取到的值不同"
就是 **HTTP 参数污染（HPP）/ 校验绕过**原语。

每个 :class:`QueryPolicy` 对应一组真实世界中出现过的解析策略组合。
参照实现用于**内部基准**（自证平台有效）；真实产品通过 probe 协议接入。

解析顺序（**刻意固定**：先按分隔符切分、再逐参数解码）——
反过来的话值里的 `%26` 会被当成新的参数分隔符，双重编码类分歧就消失了。
顺序本身不是策略开关，是这份内核的口径；写在这里以免被误当成实现细节。
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

_DECODE_LAYERS = {"never": 0, "once": 1, "twice": 2}

#: 括号语法：PHP 数组参数 `a[]`、`a[0]`、`a[key]` 的形态
_BRACKETS = re.compile(r"\[[^\]]*\]")


@dataclass(frozen=True)
class QueryPolicy:
    """一组查询串解析策略开关。每一项都是一个真实存在的实现差异点。"""

    name: str = "default"

    # 参数分隔符：只认 `&`，还是也认 `;`（RFC 3986 §3.4 允许 `;` 作子分隔符）
    # 先例：PHP 5.3.0 之前把 `;` 当参数分隔符，之后只认 `&`；Tomcat / W3C 建议 `;`。
    separators: str = "amp"              # amp | amp_semicolon
    # 同名参数取哪一个：取首 / 取尾 / 全要（HPP 的核心分歧）
    # 先例：Java Servlet `getParameter` 取首；PHP / Node `querystring` 取尾；
    #       ASP.NET `Request.QueryString[k]` 逗号合并全部。
    duplicate: str = "first"             # first | last | all
    # 百分号解码层数（`%26` 二次解码后变成 `&`）
    # 先例：多数框架解一次；前置 + 后端串联会形成事实上的二次解码。
    percent_decode: str = "once"         # never | once | twice
    # `+` 是否当空格（application/x-www-form-urlencoded）
    # 先例：PHP / Python `parse_qsl` 认；`decodeURIComponent` / 原生 URL 解析不认。
    plus_space: bool = True
    # 空值参数是否保留（`a=&b=1`）
    # 先例：多数框架保留空串；部分 WAF / 缓存会丢弃空值参数。
    keep_empty: bool = True
    # `a[]=1` / `a[0]=1` 括号语法是否归一成 `a`
    # 先例：PHP 把它读成数组；面向对象的框架 / WAF 会把 `[...]` 整个剥掉再看名字。
    bracket: str = "keep"                # keep | strip
    # 参数名是否大小写敏感
    # 先例：HTTP 规范里查询参数名大小写敏感；某些应用 / 网关会小写化后再匹配。
    case_sensitive: bool = True
    # 参数是否排序（影响缓存键 / 签名基串）
    # 先例：缓存与 WAF 常做规范化；AWS SigV4 要求查询串按键排序后签名。
    sort_params: bool = False


@dataclass
class QueryResult:
    """一次查询串解析的完整结果 —— 就是"这个实现认为请求带了哪些参数"。"""

    ok: bool = True
    status: int = 200
    reason: str = "OK"
    #: 归一化后的查询串（最关键）—— 同一段字节被判成不同参数集时这里必然不同
    norm_query: str = ""
    #: 归一化后的 (名字, 取值) 序列 —— 取值都已解码。修复形态要靠它**精确**重写
    #: （只从 ``norm_query`` 字符串反解会在取值含 ``&``/``=`` 时出错）。
    pairs: list = field(default_factory=list)
    #: 结果里的参数名（保序；开了排序则已排序）
    keys: list = field(default_factory=list)
    #: 归一化后的参数个数
    param_count: int = 0
    #: 重复参数里保留的取值（取首 / 取尾 / 全要）—— HPP 的核心观测量
    dup_kept: str = ""
    notes: list = field(default_factory=list)

    def to_fields(self) -> dict:
        return {
            "accepted": self.ok,
            "status": self.status,
            "norm_query": self.norm_query,
            "keys": list(self.keys),
            "param_count": self.param_count,
            "dup_kept": self.dup_kept,
        }


# --------------------------------------------------------------------------- 工具

def _is_hex(ch: str) -> bool:
    return ch in "0123456789abcdefABCDEF"


def _decode_once(text: str) -> tuple[str, bool]:
    """解一层百分号编码。返回 (结果, 是否发生变化)。不合法/残缺的 % 原样保留。"""
    out: list[str] = []
    changed = False
    i = 0
    n = len(text)
    while i < n:
        if (text[i] == "%" and i + 3 <= n
                and _is_hex(text[i + 1]) and _is_hex(text[i + 2])):
            out.append(chr(int(text[i + 1:i + 3], 16)))
            i += 3
            changed = True
        else:
            out.append(text[i])
            i += 1
    return "".join(out), changed


def _unquote(text: str, layers: int, plus_space: bool) -> str:
    """按层数解码；``+`` 是否先当成空格（与 ``unquote_plus`` 同序）。

    `+` → 空格发生在百分号解码**之前**：``%2B`` 解出来仍是 `+` 而不是空格，
    这正是 `application/x-www-form-urlencoded` 的既有口径。
    """
    if plus_space:
        text = text.replace("+", " ")
    for _ in range(layers):
        text, changed = _decode_once(text)
        if not changed:
            break
    return text


def _split_params(text: str, policy: QueryPolicy) -> list[str]:
    """按策略切分参数（空 token 丢弃 —— 与各实现的 ``parse_qsl`` 一致）。"""
    if policy.separators == "amp_semicolon":
        raw = re.split(r"[&;]", text)
    else:
        raw = text.split("&")
    return [token for token in raw if token != ""]


def _finalize_names(pairs: list[tuple[str, str]], policy: QueryPolicy) -> list[tuple[str, str]]:
    """结构归一化：空值过滤 → 括号剥离 → 大小写。"""
    out: list[tuple[str, str]] = []
    for name, value in pairs:
        if not policy.keep_empty and value == "":
            continue
        if policy.bracket == "strip":
            name = _BRACKETS.sub("", name)
        if not policy.case_sensitive:
            name = name.lower()
        out.append((name, value))
    return out


def _dedup(pairs: list[tuple[str, str]], policy: QueryPolicy) -> list[tuple[str, str]]:
    """同名参数去重：取首 / 取尾 / 全要。顺序按保留项的首次出现位置。"""
    if policy.duplicate == "all":
        return list(pairs)
    order: list[str] = []
    chosen: dict[str, str] = {}
    if policy.duplicate == "first":
        for name, value in pairs:
            if name not in chosen:
                chosen[name] = value
                order.append(name)
    else:                                  # last
        for name, value in pairs:
            if name not in chosen:
                order.append(name)
            chosen[name] = value
    return [(name, chosen[name]) for name in order]


def _dup_kept(raw_pairs: list[tuple[str, str]], kept: list[tuple[str, str]]) -> str:
    """重复参数里**保留下来的取值**（取首 / 取尾 / 全要）。

    只在被归一化后的名字上判重复 —— 这样 `A=1&a=2` 在大小写不敏感口径下
    才算同一个参数（且只在该口径下 dup_kept 才非空）。
    """
    counts = Counter(name for name, _ in raw_pairs)
    dup_names = [name for name in dict.fromkeys(name for name, _ in raw_pairs)
                 if counts[name] > 1]
    if not dup_names:
        return ""
    parts: list[str] = []
    for name in dup_names:
        values = [value for n, value in kept if n == name]
        parts.append("|".join(values))
    return ";".join(parts)


# --------------------------------------------------------------------------- 主入口

def parse_query(payload: bytes, policy: QueryPolicy) -> QueryResult:
    """按 ``policy`` 解析一段查询串字节（`?` 之后的内容，不含 `?`）。

    ``payload`` 是请求行里查询串的**原样**字节。
    """
    text = payload.decode("latin-1")

    layers = _DECODE_LAYERS.get(policy.percent_decode, 0)
    pairs: list[tuple[str, str]] = []
    for token in _split_params(text, policy):
        name, sep, value = token.partition("=")
        name = _unquote(name, layers, policy.plus_space)
        value = _unquote(value, layers, policy.plus_space) if sep else ""
        pairs.append((name, value))

    normed = _finalize_names(pairs, policy)
    kept = _dedup(normed, policy)
    if policy.sort_params:
        kept = sorted(kept, key=lambda kv: (kv[0], kv[1]))

    norm_query = "&".join(f"{name}={value}" for name, value in kept)

    return QueryResult(ok=True, status=200, reason="OK",
                       norm_query=norm_query,
                       pairs=list(kept),
                       keys=[name for name, _ in kept],
                       param_count=len(kept),
                       dup_kept=_dup_kept(normed, kept))


__all__ = ["QueryPolicy", "QueryResult", "parse_query"]
