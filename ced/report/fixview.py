"""修复形态与逐行对照 —— 把「该怎么改」写成可看见的对照表。

一条分歧到底在改什么？答案只有一个：**把承载歧义的那段字节重写成基准实现的
规范形态**。模糊写法（`%2e%2e`、重复参数、冲突的 CL/TE、大小写不一致的 Host…）
一旦被重写成无歧义写法，"同一段字节被读成了不同的东西"这件事就不存在了。
所以对照表看的是两栏：**原始输入** vs **规范化后的输入**。

为什么不写成一段"修复建议"文字了事：文字说不出"到底哪几个字节在制造歧义"。
逐行对照能 —— 被改掉的那几行就是答案，而且可以直接贴回 fuzzer / 代理规则里。

领域无关：改写规则是**领域知识**，由各适配器的 ``harden`` 给出（与 ``ablate`` /
``quantify`` 同一条分工），这里只负责取回结果、做逐行对照、算统计。
"""
from __future__ import annotations

from ..adapters import get as get_adapter

#: 超过这么多行就不做 LCS 对照了（一条请求不该有这么长的头部；多半不是单条请求）
MAX_DIFF_LINES = 300


def _text(line: bytes) -> str:
    """字节 → 可读文本：优先 UTF-8（中文头值），失败退回 latin-1（永不报错）。"""
    try:
        return line.decode("utf-8")
    except UnicodeDecodeError:
        return line.decode("latin-1")


def split_lines(payload: bytes) -> list[bytes]:
    """按行拆（同时认 CRLF 与裸 LF）；末尾空行不算一行。"""
    if not payload:
        return []
    body = payload.replace(b"\r\n", b"\n")
    lines = body.split(b"\n")
    while lines and not lines[-1]:
        lines.pop()
    return lines


def _row(tag: str, left: bytes | None, right: bytes | None,
         left_no: int | None, right_no: int | None) -> dict:
    return {"tag": tag,
            "orig": None if left is None else _text(left),
            "fixed": None if right is None else _text(right),
            "orig_no": left_no, "fixed_no": right_no}


def line_diff(original: bytes, fixed: bytes) -> list[dict]:
    """逐行对照（LCS）：``tag`` 为 ``same`` / ``del``（原样才有）/ ``add``（修复后才有）。

    顺序严格保持原文顺序 —— 对照表是给人一行行看的，不是给人排序的。
    """
    a = split_lines(original)
    b = split_lines(fixed)
    if len(a) > MAX_DIFF_LINES or len(b) > MAX_DIFF_LINES:
        return []                      # 太长了不逐行比，让调用方退回整体对照

    n, m = len(a), len(b)
    # 后缀 LCS 长度表：dp[i][j] = a[i:] 与 b[j:] 的最长公共子序列长度
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, below = dp[i], dp[i + 1]
        for j in range(m - 1, -1, -1):
            row[j] = (below[j + 1] + 1 if a[i] == b[j]
                      else max(below[j], row[j + 1]))

    rows: list[dict] = []
    i = j = 0
    while i < n and j < m:
        if a[i] == b[j]:
            rows.append(_row("same", a[i], b[j], i + 1, j + 1))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            rows.append(_row("del", a[i], None, i + 1, None))
            i += 1
        else:
            rows.append(_row("add", None, b[j], None, j + 1))
            j += 1
    while i < n:
        rows.append(_row("del", a[i], None, i + 1, None))
        i += 1
    while j < m:
        rows.append(_row("add", None, b[j], None, j + 1))
        j += 1
    return rows


def fix_view(domain: str, payload: bytes) -> dict | None:
    """算一条输入的修复形态与对照表；该领域给不出改写方案时返回 ``None``。

    ``payload`` 是**这条发现的原始输入**（整条请求，或领域认得的裸对象）——
    对照的右边是"改写后的它"，左边是它自己，所以看的人不用去别处找原文。
    """
    try:
        adapter = get_adapter(domain)
    except KeyError:
        # 领域名不认识（例如手工构造的 ScanResult 没填 domain）：
        # 这里是"取不到方案"，不是错误 —— 让整页/整份报告挂掉才是错误。
        return None
    harden = getattr(adapter, "harden", None)
    if harden is None:
        return None
    try:
        fixed = harden(payload)
    except Exception:      # noqa: BLE001 —— 改写失败不该让整份报告/页面挂掉
        return None
    if fixed is None:
        return None

    rows = line_diff(payload, fixed.fixed)
    return {
        "domain": domain,
        "fixed_text": _text(fixed.fixed),
        "changes": list(fixed.changes),
        "note": fixed.note,
        "reject": bool(fixed.reject),
        "rows": rows,
        "removed": sum(1 for r in rows if r["tag"] == "del"),
        "added": sum(1 for r in rows if r["tag"] == "add"),
        # 「改没改字节」问的是字节本身，不是那张对照表：超长输入压根不做逐行比对
        # （``rows`` 退化成空表），拿行去判断会得出"没改动"这个错误结论。
        "changed": fixed.fixed != payload,
    }
