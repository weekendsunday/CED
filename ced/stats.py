"""仓库规模数字的单一真源。

README / 报告里所有「从代码里数出来」的数字（领域数、实现数、对照数、
案例数、代码量、测试数）都由本模块生成 —— **不许手写**，改了代码就重跑：

    python -m ced stats        # 打印 Markdown 指标片段，直接贴回文档

数字一律现场从代码/适配器里数，不读缓存、不联网、不依赖第三方库。
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _count_lines(paths: list[Path]) -> int:
    total = 0
    for p in paths:
        try:
            total += sum(1 for _ in p.open("r", encoding="utf-8",
                                           errors="replace"))
        except OSError:
            pass
    return total


def source_files() -> list[Path]:
    """ced/ 下全部 Python 源码（不含测试）。"""
    return sorted(p for p in (ROOT / "ced").rglob("*.py")
                  if "tests" not in p.parts and "__pycache__" not in p.parts)


def test_files() -> list[Path]:
    return sorted((ROOT / "ced" / "tests").glob("test_*.py"))


def test_case_count() -> int:
    """静态数测试方法数（``def test_*``）。"""
    n = 0
    for p in test_files():
        for line in p.open("r", encoding="utf-8", errors="replace"):
            stripped = line.strip()
            if stripped.startswith("def test_") or stripped.startswith("async def test_"):
                n += 1
    return n


def domain_stats() -> list[dict]:
    """每个领域：名字、参照实现数、定向对照数。"""
    from .adapters import names, get

    out = []
    for name in names():
        adapter = get(name)
        out.append({
            "domain": name,
            "impls": len(adapter.specs()),
            "pairs": len(adapter.pairs()),
        })
    return out


def known_case_count() -> int:
    from .regression import load_cases, CASES_DIR
    return len(load_cases(CASES_DIR))


def frontend_files() -> list[Path]:
    """网页控制台的前端静态资源：页面 + 样式 + 脚本。

    三者都是手写的、由 ``server.py`` 白名单直出，所以要一起数 —— 只数
    ``index.html`` 会在拆分资源之后悄悄漏掉大半行数。
    """
    web = ROOT / "ced" / "web"
    return [p for p in (web / "index.html", web / "app.css", web / "app.js")
            if p.is_file()]


def collect() -> dict:
    doms = domain_stats()
    src, tst = source_files(), test_files()
    return {
        "domains": doms,
        "domain_count": len(doms),
        "impl_total": sum(d["impls"] for d in doms),
        "pair_total": sum(d["pairs"] for d in doms),
        "known_cases": known_case_count(),
        "src_files": len(src),
        "src_lines": _count_lines(src),
        "test_files": len(tst),
        "test_lines": _count_lines(tst),
        "test_cases": test_case_count(),
        "frontend_files": len(frontend_files()),
        "frontend_lines": _count_lines(frontend_files()),
    }


def render_markdown() -> str:
    s = collect()
    doms = s["domains"]
    impl_breakdown = "+".join(str(d["impls"]) for d in doms)
    pair_breakdown = "+".join(str(d["pairs"]) for d in doms)
    domain_list = " · ".join(f"`{d['domain']}`" for d in doms)
    lines = [
        "| 指标 | 数字 |",
        "|---|---|",
        f"| 领域 | **{s['domain_count']} 个**：{domain_list} |",
        (f"| 参照实现 / 定向对照 | {impl_breakdown} = **{s['impl_total']} 个参照实现**，"
         f"{pair_breakdown} = **{s['pair_total']} 对定向对照** |"),
        f"| 已知案例反验证 | **{s['known_cases']} 条**内置案例 |",
        (f"| 代码量 | 源码 {s['src_files']} 文件 {s['src_lines']} 行；"
         f"测试 {s['test_files']} 文件 {s['test_lines']} 行（测试方法 {s['test_cases']} 个，静态计数；"
         f"实跑结果见 `python main.py --check`）；"
         f"前端 {s['frontend_files']} 文件 {s['frontend_lines']} 行"
         f"（`index.html` / `app.css` / `app.js`）|"),
        "",
        "> 本表由 `python -m ced stats` 现场从代码生成，不手写。",
    ]
    return "\n".join(lines)


__all__ = ["collect", "render_markdown"]
