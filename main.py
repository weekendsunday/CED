"""CED 启动入口 —— 直接运行这个文件即可。

    python main.py                  启动扫描控制台（自动打开浏览器）
    python main.py --no-open        只起服务，不打开浏览器
    python main.py --port 9000      换端口
    python main.py --probe          同时起一个探针服务（接入真实产品时用）
    python main.py --check          跑自检（测试 + 已知案例反验证）后退出

控制台里能做的：起扫描任务并实时看进度、按级别 triage 结果、逐条看证据
（双侧观测 / 消融证据 / 最小复现样本 / 链式复现）、查看模型提案命中率台账。

模型是可选旁路：配置 CED_LLM_BASE_URL / CED_LLM_MODEL 后可使用「模型提案」，
不配置则全链路自动降级为纯确定性模式，扫描照跑。大模型只提案，判定权在内核。

在 VSCode / PyCharm 里直接点运行按钮也可以 —— 工作目录不对也没关系，
下面会把仓库根目录加进 sys.path。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEST_FILES = (
    "ced/tests/test_pipeline.py",
    "ced/tests/test_socket_probe.py",
    "ced/tests/test_chain_e2e.py",
    "ced/tests/test_assist.py",
    "ced/tests/test_adopted.py",
    "ced/tests/test_scan_console.py",
    "ced/tests/test_scenario.py",
    "ced/tests/test_metrics_web.py",
    "ced/tests/test_agent.py",
    "ced/tests/test_url_norm.py",
    "ced/tests/test_host_norm.py",
    "ced/tests/test_query_norm.py",
    "ced/tests/test_enc_norm.py",
    "ced/tests/test_intake.py",
    "ced/tests/test_cluster.py",
    "ced/tests/test_probe_domains.py",
    "ced/tests/test_capture.py",
    "ced/tests/test_detect.py",
    "ced/tests/test_samples.py",
)


def run_check() -> int:
    """跑一遍自检：三组测试 + 已知案例反验证。"""
    print("=" * 66)
    print("CED 自检")
    print("=" * 66)
    failed = 0

    for rel in TEST_FILES:
        print(f"\n--- {rel} ---", flush=True)
        if subprocess.call([sys.executable, str(ROOT / rel)], cwd=str(ROOT)) != 0:
            failed += 1

    print("\n--- 已知案例反验证 ---", flush=True)
    from ced import regression
    outcomes = regression.run()
    for outcome in outcomes:
        flag = "PASS" if outcome.passed else "FAIL"
        print(f"  [{flag}] {outcome.name:<28} {outcome.detail}")
    passed = sum(1 for o in outcomes if o.passed)
    print(f"== 已知案例反验证：{passed}/{len(outcomes)} 通过 ==")
    if passed != len(outcomes):
        failed += 1

    print()
    print("=" * 66)
    print("自检通过，一切正常。" if not failed else f"有 {failed} 处失败，见上面输出。")
    print("=" * 66)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="main.py", description="CED — 产品耦合误差检测（启动入口）")
    parser.add_argument("--port", type=int, default=8777, help="网页界面端口")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--no-open", action="store_true", help="不要自动打开浏览器")
    parser.add_argument("--probe", action="store_true",
                        help="同时起探针服务（把真实产品接进来时用）")
    parser.add_argument("--probe-port", type=int, default=8800)
    parser.add_argument("--probe-api-port", type=int, default=8801)
    parser.add_argument("--check", action="store_true", help="跑自检后退出")
    args = parser.parse_args(argv)

    if args.check:
        return run_check()

    if args.probe:
        from ced.impls import reference
        from ced.probe.server import serve as probe_serve

        def _probe() -> None:
            try:
                probe_serve(args.host, args.probe_port, args.probe_api_port,
                            reference.policy_of("ref-cl-first"))
            except OSError as exc:
                print(f"[!] 探针服务起不来（端口被占？）：{exc}")

        threading.Thread(target=_probe, daemon=True).start()

    from ced.web.server import serve
    serve(args.port, args.host, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
