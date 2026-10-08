"""从一条发现生成**可运行的端到端 PoC**。

产出三样东西，缺一不可：

  1. **叙事** —— 场景、影响、前提、复现步骤（由 ``templates`` 提供，这里填数字）；
  2. **量化** —— 把"两侧理解不同"变成"真的有东西错位了"。口径由**领域适配器**给出
     （分帧是"被夹带字节数"，路径归一化是"资源路径错位"），数字来自真实解析器；
  3. **脚本** —— 一个零第三方依赖、可直接执行的复现脚本（按领域选骨架），
     离线可算账、授权后可真发。

只对 ``security`` 级发现生成 PoC。``unknown`` / ``compatibility`` 一律不出 ——
**不夸大**是这套东西能站住的前提。
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters import get as get_adapter
from .. import artifacts
from ..contracts import Quantified
from . import templates

#: 生成的脚本文件名前缀
POC_PREFIX = "poc_"
#: 缺省领域（找回退适配器时用）
DEFAULT_DOMAIN = "http1-framing"


@dataclass(frozen=True)
class Poc:
    """一条发现对应的端到端复现材料。"""

    case_id: str
    scenario: str
    title: str
    level: str
    cwe: str | None
    left: str
    right: str
    axis: str
    domain: str
    impact: str
    fix: str
    evidence: str
    chain_desc: str
    #: 量化：指标名 + 人类可读描述 + 参与量化的值；未量化时为 None
    quant: Quantified | None
    original_len: int
    sample_len: int
    request_b64: str
    steps: tuple[str, ...] = field(default_factory=tuple)
    script: str = ""

    @property
    def request(self) -> bytes:
        return base64.b64decode(self.request_b64)

    @property
    def file_name(self) -> str:
        return f"{POC_PREFIX}{self.case_id}.py"

    @property
    def verified(self) -> bool:
        return self.quant is not None and self.quant.verified

    def to_dict(self) -> dict:
        """给报告 / 网页 / 落库用的扁平行。"""
        quant = None
        if self.quant is not None:
            quant = {"label": self.quant.label, "describe": self.quant.describe,
                     "values": {k: str(v) for k, v in self.quant.values.items()},
                     "numbers": list(self.quant.numbers or ()),
                     "verified": self.quant.verified}
        return {
            "case_id": self.case_id, "scenario": self.scenario, "title": self.title,
            "level": self.level, "cwe": self.cwe, "left": self.left,
            "right": self.right, "axis": self.axis, "domain": self.domain,
            "impact": self.impact, "fix": self.fix, "evidence": self.evidence,
            "chain_desc": self.chain_desc, "quant": quant,
            "verified": self.verified,
            "original_len": self.original_len, "sample_len": self.sample_len,
            "request_b64": self.request_b64, "steps": list(self.steps),
            "script": self.script, "file_name": self.file_name,
        }


# --------------------------------------------------------------------- 步骤

_FALLBACK_STEPS = (
    "确认链路方向：客户端 → {front} → {back}",
    "把下面的最小复现样本原样发给 {front}",
    "两侧含非本地实现或无法量化，本机算不出错位量 —— "
    "请在真实拓扑上按 §3.5 的方式复现，观察两侧观测差异",
    "消融实验证据：{evidence}",
    "修复：{fix}",
)


def _steps(scenario: templates.Scenario, values: dict) -> tuple[str, ...]:
    return tuple(step.format(**values) for step in scenario.steps)


# --------------------------------------------------------------------- 脚本骨架

#: 跨领域的脚本骨架。{domain_block} 由各领域填"怎么算账 + 怎么断言"。
_SCRIPT = '''#!/usr/bin/env python3
"""{title}

由 CED 自动生成 —— 用例 {case_id}，场景 {scenario}，领域 {domain}。
零第三方依赖；放在仓库任意位置都能跑（脚本会自己往上找仓库根目录）。

    python {file_name}                      # 离线：算清量化指标（默认，不联网）
    python {file_name} --send HOST:PORT --i-am-authorized
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

{imports}

CASE_ID = {case_id!r}
FRONT = {front!r}
BACK = {back!r}
PAYLOAD = base64.b64decode({payload_b64!r})
EXPECT = {expect!r}


def measure():
    """按两侧的策略算出量化指标。算不出来返回 None。"""
{measure_body}


def main() -> int:
    ap = argparse.ArgumentParser(description="CED 生成的复现脚本")
    ap.add_argument("--send", metavar="HOST:PORT",
                    help="把最小复现样本真的发到这个地址（前置入口）")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="确认对 --send 的目标已获授权；缺此项则拒绝发送")
    args = ap.parse_args()

    print(f"用例        {{CASE_ID}}")
    print(f"链路        {{FRONT}} → {{BACK}}")
    print(f"样本长度    {{len(PAYLOAD)}} 字节")

    got = measure()
    ok = got is not None
    if got is None:
        print("量化        无法计算（两侧含非本地实现）—— 请在真实拓扑上复现")
    else:
{report_body}

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
        print(f"已发送      {{args.send}}，收到 {{len(response)}} 字节响应")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''

def _render_script(*, adapter, quant: Quantified | None, **common) -> str:
    """脚本骨架由本模块统一提供（参数解析 / 合规门禁 / --send）；
    「怎么算这个领域的量化指标、怎么断言」由**适配器**填（``poc_block()``）——
    所以新增领域不需要碰这个文件。
    """
    return _SCRIPT.format(domain=adapter.name, **adapter.poc_block(), **common)


# --------------------------------------------------------------------- 对外接口

def build_poc(finding, *, domain: str = DEFAULT_DOMAIN) -> Poc | None:
    """为一条发现生成 PoC。**只对 security 级生成**，其余返回 None。"""
    verdict = finding.verdict
    if not verdict.is_security:
        return None

    divergence = finding.divergence
    payload = (finding.minimized if finding.minimized is not None
               else divergence.payload)
    template = templates.get(verdict.scenario)
    evidence = verdict.ablation or "（未定位到可控承载 —— 该分歧本不该判为安全级，请复核）"

    adapter = get_adapter(domain)
    quant = adapter.quantify(payload, divergence.left.impl_id,
                             divergence.right.impl_id)

    values: dict = {
        "front": divergence.left.impl_id,
        "back": divergence.right.impl_id,
        "cwe": verdict.cwe or "—",
        "evidence": evidence,
        "fix": verdict.fix or "—",
    }
    if quant is not None:
        values.update({k: v for k, v in quant.values.items()})

    if quant is not None:
        steps = _steps(template, values)
    else:
        steps = tuple(step.format(**values) for step in _FALLBACK_STEPS)

    script = _render_script(
        adapter=adapter,
        quant=quant,
        title=template.title,
        case_id=finding.case_id,
        scenario=template.name,
        file_name=f"{POC_PREFIX}{finding.case_id}.py",
        front=divergence.left.impl_id,
        back=divergence.right.impl_id,
        payload_b64=base64.b64encode(payload).decode(),
        expect=tuple(quant.numbers or ()) if quant is not None else (None,),
    )

    return Poc(
        case_id=finding.case_id,
        scenario=template.name,
        title=template.title,
        level=verdict.level,
        cwe=verdict.cwe,
        left=divergence.left.impl_id,
        right=divergence.right.impl_id,
        axis=divergence.axis,
        domain=domain,
        impact=template.impact,
        fix=verdict.fix or "—",
        evidence=evidence,
        chain_desc=finding.chain_evidence or (
            quant.describe if quant is not None else "（未量化：两侧含非本地实现）"),
        quant=quant,
        original_len=finding.original_len or len(divergence.payload),
        sample_len=len(payload),
        request_b64=base64.b64encode(payload).decode(),
        steps=steps,
        script=script,
    )


def build_pocs(result) -> list[Poc]:
    """一次扫描里所有 security 级发现的 PoC，按 case_id 去重。

    领域从 ``ScanResult.domain`` 取 —— 调用方不需要知道这件事。
    """
    domain = getattr(result, "domain", "") or DEFAULT_DOMAIN
    out: list[Poc] = []
    seen: set[str] = set()
    for finding in result.findings:
        if finding.case_id in seen:
            continue
        poc = build_poc(finding, domain=domain)
        if poc is None:
            continue
        seen.add(finding.case_id)
        out.append(poc)
    return out


def write_pocs(result, out_dir: str | Path) -> list[Path]:
    """把 PoC 脚本落盘，返回写出的路径（已存在且内容相同时不重写）。"""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for poc in build_pocs(result):
        path = directory / poc.file_name
        if not path.exists() or path.read_text(encoding="utf-8") != poc.script:
            artifacts.write_text(path, poc.script)
        written.append(path)
    return written


__all__ = ["Poc", "POC_PREFIX", "DEFAULT_DOMAIN", "build_poc", "build_pocs",
           "write_pocs"]
