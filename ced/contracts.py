"""核心数据契约。

所有模块只 import 这里，模块之间不互相 import 具体实现。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- 观测失败

class ProbeUnreachable(RuntimeError):
    """链路故障（端口没人听、探针没起来、前置既没转发也没回响应）→ **中止**。

    绝不允许合成一个"看起来像观测"的结果：合成出来的观测必然与基线不同，
    会把"探测失败"整片变成假阳性安全结论。
    """


class ProbeRejected(RuntimeError):
    """前置收到字节、但按自身策略拒绝转发（真实 nginx 对畸形请求回 400 就属此类）。

    这是**前置行为的如实记录**，不是链路故障 —— 若当成故障，一轮扫描会在第一条
    畸形请求上崩掉。处置分两处，口径一致：

      * 主观测被拒 → 跳过该条用例并计数（``pipeline``），既不合成视角也不谎称探过；
      * **消融候选被拒** → 该候选不算承载者（``classify.upgradability.still_diverges``），
        因为"分歧是否消失"无从观测，不能凭空造出可控性证据。

    放在这里而不是 ``probe/errors.py``：它由各层共用（pipeline / 适配器 / 探针），
    而 ``ced.probe`` 包会 import ``evaluator`` → ``adapters``，适配器再回头 import 它
    就成环了。
    """


# --------------------------------------------------------------------------- 被测对象

@dataclass(frozen=True)
class ImplSpec:
    """一个被测产品（实现）。"""

    impl_id: str
    name: str
    version: str = ""
    role: str = "solo"            # front | back | solo
    runner: str = "local"         # local | socket
    #: 该实现属于哪个领域（决定本地用哪个解析器；socket/chain 不关心）
    domain: str = "http1-framing"
    policy: str | None = None     # local 参照实现的策略名
    endpoint: str | None = None   # socket/chain 模式：host:port（探针，或前置入口）
    probe_api: str | None = None  # chain 模式：前置后面那个探针的控制口
    image: str | None = None      # 真实产品：镜像名（由 docker-compose 启动）
    notes: str = ""

    def __str__(self) -> str:  # noqa: D105
        return self.impl_id


# --------------------------------------------------------------------------- 观测

#: 参与差分的观测字段。适配器可覆盖。
DEFAULT_COMPARE_KEYS: tuple[str, ...] = (
    "accepted",
    "status",
    "framing_source",
    "cl",
    "te",
    "body_len",
    "consumed",
    "leftover_len",
)


@dataclass
class Observation:
    """一个实现对一段字节的"理解"。"""

    impl_id: str = ""
    ok: bool = True
    error: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {"impl_id": self.impl_id, "ok": self.ok,
                "error": self.error, "fields": dict(self.fields)}


# --------------------------------------------------------------------------- 差分

@dataclass
class FieldDiff:
    key: str
    left: Any
    right: Any

    def describe(self) -> str:
        return f"{self.key}: {self.left!r} != {self.right!r}"


@dataclass
class Divergence:
    """两个实现对同一段字节的理解不一致。"""

    case_id: str
    axis: str
    payload: bytes
    left: Observation
    right: Observation
    diffs: list[FieldDiff] = field(default_factory=list)

    @property
    def keys(self) -> list[str]:
        return [d.key for d in self.diffs]

    def summary(self) -> str:
        return (f"[{self.axis}] {self.left.impl_id} vs {self.right.impl_id}: "
                + "; ".join(d.describe() for d in self.diffs))


# --------------------------------------------------------------------------- 判定

#: 判定级别
LEVEL_SECURITY = "security"
LEVEL_COMPAT = "compatibility"
LEVEL_UNKNOWN = "unknown"


@dataclass
class Verdict:
    """可升级性判定结果。"""

    level: str = LEVEL_UNKNOWN
    kind: str = "unclassified"     # framing_boundary | syntax | chunk | request_line | status_only
    reason: str = ""
    cwe: str | None = None
    scenario: str | None = None    # desync | bypass | None
    controllable: bool = False     # 分歧点是否由攻击者可控的字节承载
    ablation: str | None = None    # 消融实验：定位承载分歧的字节
    effect: str = ""               # 安全后果（判定时由领域适配器给出）
    fix: str = ""                  # 修复建议（同上）

    @property
    def is_security(self) -> bool:
        return self.level == LEVEL_SECURITY


@dataclass
class Finding:
    """最终产出。"""

    divergence: Divergence
    verdict: Verdict
    minimized: bytes | None = None
    original_len: int = 0
    minimized_len: int = 0
    chain_evidence: str | None = None

    @property
    def case_id(self) -> str:
        return self.divergence.case_id


# --------------------------------------------------------------------------- 量化

@dataclass(frozen=True)
class Quantified:
    """把"两侧理解不同"量化成"真的有东西错位了"。

    各领域的量化指标不同（分帧是**被夹带的字节数**，路径归一化是**资源路径的错位**），
    但契约一致：给步骤占位符、给数字、给人类可读描述。判定器不消费它 ——
    它只影响报告与 PoC 的表述，**不参与 level 的判定**。
    """

    label: str                      # 指标名，如"被夹带字节数"
    describe: str                   # 人类可读描述（进报告）
    values: dict = field(default_factory=dict)   # 步骤模板占位符
    numbers: tuple | None = None    # 脚本断言用的数字/字符串
    verified: bool = True           # 是否真的量化出来了（否则如实写"未量化"）
