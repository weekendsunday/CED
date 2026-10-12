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

def parse_addr(addr: str) -> tuple[str, int]:
    """``host:port`` → ``(host, port)``；没有 host 时按本机回环兜底。

    探针数据口与前置地址都要按同一口径解析，所以放在这个"只被 import、
    不 import 具体实现"的叶子模块里（``probe.evaluator`` 与 ``probe.chain`` 共用）。
    """
    host, _, port = addr.rpartition(":")
    return host or "127.0.0.1", int(port)


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


def impl_brief(spec: ImplSpec) -> dict:
    """一个实现的"来路"摘要。

    报告与结果页都要把话说全："A 侧是谁、在哪个地址、这一条是**实测**还是推演"。
    ``measured`` 的定义只有一处 —— 观测来自真实产品（chain / socket）才算实测，
    内置参照实现之间的对比是推演（离线模型账）。
    """
    return {"id": spec.impl_id, "name": spec.name or spec.impl_id,
            "version": spec.version, "role": spec.role, "runner": spec.runner,
            "domain": spec.domain, "policy": spec.policy,
            "endpoint": spec.endpoint, "probe_api": spec.probe_api,
            "measured": spec.runner in ("chain", "socket")}


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

#: 危险等级（五档）—— 与 ``level`` **正交**：
#: ``level`` 回答"这算不算安全问题"，``severity`` 回答"多严重、证据多硬"。
#: 为什么要分开：``security`` 的本义只是"具备可升级的结构性前提"，
#: 把 CWE-22（跨目录）与 CWE-180（编码口径）塞进同一个"安全级"数字里，
#: 谁看都会把它读成"这么多漏洞"。
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

#: 从重到轻 —— 排序、配色、报告分档都按这个顺序
SEVERITY_ORDER: tuple[str, ...] = (SEVERITY_CRITICAL, SEVERITY_HIGH,
                                   SEVERITY_MEDIUM, SEVERITY_LOW,
                                   SEVERITY_INFO)

SEVERITY_RANK: dict[str, int] = {name: i for i, name in enumerate(SEVERITY_ORDER)}

SEVERITY_LABEL: dict[str, str] = {
    SEVERITY_CRITICAL: "严重", SEVERITY_HIGH: "高", SEVERITY_MEDIUM: "中",
    SEVERITY_LOW: "低", SEVERITY_INFO: "信息",
}

#: 老数据 / 外部构造的 ``Verdict`` 没带 severity 时按 level 兜底，
#: 保证 ``verdict.severity`` 永远有值（下游不必到处判空）。
_LEVEL_SEVERITY: dict[str, str] = {
    LEVEL_SECURITY: SEVERITY_MEDIUM,
    LEVEL_UNKNOWN: SEVERITY_LOW,
    LEVEL_COMPAT: SEVERITY_INFO,
}


def severity_label(severity: str) -> str:
    """等级代号 → 中文档位名。"""
    return SEVERITY_LABEL.get(severity, severity or "—")


def worst_severity(counts: dict[str, int]) -> str:
    """一组「等级 → 条数」里最严重的那一档（没有非零项就返回空串）。"""
    names = [name for name, count in counts.items() if count]
    return min(names, key=lambda name: SEVERITY_RANK.get(name, 99), default="")


def downgrade(severity: str, steps: int = 1) -> str:
    """降档（``high`` → ``medium`` → ``low`` → ``info``）；到底就停在 ``info``。"""
    rank = SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))
    return SEVERITY_ORDER[min(rank + steps, len(SEVERITY_ORDER) - 1)]


@dataclass
class Verdict:
    """可升级性判定结果。"""

    level: str = LEVEL_UNKNOWN     # 类别：security | unknown | compatibility
    kind: str = "unclassified"     # framing_boundary | syntax | chunk | request_line | status_only
    reason: str = ""
    cwe: str | None = None
    scenario: str | None = None    # desync | bypass | authz | filter | None
    controllable: bool = False     # 分歧点是否由攻击者可控的字节承载
    ablation: str | None = None    # 消融实验：定位承载分歧的字节
    effect: str = ""               # 安全后果（判定时由领域适配器给出）
    fix: str = ""                  # 修复建议（同上）
    #: 危险等级（``SEVERITY_*``）：类型上限 + 证据强度定出来的档位。
    #: 留空则按 ``level`` 兜底 —— 见 :meth:`__post_init__`。
    severity: str = ""

    def __post_init__(self) -> None:
        if not self.severity:
            self.severity = _LEVEL_SEVERITY.get(self.level, SEVERITY_INFO)

    @property
    def is_security(self) -> bool:
        return self.level == LEVEL_SECURITY

    @property
    def severity_label(self) -> str:
        return severity_label(self.severity)


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
    #: 量化结果是否**确实显示出错位**。两侧算出来一样时（如"前置后端都把同一段
    #: 路径认成 /a"）不构成危害证据 —— 定级要据此降档，而不是照样报"高"。
    mismatch: bool = True
    #: 是否**实机测量**（前置转发/探针实测）而非模型推演 —— 只有它能把等级顶到"严重"。
    measured: bool = False
    #: 这条链路**根本没串起来**（前置按自身策略拒绝了，一个字节都没转发）。
    #: 此时 ``mismatch=False`` 说的是"没有链路"，不是"两侧读成了同一个东西" ——
    #: 定级不该据此降档，否则一个"前置严格拒绝"的实现会把整类分歧降到"低"。
    blocked: bool = False


# --------------------------------------------------------------------------- 修复形态

@dataclass
class HardenedRequest:
    """一条分歧的「修复后形态」—— 与**原始输入**逐行对照用。

    怎么算出来的（领域知识，由适配器实现）：把承载歧义的那一段字节重写成
    **基准实现的规范形态** —— 模糊写法（`%2e%2e`、重复参数、冲突的 CL/TE、
    大小写不一致的 Host…）一旦重写成无歧义写法，"同一段字节被读成不同的东西"
    这件事就不存在了。所以对照看的是：**原始请求 vs 规范化后的请求**。

    ``reject`` 为真表示按修复口径这条请求**应当直接拒绝**（更保险的那一步）：
    ``fixed`` 仍然给出规范化形态，人才能看清到底哪几个字节在制造歧义 ——
    只看一句"请拒绝"是学不到东西的。
    """

    domain: str
    fixed: bytes
    changes: list[str] = field(default_factory=list)
    note: str = ""
    reject: bool = False
