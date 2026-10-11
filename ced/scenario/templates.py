"""攻击场景模板 —— 把"可升级的语义分歧"翻译成**可复现的攻击叙事**。

场景是**数据**，不是代码分支：每个场景只声明"标题 / 影响 / 前提 / 步骤模板"，
真正填数字（转发了多少字节、夹带了多少字节）由 ``poc.py`` 统一做。
这样新增一个场景不需要动复现逻辑。

占位符由 ``poc.py`` 填充：
    {front} {back} {cwe} {forwarded} {back_consumed} {smuggled} {evidence} {fix}
"""
from __future__ import annotations

from dataclasses import dataclass

SCENARIO_DESYNC = "desync"
SCENARIO_BYPASS = "bypass"
SCENARIO_AUTHZ = "authz"
SCENARIO_POISON = "poison"
SCENARIO_PARAM = "param"
SCENARIO_FILTER = "filter"
SCENARIO_GENERIC = "generic"


@dataclass(frozen=True)
class Scenario:
    """一个攻击场景的**模板**。"""

    name: str
    title: str
    impact: str
    preconditions: tuple[str, ...]
    steps: tuple[str, ...]
    #: 是否能用"前置转发了多少 / 后端消费了多少 / 夹带多少"来量化
    quotable: bool = True


DESYNC = Scenario(
    name=SCENARIO_DESYNC,
    title="请求走私（HTTP/1.1 消息边界分歧）",
    impact=(
        "前置与后端对『这条请求到哪里结束』判断不同：前置转发的字节里，"
        "后端只消费了一部分，剩下的成为后端眼中**下一条请求**的开头。"
        "于是攻击者可以在前置完全看不见的情况下，向后端注入一条自选请求 —— "
        "前置的鉴权、限流、审计对这条被夹带的请求全部失效。"
    ),
    preconditions=(
        "前置与后端对同一段字节的定帧策略不一致（本工具已用差分 + 消融实验证明）",
        "两侧串联且复用同一条后端连接（HTTP/1.1 长连接或连接池）",
        "攻击者能直接向前置发送请求（含畸形写法）",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置） → {back}（后端）",
        "把下面的最小复现样本原样发给 {front}：它包含一处非规范的定帧写法",
        "{front} 按自身策略认为该请求占用 {forwarded} 字节，全部转发给 {back}",
        "{back} 按自身策略只消费 {back_consumed} 字节 → 剩余 **{smuggled} 字节**留在后端缓冲区",
        "紧随其后的下一条请求会被拼接在那 {smuggled} 字节之后，"
        "被夹带的字节成为后端眼中另一条请求的开头",
        "修复：{fix}",
    ),
)

BYPASS = Scenario(
    name=SCENARIO_BYPASS,
    title="防护绕过（接受性分歧）",
    impact=(
        "一侧接受、另一侧拒绝同一段字节。前置放行而下游拒绝（或反之）时，"
        "任何依赖前置做拦截的保护（WAF 规则、鉴权中间件、路径白名单）"
        "都可能被绕过，或被用于制造可用性差异。"
    ),
    preconditions=(
        "两侧对同一份非规范语法的接受度不同（本工具已用消融实验定位分歧由可控字节承载）",
        "前置的保护策略建立在其自身解析结果之上",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置） → {back}（下游）",
        "把下面的最小复现样本发给 {front}",
        "{front} 与 {back} 对这份字节的接受性判断不同（接受/拒绝分叉）",
        "消融实验证据：{evidence}",
        "修复：{fix}",
    ),
    quotable=False,
)

AUTHZ = Scenario(
    name=SCENARIO_AUTHZ,
    title="鉴权绕过（路径归一化不一致）",
    impact=(
        "前置与后端把同一段请求目标解释成**不同资源字符串**：前置按自己的归一化结果做鉴权、"
        "后端按自己的归一化结果路由。**若**两者的解算结果指向不同资源，攻击者就能触及"
        "前置认为他无权触及的那个 —— 鉴权、目录保护、WAF 路径规则全都落在错的对象上。"
        "注意：字符串不同不等于资源不同（例如根目录下的 `/..` 与 `/` 是同一个资源），"
        "**是否真的构成绕过，要看两端各自的路由与鉴权规则** —— "
        "所以这里给出两侧的解算结果与最小复现样本供直接复核。"
    ),
    preconditions=(
        "前置与后端对同一段 target 的归一化口径不一致（本工具已用差分 + 消融实验证明）",
        "前置的鉴权 / 防护决策建立在自己的归一化结果之上",
        "后端对转发过来的 target 会再解释一次（重新解码 / 重新归一化）",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置，做鉴权） → {back}（后端，做路由）",
        "把下面的 target 原样发给 {front}",
        "{front} 把它归一化成 `{norm_front}` —— 它据此判定「允许访问」",
        "{back} 把同一段字节归一化成 `{norm_back}` —— 它据此路由到**另一个资源**",
        "两侧解算结果的差别，就是攻击者实际触及、而按前置的判定本不该触及的资源",
        "修复：{fix}",
    ),
    quotable=True,
)

POISON = Scenario(
    name=SCENARIO_POISON,
    title="虚拟主机绕过 / 缓存投毒（Host 归一化不一致）",
    impact=(
        "前置与后端把同一个 Host 头认成**不同的虚拟主机**：前置按自己的归一化结果选路由/缓存键、"
        "后端按自己的归一化结果选站。**若**两者落在不同站点或不同缓存键上，就会出现"
        "虚拟主机绕过（访问到本不该路由到的站）或缓存投毒（一条响应被缓存到另一个键下，"
        "喂给别的用户）。注意：字符串不同不等于主机不同，"
        "**是否真的构成绕过要看两端的路由表与缓存键规则** —— 两侧解算结果已一并给出供复核。"
    ),
    preconditions=(
        "前置与后端对同一段 Host 的归一化口径不一致（本工具已用差分 + 消融实验证明）",
        "前置的路由 / 缓存键决策建立在自己的归一化结果之上",
        "后端对转发过来的 Host 会再解释一次",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（前置，选路由/缓存键） → {back}（后端，选站）",
        "把下面的 Host 值原样发给 {front}",
        "{front} 把它归一化成 `{norm_front}` —— 它据此选到某个站/缓存键",
        "{back} 把同一段字节归一化成 `{norm_back}` —— 它据此选到**另一个站**",
        "两侧解算结果的差别，就是攻击者实际到达、而按前置的判定本不该到达的那个站/缓存键",
        "修复：{fix}",
    ),
    quotable=True,
)

PARAM = Scenario(
    name=SCENARIO_PARAM,
    title="参数污染（查询串解析不一致）",
    impact=(
        "同一段查询串被两侧解析成**不同的参数集合或不同的取值**："
        "前置的校验/鉴权读到的是第一个值，业务逻辑吃到的是最后一个值（或反之）。"
        "**若**两者读到的不是同一个值，就可能绕过校验、越权访问他人数据、或篡改业务结果。"
        "字符串不同不等于语义不同，**是否可利用要看两端各自怎么取值** —— 两侧解算结果已一并给出。"
    ),
    preconditions=(
        "前置与后端对同一段查询串的解析口径不一致（本工具已用差分 + 消融实验证明）",
        "至少一侧的安全校验（鉴权/白名单/金额/ID 归属）建立在自己的解析结果之上",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（做校验） → {back}（做业务）",
        "把下面的查询串原样发给 {front}",
        "{front} 把它解析成 `{norm_front}` —— 它据此做校验",
        "{back} 把同一段字节解析成 `{norm_back}` —— 它据此执行业务",
        "两侧取值不同这件事，就是攻击者用同一份输入让「被校验的值」与「被使用的值」分叉",
        "修复：{fix}",
    ),
    quotable=True,
)

FILTER = Scenario(
    name=SCENARIO_FILTER,
    title="过滤器绕过（编码 / Unicode 归一化不一致）",
    impact=(
        "同一段字节被两侧按**不同的编码/规范化**解释：一側在检查（WAF、关键字黑名单、"
        "路径前缀、扩展名白名单）时看到的是无害形式，另一侧在真正执行时解成了危险形式。"
        "**若**两者的解释结果不同，检查就落空了 —— 这是编码绕过与 Unicode 绕过的共同机理。"
        "两侧解释结果已一并给出，是否可利用取决于真正的执行侧怎么解释。"
    ),
    preconditions=(
        "一側做检查、另一側做执行，且两者对同一份字节的编码/规范化口径不一致"
        "（本工具已用差分 + 消融实验证明）",
        "检查侧的判定建立在它自己的解码/规范化结果之上",
    ),
    steps=(
        "确认链路方向：客户端 → {front}（做检查） → {back}（做执行）",
        "把下面的字节原样发给 {front}",
        "{front} 把它解释成 `{norm_front}` —— 它据此做检查（判为无害）",
        "{back} 把同一段字节解释成 `{norm_back}` —— 它据此执行",
        "两侧解释结果的差别，就是检查侧漏看而执行侧认得的那部分",
        "修复：{fix}",
    ),
    quotable=True,
)

GENERIC = Scenario(
    name=SCENARIO_GENERIC,
    title="可升级分歧（场景未归类）",
    impact=(
        "该分歧已通过『消息边界解释 + 攻击者可控』两道判定，但尚未归入已知攻击场景。"
        "这里只给出**最小复现样本与对比观测**，不对攻击后果下结论。"
    ),
    preconditions=(
        "分歧落在结构字段上且由攻击者可直接发送的字节承载",
    ),
    steps=(
        "确认链路方向：客户端 → {front} → {back}",
        "把下面的最小复现样本发给 {front}，观察两侧观测差异",
        "消融实验证据：{evidence}",
        "修复：{fix}",
    ),
    quotable=False,
)

#: 场景注册表：键与 ``Verdict.scenario`` 对齐
SCENARIOS: dict[str, Scenario] = {
    DESYNC.name: DESYNC,
    BYPASS.name: BYPASS,
    AUTHZ.name: AUTHZ,
    POISON.name: POISON,
    PARAM.name: PARAM,
    FILTER.name: FILTER,
    SCENARIO_GENERIC: GENERIC,
}


def get(scenario: str | None) -> Scenario:
    """按 ``Verdict.scenario`` 取模板；未知或为空时退回通用模板。"""
    return SCENARIOS.get(scenario or "", GENERIC)


def names() -> list[str]:
    return sorted(SCENARIOS)


__all__ = ["DESYNC", "BYPASS", "AUTHZ", "POISON", "PARAM", "FILTER", "GENERIC",
           "SCENARIOS", "Scenario", "get", "names", "AUTO_UPGRADED",
           "SCENARIO_DESYNC", "SCENARIO_BYPASS", "SCENARIO_AUTHZ",
           "SCENARIO_POISON", "SCENARIO_PARAM", "SCENARIO_FILTER",
           "SCENARIO_GENERIC"]


#: 真正会被自动升级的场景（其余走通用模板，只给复现不给后果结论）
AUTO_UPGRADED: tuple[str, ...] = (SCENARIO_DESYNC, SCENARIO_BYPASS, SCENARIO_AUTHZ,
                                  SCENARIO_POISON, SCENARIO_PARAM, SCENARIO_FILTER)
