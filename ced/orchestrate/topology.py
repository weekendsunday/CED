"""连线设置（原先叫"拓扑"）：产品怎么串起来、引擎从哪儿观测它。

对应方案 §0.2 的输入契约：
  ① 产品本身（内置参照实现，或 socket/chain 指向的真实产品）
  ② 产品之间的串联方式（chain）

**这一层宁可报错也不静默。** 字段写错、产品清单为空、id 缺失、
runner 说不出地址 —— 一律当场说人话。这里是"跑完 0 条分歧、还以为
跑过了"最容易发生的地方：按旧文档那份示例（``topology:`` /
``product:``）写文件，从前会解析出 0 个实现、跑完报 0 条分歧、
还一声不吭。

文件支持 YAML 或 JSON。本机默认不装 PyYAML，所以读 .yaml 会给人话
而不是一个看不懂的 JSONDecodeError（仓库里的示例另备了 .json）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..contracts import ImplSpec

#: 连线设置的文件格式版本。写在文件里（``format: 1``），加载时核对。
#: 将来改字段时，"旧文件 + 新程序"至少要能说出"你这是旧版本写的"。
FORMAT_VERSION = 1

#: 顶层字段 / 实现字段。**多写一个都要报错** —— 静默忽略字段正是
#: "少接了东西却以为接上了"的来源。
_TOP_KEYS = ("format", "domain", "impls", "product", "chain", "notes")
#: 旧文档写法：topology = 产品清单
_TOP_ALIASES = {"topology": "impls"}
_IMPL_KEYS = ("id", "name", "version", "role", "runner", "domain",
              "policy", "endpoint", "probe_api", "image", "notes")
_IMPL_ALIASES = {"product": "image", "address": "endpoint",
                 "control": "probe_api"}
#: 单个产品的简写（界面上"接我的产品"就是写这一段）
_PRODUCT_KEYS = ("id", "name", "version", "policy", "endpoint",
                 "probe_api", "image", "notes")
_RUNNERS = ("local", "socket", "chain")
_ROLES = ("front", "back", "solo")


class SettingsError(ValueError):
    """连线设置本身有问题 —— 消息就是给用户看的人话，不再包一层。"""


@dataclass
class Topology:
    domain: str = "http1-framing"
    impls: list[ImplSpec] = field(default_factory=list)
    #: 客户真实链路（前置, 后端）；None 表示只做两两差分
    chain: tuple[str, str] | None = None

    def ids(self) -> list[str]:
        return [s.impl_id for s in self.impls]

    def describe(self) -> str:
        chain = " → ".join(self.chain) if self.chain else "(未指定链路)"
        return f"domain={self.domain} impls={len(self.impls)} chain={chain}"


# ----------------------------------------------------------------- 读文件

def _parse_text(text: str, suffix: str, source: str) -> dict:
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise SettingsError(
                f"{source} 是 YAML，但这台机器没装 YAML 解析器。"
                f"两条路：另存成 .json（内容照写），或装上解析器"
                f"（pip install pyyaml）后重试。") from exc
        try:
            raw = yaml.safe_load(text)
        except Exception as exc:                    # noqa: BLE001
            raise SettingsError(f"{source} 不是合法的 YAML：{exc}") from exc
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SettingsError(
                f"{source} 不是合法的 JSON（第 {exc.lineno} 行第 "
                f"{exc.colno} 列：{exc.msg}）—— 检查是不是少了逗号、"
                f"引号，或者选了 YAML 却把文件存成了 .json。") from exc
    if not isinstance(raw, dict):
        raise SettingsError(
            f"{source} 的最外层应该是一组「字段: 值」，"
            f"实际是 {type(raw).__name__}")
    return raw


# ----------------------------------------------------------------- 校验

def _reject_unknown(where: str, node: dict, allowed, aliases: dict) -> None:
    unknown = [k for k in node if k not in allowed and k not in aliases]
    if not unknown:
        return
    names = "、".join(allowed) + "".join(
        f"（旧写法 {a} = {t}）" for a, t in aliases.items())
    raise SettingsError(
        f"{where} 里有不认识的字段：{'、'.join(map(str, unknown))}。"
        f"可用字段：{names}")


def _canonical(node: dict, aliases: dict) -> dict:
    out = {}
    for key, value in node.items():
        name = aliases.get(key, key)
        if name in out and out[name] != value:
            raise SettingsError(f"字段 {name} 被写了两次（其中一次是旧写法）")
        out[name] = value
    return out


def _id_from_image(image: str) -> str:
    """从镜像名里取一个能当 id 的名字：``repo/name:tag`` → ``name``。"""
    head = image.split("@", 1)[0].rsplit("/", 1)[-1]
    return head.split(":", 1)[0]


def _version_from_image(image: str) -> str:
    head = image.split("@", 1)[0].rsplit("/", 1)[-1]
    return head.split(":", 1)[1] if ":" in head else ""


def _require_reference(where: str, impl_id: str, policy: str,
                       domain: str) -> None:
    """内置参照实现（runner=local）的 policy 必须真的存在。

    少了这道检查，"把真实产品写成 runner=local"要一路走到运行期才炸，
    而且报的是一个裸 KeyError —— 正是"看着跑完了、其实什么都没测"的来源。
    """
    from ..impls import local_specs
    try:
        known = {s.impl_id for s in local_specs(domain)}
    except KeyError:                # 领域还没注册（命令行/测试的导入顺序）
        return
    if policy not in known:
        raise SettingsError(
            f"{where}（{impl_id}）是内置参照实现（runner=local），但 "
            f"policy=「{policy}」不是 {domain} 里的参照实现。"
            f"要接真实产品请写 runner: chain + endpoint + probe_api。")


def _impl_of(node, where: str, default_domain: str, source: str) -> ImplSpec:
    if not isinstance(node, dict):
        raise SettingsError(
            f"{where} 应该是一组「字段: 值」，实际是 {type(node).__name__}")
    _reject_unknown(where, node, _IMPL_KEYS, _IMPL_ALIASES)
    node = _canonical(node, _IMPL_ALIASES)

    image = node.get("image")
    impl_id = node.get("id") or (_id_from_image(image) if image else "")
    if not impl_id:
        raise SettingsError(
            f"{where} 没写 id。每个产品都要有个名字（例如 "
            f"id: customer-gateway），报告和结果页都靠它指认是谁。")

    runner = node.get("runner", "local")
    if runner not in _RUNNERS:
        raise SettingsError(
            f"{where}（{impl_id}）的 runner 是「{runner}」，只认 "
            f"{'、'.join(_RUNNERS)} —— 接真实产品请用 chain。")
    role = node.get("role", "solo")
    if role not in _ROLES:
        raise SettingsError(
            f"{where}（{impl_id}）的 role 是「{role}」，"
            f"只认 {'、'.join(_ROLES)}")

    endpoint, probe_api = node.get("endpoint"), node.get("probe_api")
    if runner in ("chain", "socket") and not endpoint:
        raise SettingsError(
            f"{where}（{impl_id}）声明了 runner={runner}，却没给 "
            f"endpoint —— 那是「产品入口地址」（host:port），"
            f"没有它观测不到任何东西。")
    if runner == "chain" and not probe_api:
        raise SettingsError(
            f"{where}（{impl_id}）声明了 runner=chain，却没给 "
            f"probe_api —— 那是产品**后面**那个记录员的控制口"
            f"（host:port）。")

    domain = node.get("domain") or default_domain
    policy = node.get("policy")
    if runner == "local":
        policy = policy or impl_id
        _require_reference(where, impl_id, policy, domain)

    version = node.get("version")
    if not version and image:
        version = _version_from_image(image)
    return ImplSpec(
        impl_id=str(impl_id),
        name=str(node.get("name") or impl_id),
        version=str(version or ""),
        role=role,
        runner=runner,
        domain=domain,
        policy=policy,
        endpoint=endpoint,
        probe_api=probe_api,
        image=image,
        notes=str(node.get("notes") or ""),
    )


def _product_of(node, default_domain: str, source: str) -> ImplSpec:
    """``product:`` 简写 —— 就是"一个要实测的真实产品"。"""
    if not isinstance(node, dict):
        raise SettingsError(
            f"{source} 的 product 应该是一组「字段: 值」"
            f"（含 endpoint / probe_api），实际是 {type(node).__name__}")
    _reject_unknown(f"{source} 的 product", node, _PRODUCT_KEYS, {})
    merged = {"id": "product", "name": "我的产品", "role": "front",
              "runner": "chain", **node}
    return _impl_of(merged, f"{source} 的 product", default_domain, source)


def parse_settings(raw: dict, source: str = "连线设置") -> Topology:
    """把一份**已经读成字典**的连线设置校验成 Topology。"""
    _reject_unknown(source, raw, _TOP_KEYS, _TOP_ALIASES)
    raw = _canonical(raw, _TOP_ALIASES)

    fmt = raw.get("format", FORMAT_VERSION)
    if isinstance(fmt, bool) or not isinstance(fmt, int):
        raise SettingsError(
            f"{source} 的 format 得是整数（当前支持 {FORMAT_VERSION}），"
            f"实际是 {fmt!r}")
    if fmt > FORMAT_VERSION:
        raise SettingsError(
            f"{source} 写的是 format: {fmt}，比本程序支持的 "
            f"{FORMAT_VERSION} 新 —— 换新版 CED 再打开这份文件。")

    domain = raw.get("domain") or "http1-framing"
    if not isinstance(domain, str) or not domain.strip():
        raise SettingsError(
            f"{source} 的 domain 得是领域名（例如 http1-framing）")

    impls: list[ImplSpec] = []
    if raw.get("product") is not None:
        impls.append(_product_of(raw["product"], domain, source))

    listed = raw.get("impls")
    if listed is not None:
        if not isinstance(listed, list):
            raise SettingsError(
                f"{source} 的 impls 应该是一个清单（每项一个产品），"
                f"实际是 {type(listed).__name__}")
        impls.extend(
            _impl_of(node, f"{source} 里第 {index} 个产品", domain, source)
            for index, node in enumerate(listed, start=1))

    if not impls:
        raise SettingsError(
            f"{source} 里一个产品都没有（impls 是空的、也没写 product）"
            f"—— 这样跑出来必然是 0 条发现。"
            f"只跑内置基准的话，把「跑法」选成「只跑内置基准」即可。")

    seen = {s.impl_id for s in impls}
    if len(seen) != len(impls):
        raise SettingsError(f"{source} 里有两个产品用了同一个 id —— 请改掉重名")

    chain = raw.get("chain")
    if chain is not None:
        if not isinstance(chain, (list, tuple)) or len(chain) != 2:
            raise SettingsError(
                f"{source} 的 chain 要写成两个 id（[前置, 后端]），"
                f"例如 chain: [customer-gateway, ref-cl-first]")
        unknown = [i for i in chain if i not in seen]
        if unknown:
            raise SettingsError(
                f"{source} 的 chain 引用了没定义的产品："
                f"{'、'.join(map(str, unknown))}")
        chain = (str(chain[0]), str(chain[1]))

    return Topology(domain=domain, impls=impls, chain=chain)


_SPEC_ORDER = ("id", "name", "version", "role", "runner", "domain",
               "policy", "endpoint", "probe_api", "image", "notes")
#: product 简写能写的字段（runner/role/domain 是给它隐含定死的）
_PRODUCT_OUT = ("id", "name", "version", "policy", "endpoint",
                "probe_api", "image", "notes")


def _spec_value(spec, key):
    """ImplSpec 的 id 字段叫 impl_id —— 对外写出来是 id。"""
    return spec.impl_id if key == "id" else getattr(spec, key, None)


def _spec_dict(spec) -> dict:
    out = {}
    for key in _SPEC_ORDER:
        value = _spec_value(spec, key)
        if value not in (None, "", []):
            out[key] = value
    return out


def to_settings(topo: Topology) -> dict:
    """把 Topology 写回**新版**连线设置（导出用）。

    实测产品写成 ``product:`` 简写、其余内置参照实现放进 ``impls`` ——
    这样导出再导入是等价的，而且不会把简写又变回一长串字段。

    没有实测产品时（只跑内置基准）就只给 ``impls``：导出的文件再读回来
    仍然是"只跑内置基准"，而不是被误当成"接产品"。
    """
    product, rest = None, []
    for spec in topo.impls:
        if product is None and spec.runner in ("chain", "socket"):
            product = {key: _spec_value(spec, key) for key in _PRODUCT_OUT
                       if _spec_value(spec, key) not in (None, "")}
        else:
            rest.append(_spec_dict(spec))
    out: dict = {"format": FORMAT_VERSION, "domain": topo.domain}
    if product is not None:
        out["product"] = product
    if rest:
        out["impls"] = rest
    if topo.chain:
        out["chain"] = list(topo.chain)
    return out


def load(path: str | Path, source: str | None = None) -> Topology:
    """读一个连线设置文件（.json / .yaml）。"""
    p = Path(path)
    if not p.is_file():
        raise SettingsError(f"找不到连线设置文件：{p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SettingsError(f"读不了连线设置文件 {p}：{exc}") from exc
    return parse_settings(
        _parse_text(text, p.suffix.lower(), source or str(p)),
        source=source or str(p))


def from_text(text: str, *, suffix: str = ".json",
              source: str = "连线设置") -> Topology:
    """把界面上传上来的一段**文本**读成 Topology（导入连线设置用）。

    ``suffix`` 决定按 JSON 还是 YAML 解析；本机没装 PyYAML 时选 YAML 会得到
    一句人话，而不是看不懂的 JSONDecodeError。
    """
    return parse_settings(_parse_text(text, suffix, source), source=source)


# ----------------------------------------------------------------- 组装

def demo(domain: str = "http1-framing") -> Topology:
    """内置基准：**某个领域**的全部参照实现（两侧都是离线模型账）。"""
    return with_baseline(Topology(domain=domain), domain=domain)


def with_baseline(topo: Topology, domain: str | None = None) -> Topology:
    """把内置参照实现补成 B 侧（离线基准），A 侧（产品）原样保留。

    接真实产品时，拿它跟一整排内置参照实现逐对比 —— 这就是
    "A 侧实测、B 侧离线"那句话的实现。
    """
    from ..impls import axis_pairs, local_specs

    domain = domain or topo.domain
    known = {s.impl_id for s in topo.impls}
    extra = [s for s in local_specs(domain) if s.impl_id not in known]
    impls = list(topo.impls) + extra

    chain = topo.chain
    if chain is None and impls:
        pairs = axis_pairs(domain)
        chain = next(iter(pairs.values()), None)
        if chain is None and len(impls) > 1:
            chain = (impls[0].impl_id, impls[1].impl_id)
    return Topology(domain=domain, impls=impls, chain=chain)


def build(settings: dict | None, *, domain: str) -> Topology:
    """把界面上的「连线设置」变成一次扫描的拓扑。

    ``settings`` 为空 = 只跑内置基准；给了 = 接我的产品（A 侧实测）
    + 内置基准（B 侧离线）。
    """
    if not settings:
        return demo(domain)
    topo = parse_settings(settings, source="连线设置")
    if topo.domain != domain:
        raise SettingsError(
            f"连线设置里写的领域是「{topo.domain}」，界面上选的是"
            f"「{domain}」—— 两边得是同一个领域，否则比的是两回事。")
    return with_baseline(topo, domain=domain)


# ----------------------------------------------------------------- 探针身份

def check_probes(topo: Topology, *, timeout: float = 3.0) -> list[str]:
    """起任务前核对每个「记录员」自报的身份（领域 + 读法）。

    返回**提示语**（例如"无法校验"）；**领域对不上直接抛**
    :class:`SettingsError` —— 记录员和这次要跑的领域不是一回事，
    整轮数字都没有意义，必须当场拦住，而不是跑完给一份看着正常的报告。
    """
    from ..contracts import parse_addr
    from ..probe.chain import ChainEvaluator
    from ..probe.evaluator import DEFAULT_API_PORT

    notes: list[str] = []
    for spec in topo.impls:
        if spec.runner != "chain" or not spec.endpoint:
            continue
        probe_api = spec.probe_api or (
            f"{parse_addr(spec.endpoint)[0]}:{DEFAULT_API_PORT}")
        who = spec.name or spec.impl_id
        ident = ChainEvaluator(spec.endpoint, probe_api).identity(
            timeout=timeout)
        if ident is None:
            notes.append(
                f"无法校验「{who}」后面那个记录员（{probe_api}）的身份："
                f"它没回应，或者是旧版探针。这不妨碍开跑，但领域对不上时"
                f"没人会拦你。")
            continue
        reported = str(ident.get("domain") or "")
        if not reported:
            notes.append(
                f"无法校验「{who}」后面那个记录员（{probe_api}）的身份："
                f"它是旧版探针，只回了一句 ok。")
            continue
        if reported != spec.domain:
            raise SettingsError(
                f"记录员（{probe_api}）自报的领域是「{reported}」，"
                f"而这次要跑的是「{spec.domain}」—— 两者不是一回事，"
                f"跑出来的数字没有意义。请用 --domain {spec.domain} "
                f"重启那个记录员（探针）。")
        said_policy = str(ident.get("policy") or "")
        notes.append(
            f"记录员（{probe_api}）身份已核对：领域 {reported}、"
            f"读法 {said_policy or '未自报'}")
        if spec.policy and said_policy and said_policy != spec.policy:
            notes.append(
                f"注意：连线设置里把「{who}」的记录员读法写成「{spec.policy}」，"
                f"但它自报的是「{said_policy}」—— 读法不一致，数字会挂着不对的名字。")
    return notes


def check_link(settings: dict, *, domain: str) -> dict:
    """界面上的「检查连通性」：问身份 → 清记录 → 试发一条。

    不接真实产品（只跑内置基准）时没有可检查的东西 —— 直接说清楚，
    而不是给一盏绿灯让人误以为"链路没问题"。
    """
    from ..contracts import parse_addr
    from ..probe.chain import ChainEvaluator
    from ..probe.evaluator import DEFAULT_API_PORT

    if not settings:
        raise SettingsError(
            "这次是「只跑内置基准」，没有真实链路可检查 —— "
            "内置基准全在进程内跑，不需要连任何东西。")

    topo = build(settings, domain=domain)
    spec = next((s for s in topo.impls if s.runner == "chain"), None)
    if spec is None or not spec.endpoint:
        raise SettingsError(
            "连线设置里没有写「接产品」的入口地址（endpoint）—— "
            "请先填产品入口地址和记录员地址。")
    probe_api = spec.probe_api or (
        f"{parse_addr(spec.endpoint)[0]}:{DEFAULT_API_PORT}")
    report = ChainEvaluator(spec.endpoint, probe_api).self_check(
        domain, spec.policy or "")
    report["product"] = {"name": spec.name or spec.impl_id,
                         "endpoint": spec.endpoint, "probe_api": probe_api,
                         "policy": spec.policy or ""}
    report["domain"] = domain
    return report


__all__ = ["FORMAT_VERSION", "SettingsError", "Topology", "build",
           "check_link", "check_probes", "demo", "from_text", "load",
           "parse_settings", "to_settings", "with_baseline"]
