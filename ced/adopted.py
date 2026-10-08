"""固化语料：把审过的模型提案写进仓库，下次扫描直接用，不再调模型。

模型提案默认只活一轮 —— 提出来、过两道门槛、进当次语料，然后只剩台账里一行记录。
想让它下次还起作用，就得**重新调一次模型**（再花时间、再花钱），哪怕它上次已经
逼出过真实的结构分歧。这个模块补的就是这一步：

    python -m ced adopt                         看台账里哪些提案够格（命中过的）
    python -m ced adopt --add cl_obs_fold       采纳进仓库文件
    python -m ced adopt --drop cl_obs_fold      从仓库文件里撤下

落地在 ``ced/cases/adopted/<domain>.json`` —— **进 git**，所以换机器、别人克隆都带着。

三条口径，缺一条这个设计就不成立：

  * **不是新来源**：固化的是同一条模型提案（同一个 payload → 同一个 proposal_id），
    所以台账里仍然记 ``origin=llm``、仍然带着它当初的 rationale 与模型名；
  * **不绕门槛**：加载后照样重跑差分 oracle 准入实验，没逼出分歧的就地丢弃 ——
    "只有过了准入的才进语料"这条不变式依然是字面成立的。固化省的是模型调用，
    不是门槛；
  * **只进不出人手**：只有 ``--add`` 写得进来，代码绝不自动采纳。写进这个文件等于
    把它当内置语料看，得有人认账。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from . import artifacts
from .contracts import ORIGIN_LLM, Proposal

#: 固化语料目录（进 git；文件名 = 领域名 + .json）
ADOPTED_DIR = Path(__file__).resolve().parent / "cases" / "adopted"

#: 文件里的说明，随文件一起进仓库 —— 别人看到这份数据要知道它是怎么来的
FILE_NOTE = ("从模型提案里人工采纳的语料（见 python -m ced adopt）。"
             "每次扫描都会带上并重新过一遍准入实验，不再调用模型。")


@dataclass(frozen=True)
class AdoptedCase:
    """一条固化下来的模型提案。来源信息一并留着，好让报告说得清"这是谁猜的"。"""

    axis: str
    payload: bytes
    model: str = ""
    rationale: str = ""
    hit_fields: tuple[str, ...] = ()
    adopted_at: str = ""
    note: str = ""

    def to_proposal(self) -> Proposal:
        """变回一条提案 —— 与当场从模型拿到的那条走完全相同的管线。

        ``origin`` 仍是 ``llm``：它本来就是模型提出的，固化只改变了"怎么拿到它"，
        没改变"它是谁"。台账与报告因此不必多认一种来源。
        """
        return Proposal(axis=self.axis, payload=self.payload, origin=ORIGIN_LLM,
                        rationale=self.rationale, model=self.model)

    def to_json(self) -> dict:
        return {"axis": self.axis,
                "payload_b64": base64.b64encode(self.payload).decode("ascii"),
                "adopted_from": self.model, "adopted_at": self.adopted_at,
                "hit_fields": list(self.hit_fields), "rationale": self.rationale,
                "note": self.note}


def path_of(domain: str) -> Path:
    return ADOPTED_DIR / f"{domain}.json"


def load(domain: str) -> list[AdoptedCase]:
    """读一个领域的固化语料。没有文件就是空列表（这是常态 —— 没采纳过）。"""
    path = path_of(domain)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"固化语料读不了：{path}（{exc}）") from exc
    return _parse(raw, path)


def listing(domain: str) -> list[dict]:
    """给 CLI 看的形态：一行一条，不带字节（只报长度）。"""
    return [{"axis": c.axis, "model": c.model, "adopted_at": c.adopted_at,
             "hit_fields": list(c.hit_fields), "bytes": len(c.payload),
             "rationale": c.rationale, "note": c.note}
            for c in load(domain)]


def candidates(conn) -> list[dict]:
    """台账里**够格被采纳**的提案：模型提的、且真的逼出过分歧。

    台账没有领域列，所以这里不按领域过滤 —— 跨领域的旧条目会在准入实验里被当前
    领域的对照自然筛掉，不必在这里拦（拦了反而要维护一份领域映射）。
    """
    rows = conn.execute(
        "SELECT proposal_id, axis, model, rationale, payload, hit_fields, ts"
        " FROM proposal WHERE origin = 'llm' AND admitted = 1"
        " ORDER BY ts").fetchall()
    return [{"proposal_id": r[0], "axis": r[1], "model": r[2] or "",
             "rationale": r[3] or "", "payload": bytes(r[4]),
             "hit_fields": json.loads(r[5] or "[]")} for r in rows]


def adopt(conn, domain: str, axes: list[str]) -> tuple[list[str], list[str], list[str]]:
    """把台账里这些轴（命中过的那些 payload）写进固化文件。

    幂等：已经在文件里的不再写一遍。返回 ``(新采纳, 本来就有, 台账里找不到)``。
    """
    known = load(domain)
    have = {base64.b64encode(c.payload).decode("ascii") for c in known}
    picked = {c.axis for c in known}
    found: dict[str, list[dict]] = {}
    for row in candidates(conn):
        found.setdefault(row["axis"], []).append(row)

    added: list[str] = []
    existing: list[str] = []
    missing: list[str] = []
    out = list(known)
    for axis in axes:
        rows = found.get(axis)
        if not rows:
            missing.append(axis)
            continue
        if axis in picked:
            existing.append(axis)
            continue
        for row in rows:
            blob = base64.b64encode(row["payload"]).decode("ascii")
            if blob in have:
                continue
            have.add(blob)
            out.append(AdoptedCase(
                axis=row["axis"], payload=row["payload"], model=row["model"],
                rationale=row["rationale"], hit_fields=tuple(row["hit_fields"]),
                adopted_at=date.today().isoformat()))
        picked.add(axis)
        added.append(axis)
    if added:
        _write(domain, out)
    return added, existing, missing


def drop(domain: str, axes: list[str]) -> tuple[list[str], list[str]]:
    """从固化文件里撤掉这些轴。返回 ``(撤掉的, 不在文件里的)``。"""
    want = set(axes)
    kept = [c for c in load(domain) if c.axis not in want]
    gone = sorted({c.axis for c in load(domain) if c.axis in want})
    if gone:
        _write(domain, kept)
    return gone, sorted(want - set(gone))


# --------------------------------------------------------------------- 读写

def _write(domain: str, cases: list[AdoptedCase]) -> None:
    path = path_of(domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"domain": domain, "note": FILE_NOTE,
            "adopted": [c.to_json() for c in cases]}
    artifacts.write_text(path, json.dumps(body, ensure_ascii=False, indent=2) + "\n")


def _parse(raw: object, path: Path) -> list[AdoptedCase]:
    """严格解析：写进仓库的东西不许悄悄降级，坏了就报人话（名字带行内位置）。"""
    if not isinstance(raw, dict) or not isinstance(raw.get("adopted"), list):
        raise ValueError(f"固化语料格式不对：{path}（顶层要有 adopted 数组）")
    out: list[AdoptedCase] = []
    seen: set[str] = set()
    for i, item in enumerate(raw["adopted"], start=1):
        where = f"{path} 第 {i} 条"
        if not isinstance(item, dict):
            raise ValueError(f"{where}不是对象：{type(item).__name__}")
        axis = item.get("axis")
        if not isinstance(axis, str) or not axis:
            raise ValueError(f"{where}缺 axis")
        blob = item.get("payload_b64")
        if not isinstance(blob, str) or not blob:
            raise ValueError(f"{where}（{axis}）缺 payload_b64")
        try:
            payload = base64.b64decode(blob, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{where}（{axis}）的 payload_b64 不是合法 base64") from exc
        if not payload:
            raise ValueError(f"{where}（{axis}）的 payload 是空的")
        key = base64.b64encode(payload).decode("ascii")
        if key in seen:                      # 同一条写两遍没有意义，静默去重
            continue
        seen.add(key)
        fields = item.get("hit_fields") or []
        out.append(AdoptedCase(
            axis=axis, payload=payload, model=_str(item.get("adopted_from")),
            rationale=_str(item.get("rationale")),
            hit_fields=tuple(_str(f) for f in fields if isinstance(f, str)),
            adopted_at=_str(item.get("adopted_at")), note=_str(item.get("note"))))
    return out


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


__all__ = ["ADOPTED_DIR", "AdoptedCase", "adopt", "candidates", "drop", "listing",
           "load", "path_of"]
