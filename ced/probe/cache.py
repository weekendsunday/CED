"""观测缓存：一次运行内按「实现 + 同一条字节」复用观测。

一次扫描里同一对「实现 + 字节」会被反复求值：同一个用例要在多个对照对里出现，
消融实验与最小化又会在同一个用例上重放同一批候选。真实链路下每一次求值都是
一次真实的网络动作（先 reset 视角 → 发字节 → 取新视角），重复求值就是纯浪费 ——
接真实产品时这是"十几分钟"里最大的一块。

**必须每次运行新建、跑完就丢**，不能挂在长驻对象上：

  * 真实链路的观测是**有状态的动作**（每次都先 ``POST /reset`` 清空视角再发），
    跨运行复用等于把上一次的视角当成这一次的 —— 那是在合成观测；
  * 挂在被 ``lru_cache`` 复用的 Evaluator（流量接入那条路）上，
    内存还会随运行次数一路涨。

缓存只存**成功观测**与**前置拒绝**（同一次运行内这两者都是确定的结论）；
链路故障（``ProbeUnreachable``）一律不缓存 —— 它必须每次都如实暴露出来，
否则一次偶发抖动会被缓存成"这一整轮都这样"。
"""
from __future__ import annotations

from ..contracts import Observation, ProbeRejected


class CachedObservations:
    """把任意观测源包成"同实现、同字节只算一次"。"""

    def __init__(self, evaluate) -> None:
        self._evaluate = evaluate
        self._hits = 0
        self._trips = 0
        self._views: dict[tuple[str, bytes], Observation] = {}
        self._rejected: dict[tuple[str, bytes], str] = {}

    def __call__(self, impl_id: str, payload: bytes) -> Observation:
        key = (impl_id, payload)
        rejected = self._rejected.get(key)
        if rejected is not None:
            self._hits += 1
            raise ProbeRejected(rejected)
        cached = self._views.get(key)
        if cached is not None:
            self._hits += 1
            return cached

        self._trips += 1
        try:
            obs = self._evaluate(impl_id, payload)
        except ProbeRejected as exc:
            self._rejected[key] = str(exc)
            raise
        self._views[key] = obs
        return obs

    def stats(self) -> dict:
        """真实动作跑了几次、省了几次 —— 前端与测试用它证明缓存真的生效。"""
        return {"hits": self._hits, "trips": self._trips,
                "cached": len(self._views) + len(self._rejected)}


__all__ = ["CachedObservations"]
