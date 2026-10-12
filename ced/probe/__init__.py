"""探针层：把"实现"或"前置+探针链路"包成可被差分调用的观测源。

三种观测方式：
  local  —— 进程内直接跑参照实现（快、确定性，用于内部基准）
  socket —— 直连探针，观测某处收到的字节
  chain  —— 真实前置 → 探针，观测"前置转发出去的字节"

服务端**收全就处理，绝不空等**，三条路径按优先级：

1. 客户端半关闭写端 → 读到 EOF 立刻处理（替身前置会透传这个半关闭）；
2. **按 HTTP 消息边界判断收全**（有 ``Content-Length``、没有 ``Transfer-Encoding``）→
   到边界就处理。真实 nginx 不对上游半关闭，没有这一条就得每条白等
   ``IDLE_TIMEOUT``（5 秒），一轮 60 条就是五分钟；
3. 判不出来（分块体 / CL+TE 冲突 / 畸形 CL）→ 回落 EOF / 空闲超时，**不猜边界、不合成视角**。

**真实 nginx 吃不下客户端半关闭**（本机实测：它既不转发也不回响应），所以链路器
先试半关闭、失败再换普通客户端模式；失败类型见 ``ced.contracts`` 的
``ProbeRejected`` / ``ProbeUnreachable``。
"""
from .chain import ChainEvaluator
from .evaluator import Evaluator, LocalEvaluator, SocketEvaluator

__all__ = ["Evaluator", "LocalEvaluator", "SocketEvaluator", "ChainEvaluator"]
