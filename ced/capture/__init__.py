"""自动捕获层：把本机跑出来的真实请求**自动**送进差分 oracle。

    python -m ced capture --port 18081

与其它入口的关系（**都在，互不替代** —— 这是「多种输入形态都纳入」的那一层）：

    ced scan       引擎自己造字节（内置语料 + 定向变异）
    ced probe      你手动给一份原始字节
    ced verify     把外部扫描器的命中（nuclei/Burp/HAR/curl/清单）当假设重跑
    ced capture    ← 本层：本机代理自动收请求，无需手动导出 / 粘贴
    ced serve      探针服务（把产品接进链路，走 chain）

边界（写在前面，免得被误解）：本层**只做本机 HTTP 代理** —— 明文 HTTP 收全，
HTTPS 默认做 `CONNECT` 隧道直通；装了可选依赖 `cryptography` 并对本机信任库
导入本地 CA 后，才把 HTTPS 解成明文进同一条管线（不做则如实计为隧道）。
全程不装驱动、不要管理员、不改系统代理设置。
"""
from .analyze import Analysis, Hit, analyze
from .proxy import CaptureProxy, Config, serve

__all__ = ["Analysis", "Hit", "analyze", "CaptureProxy", "Config", "serve"]
