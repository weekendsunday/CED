"""本地 CA 导入操作系统信任库 —— 控制台「一键信任」按钮的后端。

为什么要有这一层：手敲 ``security`` / ``certutil`` 命令是门槛，三个平台的命令还各不相同，
路径写错很难自查。把「平台 → 命令」的映射收在一处，界面只调两件事：**查状态**、**导入/撤销**。

三条硬规矩（都是为了让「方便」不变成「危险」）：

1. **只碰本机这一张 CA**：证书路径固定取自 :mod:`ced.capture.mitm`，
   不接受调用方传路径 —— 否则这个接口就成了「信任任意证书」的通道。
2. **不自动提权**：需要 root 的动作（Linux 系统目录、macOS 系统钥匙串）一律不 sudo，
   只走用户级入口（macOS 登录钥匙串 / Windows 当前用户证书库）；用户级也失败就把
   系统原话与手动指引交回使用者，由人自己决定要不要用管理员身份重来。
3. **不假报成功**：依赖缺失 / 证书没生成 / 平台没有一键入口 / 命令非零退出，
   一律 ``ok=False`` 并带上真正的失败原因（stderr 原文），绝不出现"看起来成功了"。

macOS 的用户级导入会弹一次钥匙串密码框（系统行为，不是我们的弹窗），
所以命令给了较长超时 —— 人在机器前点一下就过。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import mitm

#: 归一化的平台名。测试直接改这个常量覆盖三个平台的分支，不去碰真的信任库。
PLATFORM = ("darwin" if sys.platform.startswith("darwin")
            else "win32" if sys.platform.startswith("win")
            else "linux" if sys.platform.startswith("linux")
            else sys.platform)

#: 用户级钥匙串 —— 系统域要 sudo，按规矩 2 不碰
MAC_USER_KEYCHAIN = Path.home() / "Library/Keychains/login.keychain-db"
#: Linux 手动导入的落点（一键入口不做：那一步必然要管理员权限）
LINUX_DROP_IN = "/usr/local/share/ca-certificates/ced-capture.crt"
#: 等系统弹框的时长（秒）—— 钥匙串密码框由人来点，别几秒就放弃
TIMEOUT = 180.0


def plan(undo: bool = False) -> list[str] | None:
    """把动作翻成本平台的命令。返回 None = 该平台没有一键入口（要管理员权限）。

    只返回 argv、不执行 —— 拆出来就是为了能测：测的是「到底会敲哪条命令」，
    而不是让用例真的去改本机信任库。
    """
    ca = str(mitm.CA_CERT)
    if PLATFORM == "darwin":
        if undo:
            return ["security", "delete-certificate", "-c", mitm.ca_common_name(),
                    str(MAC_USER_KEYCHAIN)]
        # -p ssl 只对 TLS 策略授信（不做全局根，影响面越小越好）；
        # -k 落用户钥匙串，所以不需要 sudo。
        return ["security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl",
                "-k", str(MAC_USER_KEYCHAIN), ca]
    if PLATFORM == "win32":
        if undo:
            return ["certutil", "-user", "-delstore", "Root", mitm.ca_common_name()]
        return ["certutil", "-user", "-addstore", "Root", ca]   # -user：不弹 UAC
    return None


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    """落到真实进程 —— 进程边界只有这一处，方便测试替换。"""
    return subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)


def _trusted(ca: Path) -> bool | None:
    """本机信任库里认不认这张 CA。None = 查不出确定结论（不等于没信任）。

    只查不写。macOS 直读用户域信任设置（``dump-trust-settings``），**不用 verify-cert** ——
    实测踩过两个坑：① 不带 ``-p`` 时它走的不是 SSL 策略，而我们只授 SSL 策略，
    结果会误报「不受信」；② 撤销之后它仍会缓存着上次的成功结论，状态迟迟回不到「未信任」。
    直读信任设置没有这两个问题：加/删完立刻就是真话。
    Windows 查当前用户证书库，Linux 只看我们那个落点在不在、内容对不对。
    """
    try:
        if PLATFORM == "darwin":
            proc = _run(["security", "dump-trust-settings"])
            if proc.returncode != 0:            # 没有任何用户域信任设置
                return False
            # 按**证书里实际的 CN**找：导入别人的 CA 时它不叫 CED Local Capture CA
            return mitm.ca_common_name() in (proc.stdout or "")
        if PLATFORM == "win32":
            # 按 certutil 的文档语义写，但没有真机可验；就算判错也只是让界面多显示一次
            # 「信任本机 CA」，点一下是幂等的，不会造成误信任。
            argv = ["certutil", "-user", "-verifystore", "Root", mitm.ca_common_name()]
            return _run(argv).returncode == 0
        if PLATFORM == "linux":
            drop = Path(LINUX_DROP_IN)
            return drop.is_file() and drop.read_bytes() == ca.read_bytes()
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def _may_prompt() -> str:
    """点按钮之后系统会不会插一手 —— 要如实预告，否则等弹框的人会以为卡死了。"""
    if PLATFORM == "darwin":
        return "点按后若 macOS 弹出钥匙串密码框，输完即生效（不是卡住）。"
    if PLATFORM == "win32":
        return "点按后写入当前用户证书库，不需要管理员。"
    return ""


def _view(state: str, *, title: str, note: str, hint: str = "", ca: Path | None = None,
          trusted: bool | None = False, supported: bool = False,
          available: bool = True) -> dict:
    """界面要的字段集中在这里拼 —— 前端只按 ``state`` 分支，不再自己推导状态。"""
    return {
        "platform": PLATFORM,
        "state": state,
        "title": title,
        "note": note,
        "hint": hint,
        "mitm": available,
        "supported": supported,
        "ca": str(ca) if ca else None,
        #: 本机这张 CA 的名字（导入的 CA 多半不叫默认名，界面上要照实显示）
        "cn": mitm.ca_common_name() if ca else "",
        "trusted": trusted,
        #: 已签发证书的**域名数**（界面拿来显示 + 决定「清理」键能不能点）
        "leaves": mitm.count_leaves(),
    }


def status() -> dict:
    """这张 CA 现在处于什么状态。``state`` 就是界面分支的全部依据：

    ``no_dependency`` 没装可选依赖，MITM 根本不可用（HTTPS 走隧道直通）
    ``missing``       有依赖、还没生成 CA
    ``trusted``       已在本机信任库里
    ``untrusted``     本机有 CA，信任库里没有
    ``unknown``       少见路径，查不出确定结论
    ``unsupported``   平台没有一键入口（现在只剩 Linux）
    """
    available = mitm.mitm_available()
    if not available:
        return _view("no_dependency", title="不可用", available=False, supported=False,
                     note="本解释器缺可选依赖 —— HTTPS 只能 CONNECT 隧道直通，明文 HTTP 一切照旧。"
                          "装上并重启界面后即可开启解密。",
                     hint="pip install cryptography")
    supported = plan() is not None
    ca = mitm.ca_cert_path()
    if ca is None:
        return _view("missing", title="未生成", supported=supported,
                     note="还没有本地 CA。点「信任本机 CA」会按需生成 —— "
                          "私钥只落在本机 ~/.ced/mitm/，不入仓库。\n" + _may_prompt())
    trusted = _trusted(ca)
    if trusted is True:
        return _view("trusted", title="已信任", ca=ca, trusted=True, supported=supported,
                     note="HTTPS 明文会进同一条差分管线。撤销后立即退回隧道直通。")
    if not supported:
        return _view("unsupported", title="需手动导入", ca=ca, trusted=trusted,
                     note="当前平台没有一键入口（那一步必然要管理员权限），按下面的指引导入。",
                     hint=mitm.install_hint(ca, PLATFORM))
    if trusted is None:
        return _view("unknown", title="待确认", ca=ca, trusted=None, supported=True,
                     note="没查出确定的信任状态，导入一次最保险。\n" + _may_prompt())
    return _view("untrusted", title="未信任", ca=ca, trusted=False, supported=True,
                 note="浏览器不认这张 CA 时 HTTPS 会报证书错误、明文进不了管线。\n" + _may_prompt())


def apply(undo: bool = False) -> dict:
    """导入 / 撤销本机信任。返回体直接给界面用：成功带命令原文，失败带系统原话。"""
    if not mitm.mitm_available():
        return {"ok": False,
                "error": "本解释器缺可选依赖，生不出 CA 也就无从导入 —— "
                         "先 pip install cryptography 再重启界面。"}
    if undo:
        ca = mitm.ca_cert_path()
        if ca is None:
            return {"ok": False, "error": "本机还没有 CA，没有可撤销的东西"}
    else:
        try:
            ca = mitm.ensure_ca()          # 没生成过就按需生成：按钮不该只对老用户可用
        except Exception as exc:            # 生成失败的原因要原样带给用户
            return {"ok": False, "error": f"生成本地 CA 失败：{exc}"}
    argv = plan(undo=undo)
    if argv is None:
        return {"ok": False, "error": "当前平台没有一键入口，请按指引手动导入",
                "hint": mitm.install_hint(ca, PLATFORM)}
    try:
        proc = _run(argv)
    except FileNotFoundError:
        return {"ok": False, "error": f"系统里没有 {argv[0]} 命令，只能手动导入",
                "hint": mitm.install_hint(ca, PLATFORM)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "command": " ".join(argv),
                "error": "等系统确认超时（钥匙串密码框是不是没点？）—— 再点一次即可",
                "hint": mitm.install_hint(ca, PLATFORM)}
    if proc.returncode != 0:
        return {"ok": False, "command": " ".join(argv),
                "error": ((proc.stderr or "").strip() or (proc.stdout or "").strip()
                          or f"{argv[0]} 退出码 {proc.returncode}"),
                "hint": mitm.install_hint(ca, PLATFORM)}
    return {"ok": True, "action": "undo" if undo else "trust",
            "command": " ".join(argv),
            "detail": (proc.stdout or "").strip() or (proc.stderr or "").strip()}
