"""网页「设置」面板的持久化配置。

一个 JSON 文件（默认仓库根下的 ``ced-settings.json``，已在 .gitignore 里挡住），三个界面：

    load()          当前配置（已与默认值合并）
    save(patch)     深合并写入；**未知键直接拒绝**（拼错了要报人话，不许静默忽略）
    apply_llm_env() 把模型配置写进环境变量，复用既有的 ``CED_LLM_*`` 读取路径

为什么要有这个文件：演示与评审时是在网页上点着改的（不会有人去设环境变量），
而密钥既要能持久化、**又绝不能进仓库** —— 所以落在仓库根、由 .gitignore 挡住，
``public_view()`` 对外只给掩码形式，从不回显明文。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

#: 配置文件位置（仓库根；同目录的 .gitignore 已挡住它）
SETTINGS_PATH = Path(__file__).resolve().parents[1] / "ced-settings.json"

#: 允许的键与默认值 —— 白名单，别的一律拒绝
DEFAULTS: dict = {
    "llm": {
        "base_url": "",          # OpenAI 兼容端点，如 http://127.0.0.1:8000/v1
        "model": "",
        "api_key": "",
        "timeout": 60.0,
        "temperature": 0.3,
        "max_tokens": 32768,     # 推理模型的思考也计入 max_tokens，给小了会只剩空 content
    },
    "capture": {
        "port": 18081,           # 自动捕获代理端口（别用 8080：Windows 常保留该端口）
        "jsonl": "",             # 留空 = 只保留内存记录
        "analyze_all": False,    # 连静态资源也分析
        "domains": [],           # 空 = 全部 5 个领域
    },
    "scan": {
        "domain": "http1-framing",
        "mode": "axis",
        "limit": 60,
        "seed": 42,
        #: 扫描前是否先向模型要一批新提案 —— 在设置里定死，省得每次开页重勾
        "use_llm": False,
    },
    "paths": {
        "poc_dir": "results/pocs",
        "report_dir": "results",
    },
}

_TYPES = {
    "llm": {"base_url": str, "model": str, "api_key": str, "timeout": float,
            "temperature": float, "max_tokens": int},
    "capture": {"port": int, "jsonl": str, "analyze_all": bool, "domains": list},
    "scan": {"domain": str, "mode": str, "limit": int, "seed": int,
             "use_llm": bool},
    "paths": {"poc_dir": str, "report_dir": str},
}


def _deep_merge(base: dict, patch: dict) -> dict:
    out = {key: dict(value) if isinstance(value, dict) else value
           for key, value in base.items()}
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _validate(patch: dict) -> None:
    """白名单 + 类型检查。拼错/写错都要当场报人话，不许静默忽略。"""
    if not isinstance(patch, dict):
        raise ValueError("设置必须是一个对象")
    for section, values in patch.items():
        if section not in DEFAULTS:
            raise ValueError(f"未知设置分组 {section!r}（可选：{', '.join(DEFAULTS)}）")
        if not isinstance(values, dict):
            raise ValueError(f"{section} 必须是一个对象")
        for key, value in values.items():
            if key not in DEFAULTS[section]:
                raise ValueError(
                    f"未知设置项 {section}.{key}（可选：{', '.join(DEFAULTS[section])}）")
            want = _TYPES[section][key]
            if want is float and isinstance(value, int):
                continue                       # int 可以当 float 用
            if want is int and isinstance(value, bool):
                raise ValueError(f"{section}.{key} 需要整数")
            if not isinstance(value, want):
                raise ValueError(
                    f"{section}.{key} 需要 {want.__name__}，收到 {type(value).__name__}")


def load() -> dict:
    if not SETTINGS_PATH.exists():
        return _deep_merge(DEFAULTS, {})
    try:
        stored = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _deep_merge(DEFAULTS, {})       # 文件坏了就退回默认，别让控制台起不来
    if not isinstance(stored, dict):
        return _deep_merge(DEFAULTS, {})
    return _deep_merge(DEFAULTS, stored)


def save(patch: dict) -> dict:
    _validate(patch)
    merged = _deep_merge(load(), patch)
    SETTINGS_PATH.write_text(json.dumps(merged, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    apply_llm_env(merged)
    return merged


def public_view(config: dict | None = None) -> dict:
    """给网页看的形态：密钥只给掩码，从不回显明文。"""
    view = _deep_merge(config if config is not None else load(), {})
    key = str(view["llm"].get("api_key") or "")
    view["llm"]["api_key"] = "" if not key else ("*" * 6 + key[-4:])
    view["llm"]["api_key_set"] = bool(key)
    view["path"] = str(SETTINGS_PATH)
    return view


def apply_llm_env(config: dict | None = None) -> None:
    """把模型配置写进环境变量 —— 复用既有的 ``CED_LLM_*`` 读取路径，不动调用方。"""
    llm = (config or load())["llm"]
    mapping = {"base_url": "CED_LLM_BASE_URL", "model": "CED_LLM_MODEL",
               "api_key": "CED_LLM_API_KEY", "timeout": "CED_LLM_TIMEOUT",
               "temperature": "CED_LLM_TEMPERATURE", "max_tokens": "CED_LLM_MAX_TOKENS"}
    for key, env_name in mapping.items():
        value = llm.get(key)
        if value in (None, ""):
            continue                           # 留空 = 不动现有环境变量
        os.environ[env_name] = str(value)


__all__ = ["SETTINGS_PATH", "DEFAULTS", "load", "save", "public_view", "apply_llm_env"]
