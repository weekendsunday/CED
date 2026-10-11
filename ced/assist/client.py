"""OpenAI 兼容 HTTP 客户端（只用 urllib，零第三方依赖）。

整个包里**唯一**发起网络请求的地方就是这里。没有配置模型时 ``available`` 为
False，``chat`` 抛 ``LlmUnavailable`` —— 调用方据此降级（不挂解读栏），
绝不让"模型没配好"打断检测。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class LlmConfig:
    """模型接入配置。``base_url`` 要含版本段（如 ``https://api.deepseek.com/v1``）。"""

    base_url: str = ""
    model: str = ""
    api_key: str = ""
    timeout: float = 60.0
    temperature: float = 0.3
    #: 上限要留给推理模型的思考 —— 思考同样计入这个额度，给小了 content 会是空的
    max_tokens: int = 32768

    @property
    def ready(self) -> bool:
        return bool(self.base_url and self.model)


class LlmUnavailable(RuntimeError):
    """模型不可用或调用失败 —— 调用方必须能据此降级，而不是把异常抛给扫描主流程。"""


def config_from_env(env: Mapping[str, str] | None = None) -> LlmConfig:
    """从环境变量读配置；数值项解析失败一律回退默认值（配置错不该崩）。"""
    env = os.environ if env is None else env
    return LlmConfig(
        base_url=_get(env, "CED_LLM_BASE_URL"),
        model=_get(env, "CED_LLM_MODEL"),
        api_key=_get(env, "CED_LLM_API_KEY"),
        timeout=_as_float(_get(env, "CED_LLM_TIMEOUT"), 60.0),
        temperature=_as_float(_get(env, "CED_LLM_TEMPERATURE"), 0.3),
        max_tokens=_as_int(_get(env, "CED_LLM_MAX_TOKENS"), 32768),
    )


def _get(env: Mapping[str, str], key: str) -> str:
    value = env.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _as_float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class LlmClient:
    """极薄的 /chat/completions 客户端。"""

    def __init__(self, config: LlmConfig) -> None:
        self.config = config

    @property
    def available(self) -> bool:
        return self.config.ready

    @property
    def url(self) -> str:
        return self.config.base_url.rstrip("/") + "/chat/completions"

    def chat(self, messages: list[dict], *, temperature: float | None = None,
             max_tokens: int | None = None) -> str:
        """发一轮对话，返回 assistant 文本。任何异常都包成 ``LlmUnavailable``。"""
        if not self.available:
            raise LlmUnavailable("未配置模型（CED_LLM_BASE_URL / CED_LLM_MODEL）")

        body = {
            "model": self.config.model,
            "messages": messages,
            "temperature": (self.config.temperature if temperature is None
                            else temperature),
            "max_tokens": (self.config.max_tokens if max_tokens is None
                           else max_tokens),
        }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except Exception:                        # 读失败不影响"不可用"这个结论
                detail = ""
            raise LlmUnavailable(f"模型返回 HTTP {exc.code}：{detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise LlmUnavailable(f"模型不可达：{exc}") from exc

        try:
            obj = json.loads(raw.decode("utf-8"))
            content = obj["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LlmUnavailable(f"模型响应结构不符：{raw[:200]!r}") from exc
        if not isinstance(content, str):
            raise LlmUnavailable(f"模型 content 不是字符串：{type(content).__name__}")
        return content
