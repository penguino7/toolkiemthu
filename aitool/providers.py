from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List
from urllib.error import HTTPError
from urllib.request import Request, urlopen


@dataclass
class ChatMessage:
    role: str
    content: str


class BaseProvider:
    """Interface chung cho mọi AI provider."""

    def complete(self, messages: List[ChatMessage]) -> str:
        raise NotImplementedError


class OfflineProvider(BaseProvider):
    """Provider giả lập để tool chạy được khi chưa setup API."""

    def complete(self, messages: List[ChatMessage]) -> str:
        return json.dumps(
            {
                "confirmed": False,
                "vulnerability_type": "unknown",
                "subtype": "unknown",
                "cwe": None,
                "possible_cve": None,
                "severity": "low",
                "confidence": 0.0,
                "reason_vi": "AI provider đang ở chế độ offline nên chưa phân tích bằng mô hình.",
                "false_positive_note_vi": "Đây là kết quả placeholder, không dùng làm kết luận cuối.",
                "remediation_vi": "Cấu hình provider trong ai.config.example.json để bật phân tích AI.",
            },
            ensure_ascii=False,
        )


class OllamaCompatibleProvider(BaseProvider):
    """Provider cho API kiểu Ollama /api/chat."""

    def __init__(self, config: dict) -> None:
        provider = config.get("provider", {})
        self.base_url = str(provider.get("base_url", "http://127.0.0.1:11434")).rstrip("/")
        self.model = str(provider.get("model", "llama3.1:8b"))
        self.timeout = int(provider.get("timeout_seconds", 60))
        self.temperature = float(provider.get("temperature", 0.1))

    def complete(self, messages: List[ChatMessage]) -> str:
        payload = {
            "model": self.model,
            "messages": [message.__dict__ for message in messages],
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        data = self._post_json(f"{self.base_url}/api/chat", payload)
        return str(data.get("message", {}).get("content", ""))

    def _post_json(self, url: str, payload: dict) -> dict:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))


class OpenAiCompatibleProvider(BaseProvider):
    """Provider cho API tương thích /chat/completions."""

    def __init__(self, config: dict) -> None:
        provider = config.get("provider", {})
        self.base_url = str(provider.get("base_url", "")).rstrip("/")
        self.model = str(provider.get("model", ""))
        self.timeout = int(provider.get("timeout_seconds", 60))
        self.temperature = float(provider.get("temperature", 0.1))
        self.stream = bool(provider.get("stream", False))
        self.last_usage = None
        api_key_env = str(provider.get("api_key_env", ""))
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.auth_header = str(provider.get("auth_header", "Authorization"))
        self.api_key_prefix = str(provider.get("api_key_prefix", "Bearer "))
        self.extra_headers = {
            str(key): str(value)
            for key, value in dict(provider.get("headers", {})).items()
        }

    def complete(self, messages: List[ChatMessage]) -> str:
        payload = {
            "model": self.model,
            "messages": [message.__dict__ for message in messages],
            "temperature": self.temperature,
            "stream": self.stream,
        }
        headers = self._build_headers()

        data = self._post_json(f"{self.base_url}/chat/completions", payload, headers)
        self.last_usage = data.get("usage")
        choices = data.get("choices", [])
        if not choices:
            return ""
        return str(choices[0].get("message", {}).get("content", ""))

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ToolKiemThu/1.0",
        }
        headers.update(self.extra_headers)
        if self.api_key and self.auth_header:
            headers[self.auth_header] = f"{self.api_key_prefix}{self.api_key}"
        return headers

    def _post_json(self, url: str, payload: dict, headers: Dict[str, str]) -> dict:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
        except HTTPError as error:
            error_body = error.read().decode("utf-8", errors="replace").strip()
            if len(error_body) > 500:
                error_body = error_body[:497] + "..."
            detail = f"HTTP Error {error.code}: {error.reason}"
            if error_body:
                detail = f"{detail} - {error_body}"
            raise RuntimeError(detail) from error

        if raw_text.lstrip().startswith("data:"):
            return self._parse_sse_chat_completion(raw_text)
        return json.loads(raw_text)

    def _parse_sse_chat_completion(self, raw_text: str) -> dict:
        content_parts = []
        finish_reason = None
        usage = None

        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue

            event_text = line[len("data:") :].strip()
            if not event_text or event_text == "[DONE]":
                continue

            event = json.loads(event_text)
            usage = event.get("usage") or usage
            choices = event.get("choices", [])
            if not choices:
                continue

            choice = choices[0]
            finish_reason = choice.get("finish_reason") or finish_reason
            delta = choice.get("delta", {})
            message = choice.get("message", {})
            content = delta.get("content", message.get("content", ""))
            if content:
                content_parts.append(str(content))

        return {
            "choices": [
                {
                    "index": 0,
                    "finish_reason": finish_reason,
                    "message": {
                        "role": "assistant",
                        "content": "".join(content_parts),
                    },
                }
            ],
            "usage": usage,
        }


def build_provider(config: dict) -> BaseProvider:
    provider_name = str(config.get("provider", {}).get("name", "offline")).lower()
    if provider_name == "offline":
        return OfflineProvider()
    if provider_name == "ollama":
        return OllamaCompatibleProvider(config)
    if provider_name in {"openai_compatible", "openai-compatible", "chat_completions"}:
        return OpenAiCompatibleProvider(config)
    raise ValueError(f"Unknown AI provider: {provider_name}")
