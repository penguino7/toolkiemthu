from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


@dataclass
class ChatMessage:
    role: str
    content: str


class AiApiClient:
    """Client gọi API tương thích OpenAI /chat/completions."""

    def __init__(self, config: dict) -> None:
        provider = config.get("provider", {})
        provider_name = str(provider.get("name", "openai_compatible")).lower()
        self.base_url = str(provider.get("base_url", "")).rstrip("/")
        self.model = str(provider.get("model", ""))
        self.timeout = int(provider.get("timeout_seconds", 60))
        self.temperature = float(provider.get("temperature", 0.1))
        self.last_usage = None

        api_key_env = str(provider.get("api_key_env", ""))
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.auth_header = str(provider.get("auth_header", "Authorization"))
        self.api_key_prefix = str(provider.get("api_key_prefix", "Bearer "))
        self.extra_headers = {str(key): str(value) for key, value in dict(provider.get("headers", {})).items()}

        if provider_name not in {"openai_compatible", "openai-compatible", "chat_completions"}:
            raise ValueError("AI client only supports provider.name=openai_compatible")
        if not self.base_url:
            raise ValueError("Missing provider.base_url in ai.config.example.json")
        if not self.model:
            raise ValueError("Missing provider.model in ai.config.example.json")
        if api_key_env and not self.api_key:
            raise ValueError(f"Missing API key. Set {api_key_env} in .env")

    def complete(self, messages: list[ChatMessage]) -> str:
        payload = {
            "model": self.model,
            "messages": [message.__dict__ for message in messages],
            "temperature": self.temperature,
        }
        data = self._post_json(f"{self.base_url}/chat/completions", payload)
        self.last_usage = data.get("usage")

        choices = data.get("choices", [])
        if not choices:
            return ""
        return str(choices[0].get("message", {}).get("content", ""))

    def _post_json(self, url: str, payload: dict) -> dict:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
        except HTTPError as error:
            raise RuntimeError(self._http_error_text(error)) from error

        return json.loads(raw_text)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ToolKiemThu/1.0",
        }
        headers.update(self.extra_headers)
        if self.api_key:
            headers[self.auth_header] = f"{self.api_key_prefix}{self.api_key}"
        return headers

    def _http_error_text(self, error: HTTPError) -> str:
        body = error.read().decode("utf-8", errors="replace").strip()
        if len(body) > 500:
            body = body[:497] + "..."

        message = f"HTTP Error {error.code}: {error.reason}"
        if body:
            message = f"{message} - {body}"
        return message
