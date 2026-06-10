from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
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
        self.last_request_at = 0.0

        rate_limit = config.get("rate_limit", provider.get("rate_limit", {}))
        self.delay_seconds = float(rate_limit.get("delay_seconds", 0.0))
        self.retry_on_429 = bool(rate_limit.get("retry_on_429", True))
        self.retry_times = int(rate_limit.get("retry_times", 0))
        self.retry_delay_seconds = float(rate_limit.get("retry_delay_seconds", 15.0))

        api_key_env = str(provider.get("api_key_env", ""))
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.auth_header = str(provider.get("auth_header", "Authorization"))
        self.api_key_prefix = str(provider.get("api_key_prefix", "Bearer "))
        self.extra_headers = {str(key): str(value) for key, value in dict(provider.get("headers", {})).items()}

        if provider_name not in {"openai_compatible", "openai-compatible", "chat_completions"}:
            raise ValueError("AI provider chỉ hỗ trợ openai_compatible")
        if not self.base_url:
            raise ValueError("Thiếu provider.base_url trong ai.config.example.json")
        if not self.model:
            raise ValueError("Thiếu provider.model trong ai.config.example.json")
        if api_key_env and not self.api_key:
            raise ValueError(f"Thiếu API key. Hãy đặt {api_key_env} trong .env")

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
        attempts = max(1, self.retry_times + 1)
        for attempt in range(1, attempts + 1):
            self._wait_before_call()
            request = Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=self._headers(),
                method="POST",
            )

            try:
                with urlopen(request, timeout=self.timeout) as response:
                    raw_text = response.read().decode("utf-8", errors="replace")
                return json.loads(raw_text)
            except HTTPError as error:
                if self._should_retry_429(error, attempt, attempts):
                    self._wait_after_429(error)
                    continue
                raise RuntimeError(self._http_error_text(error)) from error

        raise RuntimeError("AI request failed after retries")

    def _wait_before_call(self) -> None:
        if self.delay_seconds <= 0:
            return

        elapsed = time.perf_counter() - self.last_request_at
        wait_seconds = self.delay_seconds - elapsed
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        self.last_request_at = time.perf_counter()

    def _should_retry_429(self, error: HTTPError, attempt: int, attempts: int) -> bool:
        return self.retry_on_429 and error.code == 429 and attempt < attempts

    def _wait_after_429(self, error: HTTPError) -> None:
        retry_after = error.headers.get("Retry-After")
        wait_seconds = self.retry_delay_seconds
        if retry_after:
            try:
                wait_seconds = max(wait_seconds, float(retry_after))
            except ValueError:
                pass
        if wait_seconds > 0:
            time.sleep(wait_seconds)

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
