from __future__ import annotations

from typing import Any


class DataRedactor:
    """Ẩn bớt dữ liệu nhạy cảm trước khi gửi sang AI provider."""

    def __init__(self, config: dict) -> None:
        redaction = config.get("redaction", {})
        self.enabled = bool(redaction.get("enabled", True))
        self.sensitive_keys = {str(key).lower() for key in redaction.get("sensitive_keys", [])}

    def redact(self, value: Any) -> Any:
        if not self.enabled:
            return value

        if isinstance(value, dict):
            return self._redact_dict(value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value

    def _redact_dict(self, data: dict) -> dict:
        output = {}
        for key, value in data.items():
            key_text = str(key)
            if self._is_sensitive_key(key_text):
                output[key_text] = "[REDACTED]"
            else:
                output[key_text] = self.redact(value)
        return output

    def _is_sensitive_key(self, key: str) -> bool:
        lowered = key.lower()
        return any(token in lowered for token in self.sensitive_keys)


def trim_text(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", "").replace("\n", "\\n")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."

