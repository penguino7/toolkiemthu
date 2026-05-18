from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": {
        "name": "offline",
        "base_url": "http://127.0.0.1:11434",
        "model": "llama3.1:8b",
        "api_key_env": "",
        "timeout_seconds": 60,
        "temperature": 0.1,
    },
    "analysis": {
        "language": "vi",
        "max_findings": 50,
        "max_payload_chars": 500,
        "max_detail_chars": 1200,
    },
    "redaction": {
        "enabled": True,
        "sensitive_keys": [
            "authorization",
            "cookie",
            "set-cookie",
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
        ],
    },
    "output_dir": "ai-output",
}


class AiConfigLoader:
    """Đọc config AI và merge với giá trị mặc định."""

    def __init__(self, defaults: Dict[str, Any] | None = None) -> None:
        self.defaults = deepcopy(defaults or DEFAULT_CONFIG)

    def load(self, path: str | None) -> Dict[str, Any]:
        config = deepcopy(self.defaults)
        if not path:
            return config

        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return self.deep_merge(config, data)

    def deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(base)
        for key, value in override.items():
            base_value = result.get(key)
            if isinstance(value, dict) and isinstance(base_value, dict):
                result[key] = self.deep_merge(base_value, value)
            else:
                result[key] = value
        return result
