from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": {
        "name": "openai_compatible",
        "base_url": "",
        "model": "",
        "api_key_env": "",
        "env_file": ".env",
        "auth_header": "Authorization",
        "api_key_prefix": "Bearer ",
        "headers": {},
        "timeout_seconds": 60,
        "temperature": 0.1,
    },
    "analysis": {
        "language": "vi",
        "max_findings": 50,
        "max_payload_chars": 500,
        "max_detail_chars": 1200,
    },
    "rate_limit": {
        "delay_seconds": 0.0,
        "retry_on_429": True,
        "retry_times": 0,
        "retry_delay_seconds": 15.0,
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
    """Đọc config AI và tự load biến môi trường từ file .env."""

    def __init__(self, defaults: Dict[str, Any] | None = None) -> None:
        self.defaults = deepcopy(defaults or DEFAULT_CONFIG)

    def load(self, path: str | None) -> Dict[str, Any]:
        config = deepcopy(self.defaults)
        if path:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            config = self.deep_merge(config, data)

        self.load_env_file(config)
        return config

    def deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(base)
        for key, value in override.items():
            base_value = result.get(key)
            if isinstance(value, dict) and isinstance(base_value, dict):
                result[key] = self.deep_merge(base_value, value)
            else:
                result[key] = value
        return result

    def load_env_file(self, config: Dict[str, Any]) -> None:
        env_file = str(config.get("provider", {}).get("env_file", ".env"))
        if not env_file:
            return

        path = Path(env_file)
        if not path.exists():
            return

        for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export ") :].strip()
            if key and key not in os.environ:
                os.environ[key] = self._parse_env_value(value)

    def _parse_env_value(self, value: str) -> str:
        parsed = value.strip()
        if len(parsed) >= 2 and parsed[0] == parsed[-1] and parsed[0] in {"'", '"'}:
            parsed = parsed[1:-1]
        return parsed
