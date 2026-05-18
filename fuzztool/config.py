from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "base_url": "http://127.0.0.1:12001",
    "headers": {"User-Agent": "FuzzTool/0.1"},
    "scope": {
        "include_hosts": ["127.0.0.1", "localhost"],
        "exclude_paths": ["/user/logout.php"],
    },
    "safety": {
        "include_post": False,
        "max_requests": 800,
        "delay_seconds": 0.05,
        "dry_run": False,
        "skip_param_names": [
            "csrf",
            "csrf_token",
            "_csrf",
            "token",
            "auth",
            "authorization",
            "password",
            "pass",
            "pwd",
            "session",
            "sid",
            "phpsessid",
        ],
    },
    "xss": {
        "enabled": False,
        "payload_mode": "proof",
        "reflected": True,
        "stored": False,
        "dom": False,
        "stored_check_paths": [],
        "dom_headless": True,
        "dom_timeout_ms": 8000,
        "post_load_wait_ms": 500,
    },
    "sqli": {
        "enabled": False,
        "error_based": True,
        "boolean_based": False,
        "time_based": False,
        "time_threshold_seconds": 2.5,
        "time_sleep_seconds": 3,
    },
    "output_dir": "fuzz-output",
}


class FuzzConfigLoader:
    """Đọc cấu hình cho fuzztool."""

    def __init__(self, defaults: Dict[str, Any] | None = None) -> None:
        self.defaults = deepcopy(defaults or DEFAULT_CONFIG)

    def load(self, path: str | None) -> Dict[str, Any]:
        config = deepcopy(self.defaults)
        if not path:
            return config
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.deep_merge(config, data)

    def deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(base)
        for key, value in override.items():
            base_value = result.get(key)
            both_values_are_dict = isinstance(value, dict) and isinstance(base_value, dict)

            if both_values_are_dict:
                result[key] = self.deep_merge(base_value, value)
            else:
                result[key] = value
        return result
