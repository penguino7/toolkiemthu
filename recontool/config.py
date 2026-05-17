from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "base_url": "http://127.0.0.1:8080",
    "auth_context": "anonymous",
    "headers": {
        "User-Agent": "ReconTool/0.1"
    },
    "scope": {
        "include_hosts": ["127.0.0.1", "localhost"],
        "exclude_paths": ["/user/logout.php"]
    },
    "seeds": ["/"],
    "static": {
        "enabled": True,
        "max_pages": 50,
        "max_depth": 3,
        "timeout_seconds": 10
    },
    "dynamic": {
        "enabled": False,
        "max_pages": 20,
        "timeout_ms": 15000,
        "headless": True,
        "storage_state": "",
        "click_selectors": [],
        "max_clicks_per_page": 0,
        "deny_click_texts": ["logout", "delete", "remove", "submit", "sign out"],
        "resource_types": ["document", "xhr", "fetch"],
        "auto_scroll": False,
        "scroll_steps": 0,
        "scroll_delay_ms": 300,
        "debug": False
    },
    "auth_profiles": [
        {
            "name": "anonymous",
            "type": "none"
        }
    ],
    "imports": {
        "har_files": [],
        "manual_seed_files": []
    },
    "dedupe": {
        "mode": "smart"
    },
    "output_dir": "recon-output"
}


class ConfigLoader:
    """Đọc config JSON và trộn với config mặc định.

    Tách thành class giúp sinh viên thấy rõ trách nhiệm: module này chỉ lo
    chuẩn bị cấu hình, không crawl và không xử lý endpoint.
    """

    def __init__(self, defaults: Dict[str, Any] | None = None) -> None:
        self.defaults = deepcopy(defaults or DEFAULT_CONFIG)

    def load(self, path: str | None) -> Dict[str, Any]:
        config = deepcopy(self.defaults)
        if not path:
            return config

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.deep_merge(config, data)

    def deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge dict lồng nhau.

        Ví dụ file config chỉ ghi `"dynamic": {"enabled": true}` thì các key
        còn lại như `max_pages`, `timeout_ms` vẫn được giữ từ mặc định.
        """
        result = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = self.deep_merge(result[key], value)
            else:
                result[key] = value
        return result


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Wrapper tương thích cho code cũ."""
    return ConfigLoader().deep_merge(base, override)


def load_config(path: str | None) -> Dict[str, Any]:
    """Wrapper tương thích cho CLI hiện tại."""
    return ConfigLoader().load(path)
