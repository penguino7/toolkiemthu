from __future__ import annotations

import json
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
        "enabled": True,
        "max_pages": 20,
        "timeout_ms": 15000,
        "headless": True,
        "storage_state": ""
    },
    "imports": {
        "har_files": [],
        "manual_seed_files": []
    },
    "dedupe": {
        "mode": "smart"
    },
    "output_dir": "recon-output"
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | None) -> Dict[str, Any]:
    config = DEFAULT_CONFIG
    if path:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        config = deep_merge(config, data)
    return config
