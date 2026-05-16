from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..normalizer import make_record


def import_manual_seed(path: str, config: dict) -> List:
    seed_path = Path(path)
    if seed_path.suffix.lower() == ".json":
        return _import_json(seed_path, config)
    return _import_text(seed_path, config)


def _import_json(path: Path, config: dict) -> List:
    data = json.loads(path.read_text(encoding="utf-8"))
    records = []
    for item in data:
        records.append(
            make_record(
                item.get("method", "GET"),
                item["url"],
                "manual_seed_importer",
                base_url=config.get("base_url"),
                auth_context=item.get("auth_context", config.get("auth_context", "anonymous")),
                request_content_type=item.get("content_type", ""),
                body=item.get("body"),
            )
        )
    return records


def _import_text(path: Path, config: dict) -> List:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=2)
        if parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} and len(parts) >= 2:
            method = parts[0].upper()
            url = parts[1]
            body = parts[2] if len(parts) == 3 else None
        else:
            method = "GET"
            url = parts[0]
            body = None
        records.append(
            make_record(
                method,
                url,
                "manual_seed_importer",
                base_url=config.get("base_url"),
                auth_context=config.get("auth_context", "anonymous"),
                request_content_type="application/x-www-form-urlencoded" if body else "",
                body=body,
            )
        )
    return records
