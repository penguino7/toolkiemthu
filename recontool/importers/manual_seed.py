from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..models import EndpointRecord
from ..normalizer import ReconNormalizer


class ManualSeedImporter:
    """Đọc endpoint do người dùng tự ghi vào file.

    Manual seed giúp bổ sung endpoint mà crawler chưa thấy, ví dụ endpoint ẩn
    hoặc URL bạn lấy từ ghi chú riêng.
    """

    SOURCE = "manual_seed_importer"

    def __init__(self, config: dict, normalizer: ReconNormalizer | None = None) -> None:
        self.config = config
        self.normalizer = normalizer or ReconNormalizer()

    def import_file(self, path: str) -> List[EndpointRecord]:
        seed_path = Path(path)
        if seed_path.suffix.lower() == ".json":
            return self._import_json(seed_path)
        return self._import_text(seed_path)

    def _import_json(self, path: Path) -> List[EndpointRecord]:
        data = json.loads(path.read_text(encoding="utf-8"))
        records = []
        for item in data:
            records.append(
                self.normalizer.make_record(
                    item.get("method", "GET"),
                    item["url"],
                    self.SOURCE,
                    base_url=self.config.get("base_url"),
                    auth_context=item.get("auth_context", self.config.get("auth_context", "anonymous")),
                    request_content_type=item.get("content_type", ""),
                    body=item.get("body"),
                )
            )
        return records

    def _import_text(self, path: Path) -> List[EndpointRecord]:
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            parsed = self._parse_line(line)
            if not parsed:
                continue
            method, url, body = parsed
            records.append(
                self.normalizer.make_record(
                    method,
                    url,
                    self.SOURCE,
                    base_url=self.config.get("base_url"),
                    auth_context=self.config.get("auth_context", "anonymous"),
                    request_content_type="application/x-www-form-urlencoded" if body else "",
                    body=body,
                )
            )
        return records

    def _parse_line(self, line: str) -> tuple[str, str, str | None] | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split(maxsplit=2)
        if parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} and len(parts) >= 2:
            method = parts[0].upper()
            url = parts[1]
            body = parts[2] if len(parts) == 3 else None
            return method, url, body

        return "GET", parts[0], None


def import_manual_seed(path: str, config: dict) -> List[EndpointRecord]:
    return ManualSeedImporter(config).import_file(path)
