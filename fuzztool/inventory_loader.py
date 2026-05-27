from __future__ import annotations

import json
from pathlib import Path
from typing import List
from urllib.parse import urljoin, urlparse, urlunparse

from .models import FuzzTarget


class InventoryLoader:
    """Đọc inventory.json từ recontool và chọn param để fuzz."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.base_url = str(config.get("base_url", "")).rstrip("/")
        self.scope = ScopeFilter(config)
        self.skip_names = {name.lower() for name in config.get("safety", {}).get("skip_param_names", [])}

    def load_records(self, path: str) -> List[dict]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return list(data.get("endpoints", []))
        return list(data)

    def targets_for(self, path: str) -> List[FuzzTarget]:
        records = self.load_records(path)

        targets: List[FuzzTarget] = []
        for record in records:
            record_url = self._record_url(record)
            fuzz_url = self._url_for_fuzz(record_url)
            if not self.scope.allows(fuzz_url):
                continue

            for param in record.get("params", []):
                target = self._target_from_param(record, param, fuzz_url)
                if target:
                    targets.append(target)

        return targets

    def _record_url(self, record: dict) -> str:
        return str(record.get("url", ""))

    def _url_for_fuzz(self, raw_url: str) -> str:
        if not self.base_url:
            return raw_url

        base = urlparse(self.base_url)
        if not base.scheme or not base.netloc:
            return raw_url

        parsed = urlparse(raw_url)
        if not parsed.scheme and not parsed.netloc:
            return urljoin(self.base_url + "/", raw_url.lstrip("/"))

        return urlunparse((base.scheme, base.netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

    def _target_from_param(self, record: dict, param: dict, fuzz_url: str) -> FuzzTarget | None:
        name = str(param.get("name", ""))
        location = str(param.get("in") or param.get("location", ""))
        if not name or name.lower() in self.skip_names:
            return None

        sample_values = self._sample_values(param)

        return FuzzTarget(
            method=str(record.get("method", "GET")).upper(),
            url=fuzz_url,
            path=str(record.get("canonical_path") or record.get("path") or ""),
            param_name=name,
            param_location=location,
            type_hint=str(param.get("type") or param.get("type_hint") or "string"),
            sample_values=sample_values,
            request_content_type=str(record.get("request_content_type", "")),
            request_headers={str(k).lower(): str(v) for k, v in record.get("request_headers", {}).items()},
            record=record,
        )

    def _sample_values(self, param: dict) -> List[str]:
        if "sample_values" in param:
            return [str(value) for value in param.get("sample_values", [])]
        if "sample" in param:
            return [str(param.get("sample", ""))]
        return []


class ScopeFilter:
    """Gioi han host/path duoc phep fuzz."""

    def __init__(self, config: dict) -> None:
        scope = config.get("scope", {})
        self.include_hosts = {host.lower() for host in scope.get("include_hosts", [])}
        self.exclude_paths = list(scope.get("exclude_paths", []))

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if self.include_hosts and host not in self.include_hosts:
            return False

        return not any(parsed.path.startswith(path) for path in self.exclude_paths)
