from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urljoin, urlparse, urlunparse

from .models import FuzzTarget
from .scope import FuzzScope


XSS_TARGET_TESTS = {
    "reflected_xss_candidate",
    "stored_xss_candidate",
    "api_xss_source",
    "reflection_detected",
}


class InventoryLoader:
    """Đọc inventory.json từ recontool và chọn param để fuzz."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.base_url = str(config.get("base_url", "")).rstrip("/")
        self.scope = FuzzScope(config)
        self.skip_names = {name.lower() for name in config.get("safety", {}).get("skip_param_names", [])}

    def load_records(self, path: str) -> List[dict]:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def targets_for(self, path: str, kinds: Iterable[str]) -> List[FuzzTarget]:
        kinds = set(kinds)
        records = self.load_records(path)

        targets: List[FuzzTarget] = []
        for record in records:
            record_url = self._record_url(record)
            fuzz_url = self._url_for_fuzz(record_url)
            if not self.scope.allows(fuzz_url):
                continue

            for param in record.get("params", []):
                target = self._target_from_param(record, param, fuzz_url)
                if target and self._matches_kind(target, kinds):
                    targets.append(target)

        return targets

    def _record_url(self, record: dict) -> str:
        examples = record.get("examples") or []
        if examples:
            return str(examples[0] or record.get("url", ""))
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
        location = str(param.get("location", ""))
        if not name or name.lower() in self.skip_names:
            return None

        return FuzzTarget(
            method=str(record.get("method", "GET")).upper(),
            url=fuzz_url,
            path=str(record.get("canonical_path") or record.get("path") or ""),
            auth_context=str(record.get("auth_context", "anonymous")),
            param_name=name,
            param_location=location,
            type_hint=str(param.get("type_hint", "string")),
            sample_values=[str(value) for value in param.get("sample_values", [])],
            request_content_type=str(record.get("request_content_type", "")),
            request_headers={str(k).lower(): str(v) for k, v in record.get("request_headers", {}).items()},
            candidate_tests=list(param.get("candidate_tests", []) or record.get("candidate_tests", [])),
            record=record,
        )

    def _matches_kind(self, target: FuzzTarget, kinds: set[str]) -> bool:
        tests = set(target.candidate_tests)

        if "xss" in kinds and tests & XSS_TARGET_TESTS:
            return True

        if "sqli" in kinds and any(test.startswith("sqli") for test in tests):
            return True

        return False
