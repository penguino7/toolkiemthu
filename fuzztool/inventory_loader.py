from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import FuzzTarget
from .scope import FuzzScope


class InventoryLoader:
    """Đọc inventory.json từ recontool và chọn param để fuzz."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.scope = FuzzScope(config)
        self.skip_names = {name.lower() for name in config.get("safety", {}).get("skip_param_names", [])}

    def load_records(self, path: str) -> List[dict]:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def targets_for(self, path: str, kinds: Iterable[str]) -> List[FuzzTarget]:
        kinds = set(kinds)
        records = self.load_records(path)
        targets = []
        for record in records:
            if not self.scope.allows(record.get("url", "")):
                continue
            for param in record.get("params", []):
                target = self._target_from_param(record, param)
                if target and self._matches_kind(target, kinds):
                    targets.append(target)
        return targets

    def _target_from_param(self, record: dict, param: dict) -> FuzzTarget | None:
        name = str(param.get("name", ""))
        location = str(param.get("location", ""))
        if not name or name.lower() in self.skip_names:
            return None

        return FuzzTarget(
            method=str(record.get("method", "GET")).upper(),
            url=str(record.get("examples", [record.get("url", "")])[0] or record.get("url", "")),
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
        if "xss" in kinds and tests & {"reflected_xss_candidate", "stored_xss_candidate", "api_xss_source", "reflection_detected"}:
            return True
        if "sqli" in kinds and any(test.startswith("sqli") for test in tests):
            return True
        return False
