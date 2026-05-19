from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient, RequestBudgetExceeded
from ...models import Finding, FuzzTarget
from .boolean_based import BooleanBasedSqliScanner
from .error_based import ErrorBasedSqliScanner
from .time_based import TimeBasedSqliScanner


class SqliRunner:
    """Điều phối các scanner SQLi."""

    def __init__(self, client: FuzzHttpClient, config: dict) -> None:
        self.client = client
        self.config = config

    def run(self, targets: List[FuzzTarget]) -> List[Finding]:
        options = self.config.get("sqli", {})
        findings: List[Finding] = []

        # Mỗi khối bên dưới chạy một kiểu SQLi riêng.
        if options.get("error_based", True):
            scanner = ErrorBasedSqliScanner(self.client)
            for target in targets:
                try:
                    findings.extend(scanner.scan(target))
                except RequestBudgetExceeded as error:
                    print(f"[!] {error}")
                    return findings

        if options.get("boolean_based", False):
            scanner = BooleanBasedSqliScanner(self.client)
            for target in targets:
                try:
                    findings.extend(scanner.scan(target))
                except RequestBudgetExceeded as error:
                    print(f"[!] {error}")
                    return findings

        if options.get("time_based", False):
            scanner = TimeBasedSqliScanner(self.client, self.config)
            for target in self._prioritize_time_based_targets(targets):
                try:
                    findings.extend(scanner.scan(target))
                except RequestBudgetExceeded as error:
                    print(f"[!] {error}")
                    return findings

        return findings

    def _prioritize_time_based_targets(self, targets: List[FuzzTarget]) -> List[FuzzTarget]:
        """Test param co kha nang SQLi time-based cao truoc de tiet kiem request."""

        def priority(target: FuzzTarget) -> tuple[int, int, int, str]:
            name = target.param_name.lower()
            numeric_type = 0 if target.type_hint in {"int", "float"} else 1
            id_like_name = 0 if name == "id" or name.endswith("_id") or name in {"filter_cat", "edit_id"} else 1
            location_score = {"query": 0, "body": 1, "json": 2}.get(target.param_location, 3)
            return numeric_type, id_like_name, location_score, target.key

        return sorted(targets, key=priority)
