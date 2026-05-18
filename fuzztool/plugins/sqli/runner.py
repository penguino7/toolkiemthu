from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
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
                findings.extend(scanner.scan(target))

        if options.get("boolean_based", False):
            scanner = BooleanBasedSqliScanner(self.client)
            for target in targets:
                findings.extend(scanner.scan(target))

        if options.get("time_based", False):
            scanner = TimeBasedSqliScanner(self.client, self.config)
            for target in targets:
                findings.extend(scanner.scan(target))

        return findings
