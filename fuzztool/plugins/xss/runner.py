from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from .dom import DomXssScanner
from .reflected import ReflectedXssScanner
from .stored import StoredXssScanner


class XssRunner:
    """Điều phối các scanner XSS."""

    def __init__(self, client: FuzzHttpClient, config: dict) -> None:
        self.client = client
        self.config = config

    def run(self, targets: List[FuzzTarget]) -> List[Finding]:
        options = self.config.get("xss", {})
        findings: List[Finding] = []

        # Mỗi khối bên dưới chạy một loại XSS riêng, nhưng đều dùng chung target list.
        if options.get("reflected", True):
            scanner = ReflectedXssScanner(self.client, self.config)
            for target in targets:
                findings.extend(scanner.scan(target))

        if options.get("stored", False):
            scanner = StoredXssScanner(self.client, self.config)
            for target in targets:
                findings.extend(scanner.scan(target))

        if options.get("dom", False):
            scanner = DomXssScanner(self.config)
            for target in targets:
                findings.extend(scanner.scan(target))

        return findings
