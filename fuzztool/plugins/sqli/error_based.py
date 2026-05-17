from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector


class ErrorBasedSqliScanner:
    """SQLi error-based scanner."""

    PAYLOADS = ["'", "\"", "')", "\")"]

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            method, url, body, headers = self.mutator.mutate(target, payload)
            exchange = self.client.send(method, url, body=body, headers=headers)
            if self.detector.has_db_error(exchange.text):
                findings.append(
                    Finding(
                        vuln_type="sqli",
                        subtype="error_based",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="database_error_pattern",
                        request_url=exchange.url,
                        status=exchange.status,
                        details={"elapsed_seconds": round(exchange.elapsed_seconds, 4)},
                    )
                )
        return findings
