from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector
from .payload_factory import SqliPayloadFactory


class ErrorBasedSqliScanner:
    """SQLi error-based scanner."""

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()
        self.payload_factory = SqliPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        for payload in self._payloads(target):
            exchange = self._send(target, payload)
            if self.detector.has_db_error(exchange.text):
                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="error_based",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="database_error_pattern",
                        request_url=exchange.url,
                        status=exchange.status,
                        details={
                            "elapsed_seconds": round(exchange.elapsed_seconds, 4),
                            "error": exchange.error,
                        },
                    )
                ]
        return []

    def _send(self, target: FuzzTarget, payload: str):
        method, url, body, headers = self.mutator.mutate(target, payload)
        return self.client.send(method, url, body=body, headers=headers)

    def _payloads(self, target: FuzzTarget) -> List[str]:
        return self.payload_factory.error_payloads(target)
