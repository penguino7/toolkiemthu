from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector
from .payload_factory import SqliPayloadFactory


class BooleanBasedSqliScanner:
    """SQLi boolean-based scanner tùy chọn."""

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()
        self.payload_factory = SqliPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        for true_payload, false_payload in self.payload_factory.boolean_payload_pairs(target):
            true_exchange = self._send(target, true_payload)
            false_exchange = self._send(target, false_payload)
            if true_exchange.error or false_exchange.error:
                continue
            if true_exchange.status == false_exchange.status and self.detector.response_changed(true_exchange.text, false_exchange.text):
                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="boolean_based",
                        severity="medium",
                        target=target,
                        payload=f"{true_payload} / {false_payload}",
                        evidence="true_false_response_difference",
                        request_url=true_exchange.url,
                        status=true_exchange.status,
                        details={
                            "true_length": len(true_exchange.text),
                            "false_length": len(false_exchange.text),
                        },
                    )
                ]
        return []

    def _send(self, target: FuzzTarget, payload: str):
        method, url, body, headers = self.mutator.mutate(target, payload)
        return self.client.send(method, url, body=body, headers=headers)
