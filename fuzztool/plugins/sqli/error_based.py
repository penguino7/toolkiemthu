from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector
from .payload_factory import SqliPayloadFactory


class ErrorBasedSqliScanner:
    """Kiem tra SQLi error-based.

    Scanner nay tim dau hieu loi database trong response sau khi inject payload.
    """

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()
        self.payload_factory = SqliPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        payloads = self.payload_factory.error_payloads(target)

        for payload in payloads:
            # Buoc 1: tao request tan cong cho param dang test.
            attack_method, attack_url, attack_body, attack_headers = self.mutator.mutate(target, payload)

            # Buoc 2: gui request va doc response.
            response = self.client.send(attack_method, attack_url, body=attack_body, headers=attack_headers)

            # Buoc 3: neu response co loi database thi ghi finding.
            if self.detector.has_db_error(response.text):
                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="error_based",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="database_error_pattern",
                        request_url=response.url,
                        status=response.status,
                        details={
                            "elapsed_seconds": round(response.elapsed_seconds, 4),
                            "error": response.error,
                        },
                    )
                ]
        return []
