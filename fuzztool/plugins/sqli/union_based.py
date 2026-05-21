from __future__ import annotations

from typing import List
from uuid import uuid4

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector
from .payload_factory import SqliPayloadFactory


class UnionBasedSqliScanner:
    """Kiem tra SQLi union-based bang marker trong response.

    Y tuong:
    1. Gui request baseline voi gia tri binh thuong.
    2. Thu UNION SELECT voi so cot tang dan.
    3. Neu marker xuat hien trong response thi co bang chung union-based.
    """

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()
        self.payload_factory = SqliPayloadFactory()

        sqli_config = config.get("sqli", {})
        self.max_columns = int(sqli_config.get("union_max_columns", 12))
        self.marker_prefix = str(sqli_config.get("union_marker_prefix", "FUZZUNION"))

    def scan(self, target: FuzzTarget) -> List[Finding]:
        baseline_response = self._send_baseline(target)
        if baseline_response.error:
            print(f"[!] Skip union-based target because baseline failed: {target.key} error={baseline_response.error}")
            return []

        marker = self._new_marker()
        if marker in baseline_response.text:
            return []

        for column_count in range(1, self.max_columns + 1):
            columns_sql = self._marker_columns(marker, column_count)
            payloads = self.payload_factory.union_payloads(target, columns_sql)

            for payload in payloads:
                attack_method, attack_url, attack_body, attack_headers = self.mutator.mutate(target, payload)
                attack_response = self.client.send(
                    attack_method,
                    attack_url,
                    body=attack_body,
                    headers=attack_headers,
                )

                if attack_response.error:
                    continue

                marker_evidence = self.detector.marker_evidence(attack_response.text, marker)
                if not marker_evidence:
                    continue

                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="union_based",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="union_marker_in_response",
                        request_url=attack_response.url,
                        status=attack_response.status,
                        details={
                            "marker": marker,
                            "column_count": column_count,
                            "response_excerpt": marker_evidence.get("response_excerpt", ""),
                            "response_content_type": attack_response.headers.get("content-type", ""),
                            "elapsed_seconds": round(attack_response.elapsed_seconds, 4),
                        },
                    )
                ]

        return []

    def _send_baseline(self, target: FuzzTarget):
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)

    def _new_marker(self) -> str:
        return f"{self.marker_prefix}_{uuid4().hex[:8]}"

    def _marker_columns(self, marker: str, column_count: int) -> str:
        quoted_marker = f"'{marker}'"
        return ",".join([quoted_marker for _ in range(column_count)])
