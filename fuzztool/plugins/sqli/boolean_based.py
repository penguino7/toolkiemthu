from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import SqliDetector
from .payload_factory import SqliPayloadFactory


class BooleanBasedSqliScanner:
    """Kiem tra SQLi boolean-based.

    Scanner nay gui payload dung/sai theo cap. Neu response cua dieu kien dung
    va sai khac nhau ro rang thi co kha nang SQLi.
    """

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = SqliDetector()
        self.payload_factory = SqliPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        for true_payload, false_payload in self.payload_factory.boolean_payload_pairs(target):
            # Buoc 1: gui request voi dieu kien SQL dung.
            true_method, true_url, true_body, true_headers = self.mutator.mutate(target, true_payload)
            true_response = self.client.send(true_method, true_url, body=true_body, headers=true_headers)

            # Buoc 2: gui request voi dieu kien SQL sai.
            false_method, false_url, false_body, false_headers = self.mutator.mutate(target, false_payload)
            false_response = self.client.send(false_method, false_url, body=false_body, headers=false_headers)

            if true_response.error or false_response.error:
                continue

            same_status = true_response.status == false_response.status
            response_is_different = self.detector.response_changed(true_response.text, false_response.text)

            # Buoc 3: chi ghi finding khi true/false tao ra response khac nhau.
            if same_status and response_is_different:
                return [
                    Finding(
                        vuln_type="sqli",
                        subtype="boolean_based",
                        severity="medium",
                        target=target,
                        payload=f"{true_payload} / {false_payload}",
                        evidence="true_false_response_difference",
                        request_url=true_response.url,
                        status=true_response.status,
                        details={
                            "true_length": len(true_response.text),
                            "false_length": len(false_response.text),
                        },
                    )
                ]
        return []
