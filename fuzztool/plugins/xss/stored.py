from __future__ import annotations

from hashlib import sha1
from typing import List
from urllib.parse import urljoin

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .browser_verifier import BrowserXssVerifier
from .payload_factory import XssPayloadFactory


class StoredXssScanner:
    """Kiem tra stored XSS.

    Luong chinh: submit payload vao form/API, sau do mo cac trang check lai
    bang browser de xem payload da duoc luu va thuc thi hay chua.
    """

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location not in {"body", "json"}:
            return []

        marker = self._marker(target)
        payload = self.payload_factory.proof_payloads(marker)[0]
        findings: List[Finding] = []

        # Buoc 1: submit payload vao body/json param dang duoc test.
        submit_method, submit_url, submit_body, submit_headers = self.mutator.mutate(target, payload)
        submit_response = self.client.send(submit_method, submit_url, body=submit_body, headers=submit_headers)

        # Buoc 2: mo lai cac trang co kha nang hien thi du lieu vua submit.
        check_paths = self.config.get("xss", {}).get("stored_check_paths", [])
        with BrowserXssVerifier(self.config) as verifier:
            for path in check_paths:
                check_url = urljoin(self.config.get("base_url", target.url), path)
                browser_result = verifier.verify_url(check_url, marker)
                if not browser_result.executed:
                    continue

                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="stored",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="stored_alert_dialog_executed",
                        request_url=browser_result.final_url,
                        status=submit_response.status,
                        details={
                            "marker": marker,
                            "submit_status": submit_response.status,
                            "check_url": check_url,
                            "dialog_messages": browser_result.dialog_messages,
                            "rendered_in_browser": browser_result.rendered,
                            "browser_error": browser_result.error,
                        },
                    )
                )
        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"stored|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZSTORED_{digest}"
