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
    """Stored XSS scanner, chi ghi finding khi payload da duoc thuc thi."""

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
        method, url, body, headers = self.mutator.mutate(target, payload)
        submit = self.client.send(method, url, body=body, headers=headers)
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for path in self.config.get("xss", {}).get("stored_check_paths", []):
                check_url = urljoin(self.config.get("base_url", target.url), path)
                proof = verifier.verify_url(check_url, marker)
                if not proof.executed:
                    continue

                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="stored",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="stored_alert_dialog_executed",
                        request_url=proof.final_url,
                        status=submit.status,
                        details={
                            "marker": marker,
                            "submit_status": submit.status,
                            "check_url": check_url,
                            "dialog_messages": proof.dialog_messages,
                            "rendered_in_browser": proof.rendered,
                            "browser_error": proof.error,
                        },
                    )
                )
        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"stored|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZSTORED_{digest}"
