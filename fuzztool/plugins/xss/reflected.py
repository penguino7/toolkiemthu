from __future__ import annotations

from hashlib import sha1
from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .browser_verifier import BrowserXssVerifier
from .detector import XssDetector
from .payload_factory import XssPayloadFactory


class ReflectedXssScanner:
    """Kiem tra reflected XSS va chi ghi finding khi payload thuc thi."""

    def __init__(self, client: FuzzHttpClient, config: dict | None = None, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config or {}
        self.mutator = mutator or RequestMutator()
        self.detector = XssDetector()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location != "query":
            return []

        marker = self._marker(target)
        payloads = self._payloads(marker)
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for payload in payloads:
                method, url, body, headers = self.mutator.mutate(target, payload)
                exchange = self.client.send(method, url, body=body, headers=headers)
                found, context = self.detector.reflected(exchange.text, marker, exchange.headers.get("content-type", ""))
                if not found:
                    continue

                proof = verifier.verify_url(url, marker)
                if not proof.executed:
                    continue

                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="reflected",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="alert_dialog_executed_after_reflection",
                        request_url=proof.final_url,
                        status=exchange.status,
                        details={
                            "context": context,
                            "marker": marker,
                            "dialog_messages": proof.dialog_messages,
                            "rendered_in_browser": proof.rendered,
                            "browser_error": proof.error,
                            "elapsed_seconds": round(exchange.elapsed_seconds, 4),
                        },
                    )
                )
        return findings

    def _payloads(self, marker: str) -> List[str]:
        mode = self.config.get("xss", {}).get("payload_mode", "proof")
        if mode == "marker":
            return self.payload_factory.marker_payloads(marker)
        return self.payload_factory.proof_payloads(marker)

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZXSS_{digest}"
