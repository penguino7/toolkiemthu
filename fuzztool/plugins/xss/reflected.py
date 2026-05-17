from __future__ import annotations

from hashlib import sha1
from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import XssDetector
from .payload_factory import XssPayloadFactory


class ReflectedXssScanner:
    """Kiểm tra reflected XSS bằng payload thật có marker."""

    def __init__(self, client: FuzzHttpClient, config: dict | None = None, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config or {}
        self.mutator = mutator or RequestMutator()
        self.detector = XssDetector()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        marker = self._marker(target)
        payloads = self._payloads(marker)
        findings: List[Finding] = []

        for payload in payloads:
            method, url, body, headers = self.mutator.mutate(target, payload)
            exchange = self.client.send(method, url, body=body, headers=headers)
            found, context = self.detector.reflected(exchange.text, marker, exchange.headers.get("content-type", ""))
            if found:
                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="reflected",
                        severity="high" if "alert(" in payload else "medium",
                        target=target,
                        payload=payload,
                        evidence="xss_proof_payload_reflected",
                        request_url=exchange.url,
                        status=exchange.status,
                        details={
                            "context": context,
                            "marker": marker,
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
