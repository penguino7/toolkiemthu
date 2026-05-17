from __future__ import annotations

from hashlib import sha1
from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import XssDetector


class ReflectedXssScanner:
    """Kiểm tra XSS reflected bằng marker an toàn."""

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()
        self.detector = XssDetector()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        marker = self._marker(target)
        payloads = [marker, f'">{marker}', f"'{marker}"]
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
                        severity="medium",
                        target=target,
                        payload=payload,
                        evidence="marker_reflected_in_response",
                        request_url=exchange.url,
                        status=exchange.status,
                        details={"context": context, "elapsed_seconds": round(exchange.elapsed_seconds, 4)},
                    )
                )
        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZXSS_{digest}"
