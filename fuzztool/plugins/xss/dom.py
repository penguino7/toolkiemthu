from __future__ import annotations

from hashlib import sha1
from typing import List

from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .browser_verifier import BrowserXssVerifier
from .payload_factory import XssPayloadFactory


class DomXssScanner:
    """DOM XSS scanner bang Playwright, chi ghi khi payload thuc thi."""

    def __init__(self, config: dict, mutator: RequestMutator | None = None) -> None:
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location != "query":
            return []

        marker = self._marker(target)
        payloads = self.payload_factory.proof_payloads(marker)
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for payload in payloads:
                _, url, _, _ = self.mutator.mutate(target, payload)
                proof = verifier.verify_url(url, marker)
                if not proof.executed:
                    continue

                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="dom",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="alert_dialog_executed",
                        request_url=proof.final_url,
                        status=None,
                        details={
                            "marker": marker,
                            "dialog_messages": proof.dialog_messages,
                            "rendered_in_browser": proof.rendered,
                            "browser_error": proof.error,
                            "scanner": "playwright_dom",
                        },
                    )
                )

        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"dom|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZDOM_{digest}"
