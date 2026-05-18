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
    """Kiem tra reflected XSS.

    File nay chi lo mot viec: thay payload vao query param, mo URL bang
    browser that, roi ghi finding neu alert/dialog that su chay.
    """

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
        payload_mode = self.config.get("xss", {}).get("payload_mode", "proof")
        payloads = (
            self.payload_factory.marker_payloads(marker)
            if payload_mode == "marker"
            else self.payload_factory.proof_payloads(marker)
        )
        findings: List[Finding] = []

        with BrowserXssVerifier(self.config) as verifier:
            for payload in payloads:
                # Buoc 1: tao request tan cong bang cach thay param hien tai bang payload.
                attack_method, attack_url, attack_body, attack_headers = self.mutator.mutate(target, payload)

                # Buoc 2: gui request de xem marker co bi reflect trong HTTP response khong.
                response = self.client.send(attack_method, attack_url, body=attack_body, headers=attack_headers)
                content_type = response.headers.get("content-type", "")
                is_reflected, reflection_context = self.detector.reflected(response.text, marker, content_type)
                if not is_reflected:
                    continue

                # Buoc 3: reflect chua du. Mo browser that de xac nhan JavaScript co chay.
                browser_result = verifier.verify_url(attack_url, marker)
                if not browser_result.executed:
                    continue

                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="reflected",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="alert_dialog_executed_after_reflection",
                        request_url=browser_result.final_url,
                        status=response.status,
                        details={
                            "context": reflection_context,
                            "marker": marker,
                            "dialog_messages": browser_result.dialog_messages,
                            "rendered_in_browser": browser_result.rendered,
                            "browser_error": browser_result.error,
                            "elapsed_seconds": round(response.elapsed_seconds, 4),
                        },
                    )
                )
        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZXSS_{digest}"
