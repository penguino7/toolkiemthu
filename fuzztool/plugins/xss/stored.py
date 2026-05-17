from __future__ import annotations

from hashlib import sha1
from typing import List
from urllib.parse import urljoin

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .detector import XssDetector
from .payload_factory import XssPayloadFactory


class StoredXssScanner:
    """Stored XSS scanner tùy chọn.

    Scanner này dùng payload thật. Mặc định không bật để tránh tạo dữ liệu ngoài
    ý muốn trên target không phải lab.
    """

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.detector = XssDetector()
        self.payload_factory = XssPayloadFactory()

    def scan(self, target: FuzzTarget) -> List[Finding]:
        if target.param_location not in {"body", "json"}:
            return []

        marker = self._marker(target)
        payload = self.payload_factory.proof_payloads(marker)[0]
        method, url, body, headers = self.mutator.mutate(target, payload)
        submit = self.client.send(method, url, body=body, headers=headers)
        findings = []

        for path in self.config.get("xss", {}).get("stored_check_paths", []):
            check_url = urljoin(self.config.get("base_url", target.url), path)
            response = self.client.send("GET", check_url)
            found, context = self.detector.reflected(response.text, marker, response.headers.get("content-type", ""))
            if found:
                findings.append(
                    Finding(
                        vuln_type="xss",
                        subtype="stored",
                        severity="high",
                        target=target,
                        payload=payload,
                        evidence="xss_proof_payload_persisted",
                        request_url=response.url,
                        status=response.status,
                        details={
                            "marker": marker,
                            "submit_status": submit.status,
                            "check_url": check_url,
                            "context": context,
                        },
                    )
                )
        return findings

    def _marker(self, target: FuzzTarget) -> str:
        seed = f"stored|{target.method}|{target.path}|{target.param_location}|{target.param_name}"
        digest = sha1(seed.encode("utf-8")).hexdigest()[:8]
        return f"FUZZSTORED_{digest}"
