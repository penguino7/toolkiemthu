from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator
from .payload_factory import SqliPayloadFactory


class TimeBasedSqliScanner:
    """Kiem tra SQLi time-based.

    Scanner nay so sanh thoi gian response binh thuong voi response khi inject
    payload SLEEP. Neu request payload cham hon ro rang thi ghi finding.
    """

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        sqli_config = config.get("sqli", {})
        self.threshold = float(sqli_config.get("time_threshold_seconds", 2.5))
        self.sleep_seconds = int(sqli_config.get("time_sleep_seconds", 3))
        self.payload_factory = SqliPayloadFactory(sleep_seconds=self.sleep_seconds)

    def scan(self, target: FuzzTarget) -> List[Finding]:
        # Buoc 1: gui request baseline de biet target binh thuong nhanh/cham the nao.
        baseline_method, baseline_url, baseline_body, baseline_headers = self.mutator.baseline(target)
        baseline_response = self.client.send(
            baseline_method,
            baseline_url,
            body=baseline_body,
            headers=baseline_headers,
        )
        if baseline_response.error:
            return []

        payloads = self.payload_factory.time_payloads(target)
        for payload in payloads:
            # Buoc 2: gui request co payload delay, vi du SLEEP(3).
            attack_method, attack_url, attack_body, attack_headers = self.mutator.mutate(target, payload)
            attack_response = self.client.send(
                attack_method,
                attack_url,
                body=attack_body,
                headers=attack_headers,
            )

            # Buoc 3: so sanh thoi gian payload voi baseline.
            delta_seconds = attack_response.elapsed_seconds - baseline_response.elapsed_seconds
            timeout_after_stable_baseline = bool(
                attack_response.error and attack_response.elapsed_seconds >= self.threshold
            )
            delayed_over_baseline = delta_seconds >= self.threshold
            if not timeout_after_stable_baseline and not delayed_over_baseline:
                continue

            evidence = (
                "request_timeout_after_stable_baseline"
                if timeout_after_stable_baseline
                else "response_delay_delta_over_threshold"
            )
            return [
                Finding(
                    vuln_type="sqli",
                    subtype="time_based",
                    severity="medium",
                    target=target,
                    payload=payload,
                    evidence=evidence,
                    request_url=attack_response.url,
                    status=attack_response.status,
                    details={
                        "baseline_seconds": round(baseline_response.elapsed_seconds, 4),
                        "payload_seconds": round(attack_response.elapsed_seconds, 4),
                        "delta_seconds": round(delta_seconds, 4),
                        "threshold": self.threshold,
                        "sleep_seconds": self.sleep_seconds,
                        "error": attack_response.error,
                    },
                )
            ]
        return []
