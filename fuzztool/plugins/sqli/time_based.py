from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget, HttpExchange
from ...mutator import RequestMutator


class TimeBasedSqliScanner:
    """SQLi time-based scanner."""

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        sqli_config = config.get("sqli", {})
        self.threshold = float(sqli_config.get("time_threshold_seconds", 2.5))
        self.sleep_seconds = int(sqli_config.get("time_sleep_seconds", 3))

    def scan(self, target: FuzzTarget) -> List[Finding]:
        baseline = self._send_baseline(target)
        if baseline.error:
            return []

        for payload in self._payloads(target):
            method, url, body, headers = self.mutator.mutate(target, payload)
            exchange = self.client.send(method, url, body=body, headers=headers)
            finding = self._finding_if_delayed(target, payload, baseline, exchange)
            if finding:
                return [finding]
        return []

    def _finding_if_delayed(
        self,
        target: FuzzTarget,
        payload: str,
        baseline: HttpExchange,
        exchange: HttpExchange,
    ) -> Finding | None:
        delta = exchange.elapsed_seconds - baseline.elapsed_seconds
        timeout_after_stable_baseline = bool(exchange.error and exchange.elapsed_seconds >= self.threshold)
        delayed_over_baseline = delta >= self.threshold
        if not timeout_after_stable_baseline and not delayed_over_baseline:
            return None

        evidence = "request_timeout_after_stable_baseline" if timeout_after_stable_baseline else "response_delay_delta_over_threshold"
        return Finding(
            vuln_type="sqli",
            subtype="time_based",
            severity="medium",
            target=target,
            payload=payload,
            evidence=evidence,
            request_url=exchange.url,
            status=exchange.status,
            details={
                "baseline_seconds": round(baseline.elapsed_seconds, 4),
                "payload_seconds": round(exchange.elapsed_seconds, 4),
                "delta_seconds": round(delta, 4),
                "threshold": self.threshold,
                "sleep_seconds": self.sleep_seconds,
                "error": exchange.error,
            },
        )

    def _send_baseline(self, target: FuzzTarget) -> HttpExchange:
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)

    def _payloads(self, target: FuzzTarget) -> List[str]:
        sample = target.sample_value
        sleep = self.sleep_seconds
        if target.type_hint in {"int", "float"}:
            return [
                f"{sample} AND SLEEP({sleep})",
                f"{sample}' AND SLEEP({sleep})-- -",
            ]
        return [
            f"{sample}' AND SLEEP({sleep})-- -",
            f"{sample}' OR SLEEP({sleep})-- -",
        ]
