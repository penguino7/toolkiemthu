from __future__ import annotations

from typing import List

from ...http_client import FuzzHttpClient
from ...models import Finding, FuzzTarget
from ...mutator import RequestMutator


class TimeBasedSqliScanner:
    """SQLi time-based scanner tùy chọn.

    Mặc định không bật vì chậm và dễ gây nhiễu. Chỉ dùng trong lab riêng.
    """

    def __init__(self, client: FuzzHttpClient, config: dict, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.config = config
        self.mutator = mutator or RequestMutator()
        self.threshold = float(config.get("sqli", {}).get("time_threshold_seconds", 2.5))

    def scan(self, target: FuzzTarget) -> List[Finding]:
        payload = f"{target.sample_value} AND SLEEP(3)"
        method, url, body, headers = self.mutator.mutate(target, payload)
        exchange = self.client.send(method, url, body=body, headers=headers)
        if exchange.elapsed_seconds >= self.threshold:
            return [
                Finding(
                    vuln_type="sqli",
                    subtype="time_based",
                    severity="medium",
                    target=target,
                    payload=payload,
                    evidence="response_delay_over_threshold",
                    request_url=exchange.url,
                    status=exchange.status,
                    details={
                        "elapsed_seconds": round(exchange.elapsed_seconds, 4),
                        "threshold": self.threshold,
                    },
                )
            ]
        return []
