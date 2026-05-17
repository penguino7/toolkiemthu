from __future__ import annotations

from .http_client import FuzzHttpClient
from .models import FuzzTarget, HttpExchange
from .mutator import RequestMutator


class BaselineRunner:
    """Gửi request gốc để lấy response nền trước khi fuzz."""

    def __init__(self, client: FuzzHttpClient, mutator: RequestMutator | None = None) -> None:
        self.client = client
        self.mutator = mutator or RequestMutator()

    def run(self, target: FuzzTarget) -> HttpExchange:
        method, url, body, headers = self.mutator.baseline(target)
        return self.client.send(method, url, body=body, headers=headers)
