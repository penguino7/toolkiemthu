from __future__ import annotations

from urllib.parse import urlparse


class ScopePolicy:
    """Quy định URL nào được phép crawl.

    Đây là lớp rất quan trọng trong recon tool: crawler chỉ nên đi trong phạm vi
    target, tránh crawl nhầm sang domain khác.
    """

    def __init__(self, config: dict) -> None:
        self.config = config
        scope = config.get("scope", {})
        self.include_hosts = {host.lower() for host in scope.get("include_hosts", [])}
        self.exclude_paths = list(scope.get("exclude_paths", []))

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if self.include_hosts and hostname not in self.include_hosts:
            return False

        for excluded in self.exclude_paths:
            if parsed.path.startswith(excluded):
                return False

        return True


def in_scope(url: str, config: dict) -> bool:
    """Wrapper tương thích cho code cũ."""
    return ScopePolicy(config).allows(url)
