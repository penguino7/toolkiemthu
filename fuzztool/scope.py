from __future__ import annotations

from urllib.parse import urlparse


class FuzzScope:
    """Giới hạn URL được phép fuzz."""

    def __init__(self, config: dict) -> None:
        scope = config.get("scope", {})
        self.include_hosts = {host.lower() for host in scope.get("include_hosts", [])}
        self.exclude_paths = list(scope.get("exclude_paths", []))

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if self.include_hosts and host not in self.include_hosts:
            return False

        for excluded_path in self.exclude_paths:
            if parsed.path.startswith(excluded_path):
                return False

        return True
