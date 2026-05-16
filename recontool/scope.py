from __future__ import annotations

from urllib.parse import urlparse


def in_scope(url: str, config: dict) -> bool:
    parsed = urlparse(url)
    scope = config.get("scope", {})
    include_hosts = {host.lower() for host in scope.get("include_hosts", [])}
    if include_hosts and (parsed.hostname or "").lower() not in include_hosts:
        return False
    for excluded in scope.get("exclude_paths", []):
        if parsed.path.startswith(excluded):
            return False
    return True
