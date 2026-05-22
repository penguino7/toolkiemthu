from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PayloadCheck:
    allowed: bool
    reason: str = ""


class PayloadGuard:
    """Chặn payload nguy hiểm trước khi tool gửi request."""

    BLOCKED_PATTERNS = [
        r"\bdrop\b",
        r"\bdelete\b",
        r"\bupdate\b",
        r"\binsert\b",
        r"\balter\b",
        r"\btruncate\b",
        r"\bcreate\b",
        r"\bgrant\b",
        r"\brevoke\b",
        r"\binto\s+outfile\b",
        r"\bload_file\s*\(",
        r"\bxp_cmdshell\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bchmod\b",
        r"\bchown\b",
        r"\brm\s+-",
        r"\bshutdown\b",
    ]

    def __init__(self, max_payload_chars: int = 500) -> None:
        self.max_payload_chars = max_payload_chars

    def check(self, payload: str) -> PayloadCheck:
        if not payload or not payload.strip():
            return PayloadCheck(False, "payload rỗng")

        if len(payload) > self.max_payload_chars:
            return PayloadCheck(False, f"payload dài hơn {self.max_payload_chars} ký tự")

        lowered = payload.lower()
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, lowered):
                return PayloadCheck(False, f"payload chứa mẫu bị chặn: {pattern}")

        return PayloadCheck(True, "payload hợp lệ")
