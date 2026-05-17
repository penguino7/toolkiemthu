from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class FuzzTarget:
    """Một param cụ thể được chọn từ inventory để fuzz."""

    method: str
    url: str
    path: str
    auth_context: str
    param_name: str
    param_location: str
    type_hint: str = "string"
    sample_values: List[str] = field(default_factory=list)
    request_content_type: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    candidate_tests: List[str] = field(default_factory=list)
    record: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path} {self.param_location}:{self.param_name}"

    @property
    def sample_value(self) -> str:
        return self.sample_values[0] if self.sample_values else "1"


@dataclass
class HttpExchange:
    """Kết quả sau khi gửi một request fuzz."""

    method: str
    url: str
    status: int
    headers: Dict[str, str]
    text: str
    elapsed_seconds: float
    error: str | None = None


@dataclass
class Finding:
    """Một kết quả nghi vấn được detector ghi nhận."""

    vuln_type: str
    subtype: str
    severity: str
    target: FuzzTarget
    payload: str
    evidence: str
    request_url: str
    status: int | None = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "subtype": self.subtype,
            "severity": self.severity,
            "method": self.target.method,
            "path": self.target.path,
            "url": self.request_url,
            "auth_context": self.target.auth_context,
            "param": self.target.param_name,
            "location": self.target.param_location,
            "payload": self.payload,
            "status": self.status,
            "evidence": self.evidence,
            "details": self.details,
        }
