from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class FuzzTarget:
    """Một param cụ thể được chọn từ inventory để fuzz."""

    method: str  # HTTP method: GET, POST...
    url: str  # URL mẫu lấy từ inventory.json.
    path: str  # Path/canonical_path, ví dụ: /search.php.
    param_name: str  # Tên param sẽ fuzz, ví dụ: q, id, content.
    param_location: str  # Vị trí param: query, body hoặc json.
    type_hint: str = "string"  # Kiểu suy luận từ recon: string, int, float...
    sample_values: List[str] = field(default_factory=list)  # Giá trị mẫu đã thấy khi recon.
    request_content_type: str = ""  # Content-Type gốc của request nếu có.
    request_headers: Dict[str, str] = field(default_factory=dict)  # Headers gốc để gửi lại khi fuzz.
    record: Dict[str, Any] = field(default_factory=dict)  # Record gốc từ inventory để cần thì dựng body/json.

    @property
    def key(self) -> str:
        return f"{self.method} {self.path} {self.param_location}:{self.param_name}"

    @property
    def sample_value(self) -> str:
        return self.sample_values[0] if self.sample_values else "1"


@dataclass
class HttpExchange:
    """Kết quả sau khi gửi một request fuzz."""

    method: str  # HTTP method đã gửi.
    url: str  # URL cuối cùng sau redirect nếu có.
    status: int  # HTTP status code. Nếu lỗi network thì thường là 0.
    headers: Dict[str, str]  # Response headers.
    text: str  # Response body dạng text nếu đọc được.
    elapsed_seconds: float  # Thoi gian request, dung de so sanh response hoac debug request cham.
    error: str | None = None  # Lỗi network/timeout nếu có.


@dataclass
class Finding:
    """Một kết quả nghi vấn được detector ghi nhận."""

    vuln_type: str  # Nhóm lỗ hổng: xss hoặc sqli.
    subtype: str  # Kiểu cụ thể: reflected, stored, error_based...
    severity: str  # Mức độ: low, medium, high.
    target: FuzzTarget  # Param/endpoint tạo ra finding.
    payload: str  # Payload đã dùng.
    evidence: str  # Bằng chứng chính khiến tool ghi finding.
    request_url: str  # URL/request gây ra evidence.
    status: int | None = None  # HTTP status nếu có.
    details: Dict[str, Any] = field(default_factory=dict)  # Thông tin bổ sung cho người đọc report.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "subtype": self.subtype,
            "severity": self.severity,
            "method": self.target.method,
            "path": self.target.path,
            "url": self.request_url,
            "param": self.target.param_name,
            "location": self.target.param_location,
            "payload": self.payload,
            "status": self.status,
            "evidence": self.evidence,
            "details": self.details,
        }
