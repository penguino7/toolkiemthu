from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List

def _unique(values: List[Any]) -> List[Any]:
    """Loại bỏ phần tử trùng lặp nhưng vẫn giữ nguyên thứ tự."""
    seen = set()
    output = []
    for v in values:
        if (marker := repr(v)) not in seen:
            seen.add(marker)
            output.append(v)
    return output

@dataclass
class Param:
    """Đại diện cho một tham số của endpoint (ví dụ: query, body, json)."""
    name: str
    location: str
    type_hint: str = "string"
    sample_values: List[str] = field(default_factory=list)
    reflected: bool = False

    @property
    def key(self) -> str:
        return f"{self.location}:{self.name}" #"body:id"

    def add_value(self, value: Any) -> None:
        if value is not None and (text := str(value)) not in self.sample_values:
            self.sample_values.append(text) 
            self.sample_values = self.sample_values[:8] # Giới hạn 8 samples

#dung de gop cac tham so trung nhau thanh 1 cai
    def merge(self, other: Param) -> None:
        if self.type_hint == "string":
            self.type_hint = other.type_hint 
        self.sample_values = _unique(self.sample_values + other.sample_values)[:8]
        self.reflected = self.reflected or other.reflected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type_hint": self.type_hint,
            "sample_values": self.sample_values,
            "reflected": self.reflected,
        }

@dataclass
class EndpointRecord:
    """Một endpoint đã được chuẩn hóa, làm object trung tâm giao tiếp giữa các module."""
    
    # 1. Thông tin định tuyến cốt lõi
    method: str
    url: str
    scheme: str
    host: str
    path: str
    canonical_path: str
    port: int | None = None
    
    # 2. Context & Headers
    auth_context: str = "anonymous"
    request_content_type: str = ""
    response_content_type: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    statuses: List[int] = field(default_factory=list)
    
    # 3. Payload & Dữ liệu
    params: Dict[str, Param] = field(default_factory=dict)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    
    # 4. Metadata (Nguồn gốc & Tracking)
    source_tools: List[str] = field(default_factory=list)
    discovered_from: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    seen_count: int = 1
    evidence: Dict[str, Any] = field(default_factory=dict)

    def add_param(self, param: Param) -> None:
        if param.key in self.params:
            self.params[param.key].merge(param)
        else:
            self.params[param.key] = param

    def merge(self, other: EndpointRecord) -> None:
        self.seen_count += other.seen_count
        self.statuses = sorted(set(self.statuses + other.statuses))
        
        # Cập nhật Content-Type nếu đang thiếu
        self.response_content_type = self.response_content_type or other.response_content_type
        self.request_content_type = self.request_content_type or other.request_content_type
        
        self.request_headers.update({k: v for k, v in other.request_headers.items() if v})
        self.response_headers.update({k: v for k, v in other.response_headers.items() if v})
        
        for param in other.params.values():
            self.add_param(param)
            
        self.forms = _unique(self.forms + other.forms)
        self.source_tools = sorted(set(self.source_tools + other.source_tools))
        self.discovered_from = _unique(self.discovered_from + other.discovered_from)[:20]
        self.examples = _unique(self.examples + other.examples)[:10]
        self.evidence.update({k: v for k, v in other.evidence.items() if v})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "canonical_path": self.canonical_path,
            "auth_context": self.auth_context,
            "request_content_type": self.request_content_type,
            "response_content_type": self.response_content_type,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "statuses": self.statuses,
            "params": [p.to_dict() for p in sorted(self.params.values(), key=lambda p: p.key)],
            "forms": self.forms,
            "source_tools": self.source_tools,
            "discovered_from": self.discovered_from,
            "examples": self.examples,
            "seen_count": self.seen_count,
            "evidence": self.evidence,
        }
