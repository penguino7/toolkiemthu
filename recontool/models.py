from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


def _unique(values: List[Any]) -> List[Any]:
    seen = set()
    output = []
    for value in values:
        marker = repr(value)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(value)
    return output


@dataclass
class Param:
    name: str
    location: str
    type_hint: str = "string"
    sample_values: List[str] = field(default_factory=list)
    reflected: bool = False
    candidate_tests: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.location}:{self.name}"

    def add_value(self, value: Any) -> None:
        if value is None:
            return
        text = str(value)
        if text not in self.sample_values:
            self.sample_values.append(text)
        if len(self.sample_values) > 8:
            self.sample_values = self.sample_values[:8]

    def merge(self, other: "Param") -> None:
        self.type_hint = self.type_hint if self.type_hint != "string" else other.type_hint
        self.sample_values = _unique(self.sample_values + other.sample_values)[:8]
        self.reflected = self.reflected or other.reflected
        self.candidate_tests = sorted(set(self.candidate_tests + other.candidate_tests))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type_hint": self.type_hint,
            "sample_values": self.sample_values,
            "reflected": self.reflected,
            "candidate_tests": self.candidate_tests,
        }


@dataclass
class EndpointRecord:
    method: str
    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    canonical_path: str
    auth_context: str = "anonymous"
    request_content_type: str = ""
    response_content_type: str = ""
    statuses: List[int] = field(default_factory=list)
    params: Dict[str, Param] = field(default_factory=dict)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    source_tools: List[str] = field(default_factory=list)
    discovered_from: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    seen_count: int = 1
    evidence: Dict[str, Any] = field(default_factory=dict)
    candidate_tests: List[str] = field(default_factory=list)

    def add_param(self, param: Param) -> None:
        if param.key in self.params:
            self.params[param.key].merge(param)
        else:
            self.params[param.key] = param

    def merge(self, other: "EndpointRecord") -> None:
        self.seen_count += other.seen_count
        self.statuses = sorted(set(self.statuses + other.statuses))
        if not self.response_content_type and other.response_content_type:
            self.response_content_type = other.response_content_type
        if not self.request_content_type and other.request_content_type:
            self.request_content_type = other.request_content_type
        for param in other.params.values():
            self.add_param(param)
        self.forms = _unique(self.forms + other.forms)
        self.source_tools = sorted(set(self.source_tools + other.source_tools))
        self.discovered_from = _unique(self.discovered_from + other.discovered_from)[:20]
        self.examples = _unique(self.examples + other.examples)[:10]
        self.candidate_tests = sorted(set(self.candidate_tests + other.candidate_tests))
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
            "statuses": self.statuses,
            "params": [p.to_dict() for p in sorted(self.params.values(), key=lambda p: p.key)],
            "forms": self.forms,
            "source_tools": self.source_tools,
            "discovered_from": self.discovered_from,
            "examples": self.examples,
            "seen_count": self.seen_count,
            "evidence": self.evidence,
            "candidate_tests": self.candidate_tests,
        }
