from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .models import EndpointRecord, Param


CACHE_BUSTER_PARAMS = {
    "_",
    "_t",
    "t",
    "ts",
    "timestamp",
    "cache",
    "cachebuster",
    "cb",
    "rand",
    "random",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
}


class ReconNormalizer:
    """Chuẩn hóa dữ liệu crawl/import về cùng một kiểu EndpointRecord."""

    def make_record(
        self,
        method: str,
        url: str,
        source_tool: str,
        base_url: str | None = None,
        status: int | None = None,
        request_content_type: str = "",
        response_content_type: str = "",
        request_headers: Dict[str, str] | None = None,
        response_headers: Dict[str, str] | None = None,
        body: str | bytes | None = None,
        discovered_from: str | None = None,
        forms: List[Dict[str, Any]] | None = None,
    ) -> EndpointRecord:
        normalized_url = self.absolute_url(url, base_url)
        parsed_url = urlparse(normalized_url)

        record = EndpointRecord(
            method=method.upper(),
            url=normalized_url,
            scheme=parsed_url.scheme,
            host=parsed_url.hostname or "",
            port=parsed_url.port,
            path=parsed_url.path or "/",
            canonical_path=self.canonicalize_path(parsed_url.path or "/"),
            request_content_type=request_content_type or "",
            response_content_type=response_content_type or "",
            request_headers=self._normalize_headers(request_headers),
            response_headers=self._normalize_headers(response_headers),
            statuses=[status] if status else [],
            source_tools=[source_tool],
            discovered_from=[discovered_from] if discovered_from else [],
            examples=[normalized_url],
            forms=forms or [],
        )

        for param in self.parse_query_params(normalized_url):
            record.add_param(param)
        for param in self.parse_body_params(body, request_content_type):
            record.add_param(param)

        return record

    def absolute_url(self, url: str, base_url: str | None = None) -> str:
        if base_url:
            url = urljoin(base_url, url)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = f":{parsed.port}" if parsed.port else ""
        path = self._clean_path(parsed.path or "/")

        query_pairs = [
            (name, value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if name.lower() not in CACHE_BUSTER_PARAMS
        ]
        query = urlencode(sorted(query_pairs), doseq=True)
        return urlunparse((scheme, f"{host}{port}", path, "", query, ""))

    def canonicalize_path(self, path: str) -> str:
        parts = []
        for part in self._clean_path(path).split("/"):
            if not part:
                continue
            type_hint = self.infer_type(part)
            parts.append("{" + type_hint + "}" if type_hint in {"int", "uuid", "date"} else part)
        return "/" + "/".join(parts)

    def parse_query_params(self, url: str) -> List[Param]:
        params: List[Param] = []
        for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if name.lower() in CACHE_BUSTER_PARAMS:
                continue
            params.append(self._make_param(name, "query", value))
        return params

    def parse_body_params(self, body: str | bytes | None, content_type: str = "") -> List[Param]:
        if not body:
            return []

        body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        content_type = content_type.lower()

        if "application/json" in content_type:
            return self._parse_json_body(body_text)
        if "application/x-www-form-urlencoded" in content_type or "=" in body_text:
            return self._parse_form_body(body_text)
        return []

    def infer_type(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if text == "":
            return "empty"
        if re.fullmatch(r"-?\d+", text):
            return "int"
        if re.fullmatch(r"-?\d+\.\d+", text):
            return "float"
        if text.lower() in {"true", "false"}:
            return "bool"
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            return "date"
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text):
            return "uuid"
        if "@" in text and "." in text:
            return "email"
        return "string"

    def _parse_json_body(self, body_text: str) -> List[Param]:
        try:
            data = json.loads(body_text)
        except json.JSONDecodeError:
            return []

        return [self._make_param(name, "json", value) for name, value in self._flatten_json(data)]

    def _parse_form_body(self, body_text: str) -> List[Param]:
        return [self._make_param(name, "body", value) for name, value in parse_qsl(body_text, keep_blank_values=True)]

    def _make_param(self, name: str, location: str, value: Any) -> Param:
        param = Param(name=name, location=location, type_hint=self.infer_type(value))
        param.add_value(value)
        return param

    def _flatten_json(self, value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
        if isinstance(value, dict):
            for key, child in value.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                yield from self._flatten_json(child, next_prefix)
            return

        if isinstance(value, list):
            for index, child in enumerate(value[:5]):
                yield from self._flatten_json(child, f"{prefix}[{index}]")
            return

        yield prefix, value

    def _clean_path(self, path: str) -> str:
        cleaned = re.sub(r"/{2,}", "/", path or "/")
        return cleaned.rstrip("/") if len(cleaned) > 1 else cleaned

    def _normalize_headers(self, headers: Dict[str, str] | None) -> Dict[str, str]:
        if not headers:
            return {}
        return {str(key).lower(): str(value) for key, value in headers.items()}
