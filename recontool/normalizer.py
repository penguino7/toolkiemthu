from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .models import EndpointRecord, Param


# Cac param nay thuong chi dung de cache/tracking, khong phai diem fuzz chinh.
IGNORED_QUERY_PARAMS = {
    "_",
    "_t",
    "t",
    "ts",
    "timestamp",
    "cache",
    "cb",
    "rand",
    "random",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
}
DYNAMIC_PATH_TYPES = {"int", "uuid", "date"}
TYPE_PATTERNS = [
    ("int", r"-?\d+"),
    ("float", r"-?\d+\.\d+"),
    ("date", r"\d{4}-\d{2}-\d{2}"),
    ("uuid", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
]


class ReconNormalizer:
    """Dua URL/request thô ve EndpointRecord de recon/fuzz dung chung."""

    def make_record(
        self,
        method: str,
        url: str,
        source_tool: str,
        base_url: str | None = None,
        status: int | None = None,
        request_content_type: str = "",
        response_content_type: str = "",
        request_headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        discovered_from: str | None = None,
        forms: list[dict[str, Any]] | None = None,
    ) -> EndpointRecord:
        url = self.absolute_url(url, base_url)
        parsed = urlparse(url)

        record = EndpointRecord(
            method=method.upper(),
            url=url,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            path=parsed.path or "/",
            canonical_path=self.make_path_pattern(parsed.path or "/"),
            request_content_type=request_content_type,
            response_content_type=response_content_type,
            request_headers=self._lower_headers(request_headers),
            response_headers=self._lower_headers(response_headers),
            statuses=[status] if status else [],
            source_tools=[source_tool],
            discovered_from=[discovered_from] if discovered_from else [],
            examples=[url],
            forms=forms or [],
        )

        for param in self.parse_query_params(url) + self.parse_body_params(body, request_content_type):
            record.add_param(param)

        return record

    def absolute_url(self, url: str, base_url: str | None = None) -> str:
        """Bien URL tuong doi/thua query rac thanh URL on dinh."""
        if base_url:
            url = urljoin(base_url, url)

        parsed = urlparse(url)
        query = urlencode(self._clean_query_pairs(parsed.query))
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""

        return urlunparse(((parsed.scheme or "http").lower(), f"{host}{port}", self._clean_path(parsed.path or "/"), "", query, ""))

    def make_path_pattern(self, path: str) -> str:
        """/news/123 -> /news/{int}; dung de gom endpoint trung nhau."""
        parts = []
        for part in self._clean_path(path).split("/"):
            if not part:
                continue

            value_type = self.infer_type(part)
            parts.append(f"{{{value_type}}}" if value_type in DYNAMIC_PATH_TYPES else part)

        return "/" + "/".join(parts)

    def canonicalize_path(self, path: str) -> str:
        """Ten cu, giu lai de tranh vo code neu co noi con goi."""
        return self.make_path_pattern(path)

    def parse_query_params(self, url: str) -> list[Param]:
        return [self._new_param(name, "query", value) for name, value in self._clean_query_pairs(urlparse(url).query)]

    def parse_body_params(self, body: str | bytes | None, content_type: str = "") -> list[Param]:
        if not body:
            return []

        body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        content_type = content_type.lower()

        if "json" in content_type:
            return self._json_params(body_text)
        if "x-www-form-urlencoded" in content_type or "=" in body_text:
            return self._form_params(body_text)
        return []

    def infer_type(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if text == "":
            return "empty"
        if text.lower() in {"true", "false"}:
            return "bool"
        for type_name, pattern in TYPE_PATTERNS:
            if re.fullmatch(pattern, text):
                return type_name
        if "@" in text and "." in text:
            return "email"
        return "string"

    def _clean_query_pairs(self, query: str) -> list[tuple[str, str]]:
        return sorted(
            (name, value)
            for name, value in parse_qsl(query, keep_blank_values=True)
            if name.lower() not in IGNORED_QUERY_PARAMS
        )

    def _json_params(self, body_text: str) -> list[Param]:
        try:
            data = json.loads(body_text)
        except json.JSONDecodeError:
            return []

        return [self._new_param(name, "json", value) for name, value in self._walk_json(data)]

    def _form_params(self, body_text: str) -> list[Param]:
        return [self._new_param(name, "body", value) for name, value in parse_qsl(body_text, keep_blank_values=True)]

    def _walk_json(self, value: Any, prefix: str = ""):
        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                yield from self._walk_json(child, name)
            return

        if isinstance(value, list):
            for index, child in enumerate(value[:5]):
                yield from self._walk_json(child, f"{prefix}[{index}]")
            return

        yield prefix, value

    def _new_param(self, name: str, location: str, value: Any) -> Param:
        param = Param(name=name, location=location, type_hint=self.infer_type(value))
        param.add_value(value)
        return param

    def _clean_path(self, path: str) -> str:
        path = re.sub(r"/{2,}", "/", path or "/")
        return path.rstrip("/") if len(path) > 1 else path

    def _lower_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        return {str(name).lower(): str(value) for name, value in (headers or {}).items()}
