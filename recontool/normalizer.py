from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .models import EndpointRecord, Param


DB_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "mariadb",
    "pdo error",
    "database error",
    "you have an error in your sql",
    "ora-",
    "postgres",
    "sqlite",
]

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
    """Chuyển mọi dữ liệu crawl/import về EndpointRecord.

    Đây là "trái tim" của tool. Dù dữ liệu đến từ static crawler, Playwright,
    HAR hay manual seed, cuối cùng đều đi qua class này để có cùng format.
    """

    def absolute_url(self, url: str, base_url: str | None = None) -> str:
        if base_url:
            url = urljoin(base_url, url)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = f":{parsed.port}" if parsed.port else ""
        path = self._clean_path(parsed.path or "/")

        # Bỏ cache-buster và sort query để URL ổn định hơn khi dedupe.
        query_pairs = [
            (name, value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if name.lower() not in CACHE_BUSTER_PARAMS
        ]
        query = urlencode(sorted(query_pairs), doseq=True)
        return urlunparse((scheme, f"{host}{port}", path, "", query, ""))

    def infer_type(self, value: Any) -> str:
        """Suy luận type đơn giản từ sample value quan sát được."""
        text = "" if value is None else str(value)
        if re.fullmatch(r"-?\d+", text):
            return "int"
        if re.fullmatch(r"-?\d+\.\d+", text):
            return "float"
        if text.lower() in {"true", "false"}:
            return "bool"
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text):
            return "uuid"
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            return "date"
        if "@" in text and "." in text:
            return "email"
        if text == "":
            return "empty"
        return "string"

    def canonicalize_path(self, path: str) -> str:
        """Đổi path động thành dạng ổn định để gom trùng.

        Ví dụ `/news/1` và `/news/2` cùng thành `/news/{int}`.
        """
        cleaned = self._clean_path(path or "/")
        parts = []
        for part in cleaned.split("/"):
            if not part:
                continue
            hint = self.infer_type(part)
            parts.append("{" + hint + "}" if hint in {"int", "uuid", "date"} else part)
        return "/" + "/".join(parts)

    def parse_query_params(self, url: str) -> List[Param]:
        parsed = urlparse(url)
        params: List[Param] = []
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if name.lower() in CACHE_BUSTER_PARAMS:
                continue
            param = Param(name=name, location="query", type_hint=self.infer_type(value))
            param.add_value(value)
            params.append(param)
        return params

    def parse_body_params(self, body: str | bytes | None, content_type: str = "") -> List[Param]:
        if not body:
            return []

        body_text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        content_type = (content_type or "").lower()

        if "application/json" in content_type:
            return self._parse_json_body(body_text)

        if "application/x-www-form-urlencoded" in content_type or "=" in body_text:
            return self._parse_form_body(body_text)

        return []

    def make_record(
        self,
        method: str,
        url: str,
        source_tool: str,
        base_url: str | None = None,
        auth_context: str = "anonymous",
        status: int | None = None,
        request_content_type: str = "",
        response_content_type: str = "",
        request_headers: Dict[str, str] | None = None,
        response_headers: Dict[str, str] | None = None,
        body: str | bytes | None = None,
        response_text: str | None = None,
        discovered_from: str | None = None,
        forms: List[Dict[str, Any]] | None = None,
    ) -> EndpointRecord:
        normalized = self.absolute_url(url, base_url)
        parsed = urlparse(normalized)
        record = EndpointRecord(
            method=method.upper(),
            url=normalized,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            path=parsed.path or "/",
            canonical_path=self.canonicalize_path(parsed.path or "/"),
            auth_context=auth_context,
            request_content_type=request_content_type or "",
            response_content_type=response_content_type or "",
            request_headers=self._normalize_headers(request_headers),
            response_headers=self._normalize_headers(response_headers),
            statuses=[status] if status else [],
            source_tools=[source_tool],
            discovered_from=[discovered_from] if discovered_from else [],
            examples=[normalized],
            forms=forms or [],
        )

        for param in self.parse_query_params(normalized):
            record.add_param(param)
        for param in self.parse_body_params(body, request_content_type):
            record.add_param(param)

        self.mark_reflections(record, response_text, response_content_type)
        if self.detect_db_error(response_text):
            record.evidence["db_error_pattern"] = True
        return record

    def mark_reflections(self, record: EndpointRecord, response_text: str | None, response_content_type: str = "") -> None:
        """Ghi nhận nếu sample value xuất hiện lại trong response.

        Đây vẫn là recon metadata, không gửi giá trị kiểm thử mới. Tool chỉ nhìn response
        của request đã crawl được.
        """
        if not response_text:
            return

        contexts = set(record.evidence.get("reflection_contexts", []))
        for param in record.params.values():
            for value in param.sample_values:
                if value and value in response_text:
                    param.reflected = True
                    record.evidence["has_reflection"] = True
                    contexts.add(self.reflection_context(response_text, value, response_content_type))

        if contexts:
            record.evidence["reflection_contexts"] = sorted(contexts)

    def detect_db_error(self, response_text: str | None) -> bool:
        if not response_text:
            return False
        lowered = response_text.lower()
        return any(pattern in lowered for pattern in DB_ERROR_PATTERNS)

    def reflection_context(self, response_text: str, value: str, response_content_type: str = "") -> str:
        if "json" in (response_content_type or "").lower():
            return "json"

        index = response_text.find(value)
        if index == -1:
            return "unknown"

        before = response_text[max(0, index - 40):index].lower()
        after = response_text[index:index + len(value) + 40].lower()
        if "<script" in before or "</script" in after:
            return "script"
        if "=" in before and ("\"" in before[-5:] or "'" in before[-5:]):
            return "html_attribute"
        if "<" in before and ">" in after:
            return "html_body"
        return "raw"

    def query_signature(self, record: EndpointRecord) -> str:
        names = sorted(p.name for p in record.params.values() if p.location == "query")
        return urlencode([(name, "") for name in names])

    def _parse_json_body(self, body_text: str) -> List[Param]:
        try:
            data = json.loads(body_text)
        except json.JSONDecodeError:
            return []

        params = []
        for name, value in self._flatten_json(data):
            param = Param(name=name, location="json", type_hint=self.infer_type(value))
            param.add_value(value)
            params.append(param)
        return params

    def _parse_form_body(self, body_text: str) -> List[Param]:
        params = []
        for name, value in parse_qsl(body_text, keep_blank_values=True):
            param = Param(name=name, location="body", type_hint=self.infer_type(value))
            param.add_value(value)
            params.append(param)
        return params

    def _flatten_json(self, value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
        if isinstance(value, dict):
            for key, child in value.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                yield from self._flatten_json(child, next_prefix)
        elif isinstance(value, list):
            for index, child in enumerate(value[:5]):
                next_prefix = f"{prefix}[{index}]"
                yield from self._flatten_json(child, next_prefix)
        else:
            yield prefix, value

    def _clean_path(self, path: str) -> str:
        cleaned = re.sub(r"/{2,}", "/", path or "/")
        if len(cleaned) > 1:
            cleaned = cleaned.rstrip("/")
        return cleaned

    def _normalize_headers(self, headers: Dict[str, str] | None) -> Dict[str, str]:
        if not headers:
            return {}
        return {str(key).lower(): str(value) for key, value in headers.items()}


_DEFAULT_NORMALIZER = ReconNormalizer()


def absolute_url(url: str, base_url: str | None = None) -> str:
    return _DEFAULT_NORMALIZER.absolute_url(url, base_url)


def infer_type(value: Any) -> str:
    return _DEFAULT_NORMALIZER.infer_type(value)


def canonicalize_path(path: str) -> str:
    return _DEFAULT_NORMALIZER.canonicalize_path(path)


def parse_query_params(url: str) -> List[Param]:
    return _DEFAULT_NORMALIZER.parse_query_params(url)


def parse_body_params(body: str | bytes | None, content_type: str = "") -> List[Param]:
    return _DEFAULT_NORMALIZER.parse_body_params(body, content_type)


def detect_db_error(response_text: str | None) -> bool:
    return _DEFAULT_NORMALIZER.detect_db_error(response_text)


def reflection_context(response_text: str, value: str, response_content_type: str = "") -> str:
    return _DEFAULT_NORMALIZER.reflection_context(response_text, value, response_content_type)


def mark_reflections(record: EndpointRecord, response_text: str | None, response_content_type: str = "") -> None:
    _DEFAULT_NORMALIZER.mark_reflections(record, response_text, response_content_type)


def make_record(
    method: str,
    url: str,
    source_tool: str,
    base_url: str | None = None,
    auth_context: str = "anonymous",
    status: int | None = None,
    request_content_type: str = "",
    response_content_type: str = "",
    request_headers: Dict[str, str] | None = None,
    response_headers: Dict[str, str] | None = None,
    body: str | bytes | None = None,
    response_text: str | None = None,
    discovered_from: str | None = None,
    forms: List[Dict[str, Any]] | None = None,
) -> EndpointRecord:
    return _DEFAULT_NORMALIZER.make_record(
        method=method,
        url=url,
        source_tool=source_tool,
        base_url=base_url,
        auth_context=auth_context,
        status=status,
        request_content_type=request_content_type,
        response_content_type=response_content_type,
        request_headers=request_headers,
        response_headers=response_headers,
        body=body,
        response_text=response_text,
        discovered_from=discovered_from,
        forms=forms,
    )


def query_signature(record: EndpointRecord) -> str:
    return _DEFAULT_NORMALIZER.query_signature(record)
