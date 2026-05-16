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


def absolute_url(url: str, base_url: str | None = None) -> str:
    if base_url:
        url = urljoin(base_url, url)
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or "http"
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = parsed.query
    return urlunparse((scheme, f"{host}{port}", path, "", query, ""))


def infer_type(value: Any) -> str:
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


def canonicalize_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if not part:
            continue
        hint = infer_type(part)
        if hint in {"int", "uuid", "date"}:
            parts.append("{" + hint + "}")
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def parse_query_params(url: str) -> List[Param]:
    parsed = urlparse(url)
    params: List[Param] = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        param = Param(name=name, location="query", type_hint=infer_type(value))
        param.add_value(value)
        params.append(param)
    return params


def _flatten_json(value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_json(child, next_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value[:5]):
            next_prefix = f"{prefix}[{index}]"
            yield from _flatten_json(child, next_prefix)
    else:
        yield prefix, value


def parse_body_params(body: str | bytes | None, content_type: str = "") -> List[Param]:
    if not body:
        return []
    if isinstance(body, bytes):
        body_text = body.decode("utf-8", errors="replace")
    else:
        body_text = body
    content_type = (content_type or "").lower()
    params: List[Param] = []

    if "application/json" in content_type:
        try:
            data = json.loads(body_text)
        except json.JSONDecodeError:
            return []
        for name, value in _flatten_json(data):
            param = Param(name=name, location="json", type_hint=infer_type(value))
            param.add_value(value)
            params.append(param)
        return params

    if "application/x-www-form-urlencoded" in content_type or "=" in body_text:
        for name, value in parse_qsl(body_text, keep_blank_values=True):
            param = Param(name=name, location="body", type_hint=infer_type(value))
            param.add_value(value)
            params.append(param)
    return params


def detect_db_error(response_text: str | None) -> bool:
    if not response_text:
        return False
    lowered = response_text.lower()
    return any(pattern in lowered for pattern in DB_ERROR_PATTERNS)


def mark_reflections(record: EndpointRecord, response_text: str | None) -> None:
    if not response_text:
        return
    for param in record.params.values():
        for value in param.sample_values:
            if value and value in response_text:
                param.reflected = True
                record.evidence["has_reflection"] = True
                return


def make_record(
    method: str,
    url: str,
    source_tool: str,
    base_url: str | None = None,
    auth_context: str = "anonymous",
    status: int | None = None,
    request_content_type: str = "",
    response_content_type: str = "",
    body: str | bytes | None = None,
    response_text: str | None = None,
    discovered_from: str | None = None,
    forms: List[Dict[str, Any]] | None = None,
) -> EndpointRecord:
    normalized = absolute_url(url, base_url)
    parsed = urlparse(normalized)
    record = EndpointRecord(
        method=method.upper(),
        url=normalized,
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=parsed.port,
        path=parsed.path or "/",
        canonical_path=canonicalize_path(parsed.path or "/"),
        auth_context=auth_context,
        request_content_type=request_content_type or "",
        response_content_type=response_content_type or "",
        statuses=[status] if status else [],
        source_tools=[source_tool],
        discovered_from=[discovered_from] if discovered_from else [],
        examples=[normalized],
        forms=forms or [],
    )

    for param in parse_query_params(normalized):
        record.add_param(param)
    for param in parse_body_params(body, request_content_type):
        record.add_param(param)
    mark_reflections(record, response_text)
    if detect_db_error(response_text):
        record.evidence["db_error_pattern"] = True
    return record


def query_signature(record: EndpointRecord) -> str:
    names = sorted(p.name for p in record.params.values() if p.location == "query")
    return urlencode([(name, "") for name in names])
