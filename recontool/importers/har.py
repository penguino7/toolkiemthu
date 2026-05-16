from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from ..normalizer import make_record


def _headers_to_dict(headers) -> Dict[str, str]:
    output = {}
    for item in headers or []:
        name = item.get("name", "").lower()
        if name:
            output[name] = item.get("value", "")
    return output


def import_har(path: str, config: dict) -> List:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    records = []
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        req_headers = _headers_to_dict(request.get("headers"))
        res_headers = _headers_to_dict(response.get("headers"))
        post_data = request.get("postData") or {}
        response_content = response.get("content") or {}
        records.append(
            make_record(
                request.get("method", "GET"),
                request.get("url", ""),
                "har_importer",
                base_url=config.get("base_url"),
                auth_context=config.get("auth_context", "anonymous"),
                status=response.get("status"),
                request_content_type=post_data.get("mimeType") or req_headers.get("content-type", ""),
                response_content_type=response_content.get("mimeType") or res_headers.get("content-type", ""),
                body=post_data.get("text"),
                response_text=response_content.get("text"),
            )
        )
    return records
