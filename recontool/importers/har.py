from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from ..models import EndpointRecord
from ..normalizer import ReconNormalizer


class HarImporter:
    """Đọc file HAR và biến mỗi request thành EndpointRecord."""

    SOURCE = "har_importer"

    def __init__(self, config: dict, normalizer: ReconNormalizer | None = None) -> None:
        self.config = config
        self.normalizer = normalizer or ReconNormalizer()

    def import_file(self, path: str) -> List[EndpointRecord]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = data.get("log", {}).get("entries", [])
        return [self._record_from_entry(entry) for entry in entries]

    def _record_from_entry(self, entry: dict) -> EndpointRecord:
        request = entry.get("request", {})
        response = entry.get("response", {})
        req_headers = self._headers_to_dict(request.get("headers"))
        res_headers = self._headers_to_dict(response.get("headers"))
        post_data = request.get("postData") or {}
        response_content = response.get("content") or {}

        return self.normalizer.make_record(
            request.get("method", "GET"),
            request.get("url", ""),
            self.SOURCE,
            base_url=self.config.get("base_url"),
            auth_context=self.config.get("auth_context", "anonymous"),
            status=response.get("status"),
            request_content_type=post_data.get("mimeType") or req_headers.get("content-type", ""),
            response_content_type=response_content.get("mimeType") or res_headers.get("content-type", ""),
            request_headers=req_headers,
            response_headers=res_headers,
            body=post_data.get("text"),
            response_text=response_content.get("text"),
        )

    def _headers_to_dict(self, headers) -> Dict[str, str]:
        output = {}
        for item in headers or []:
            name = item.get("name", "").lower()
            if name:
                output[name] = item.get("value", "")
        return output


def import_har(path: str, config: dict) -> List[EndpointRecord]:
    return HarImporter(config).import_file(path)
